@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.codec.DecodeContext
import com.ditchoom.buffer.codec.encodeToPlatformBuffer
import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.socket.udp.UdpSocket
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The out-of-band **signaling** channel between the two container peers — a tiny UDP client to the
 * rendezvous relay (a stateless keyed mailbox on the public network, reachable from both peers exactly
 * the way coturn is). It moves the ~4 signaling blobs (offer, answer, each side's trickled candidates)
 * with **zero disk and zero TCP**: it rides the SAME `socket-udp` / buffer-flow [DatagramChannel] the peer
 * already links for ICE, so it adds no dependency and no BoringSSL duplicate-symbol risk that a WebSocket/
 * MQTT/QUIC signaling client would (see `~/git/cinterop-issues`). It is not production WebRTC signaling —
 * it is a harness rendezvous, deliberately minimal. The wire format is the KSP-generated buffer-codec
 * schema in [PutRequest]/[GetRequest]/[MailboxResponse].
 *
 * **Reliability over UDP:** PUT carries a caller-assigned `recordId` (monotonic per slot), so the relay
 * stores records in an ordered, id-keyed map and a retransmit is idempotent. GET carries a `since` index
 * and returns only records at or after it. The client retransmits a PUT until it sees an ack and polls a
 * GET on an interval — the standard lost-datagram recovery, bounded by a watchdog.
 *
 * **Single-consumer:** one [UdpSignaling] instance is driven by exactly one coroutine (open a second
 * instance for a concurrent activity) so two coroutines never race the one socket's `receive()`.
 */
internal class UdpSignaling private constructor(
    private val channel: DatagramChannel,
    private val rendezvous: SocketAddress,
    private val session: String,
    // Native factory (deterministic() → malloc-backed): socket-udp's io_uring `send` rejects a GC-heap
    // buffer, so frames must be encoded into native memory. Same factory the datapath uses.
    private val factory: BufferFactory,
) {
    /** PUT [payload] as record [recordId] into [slot]; retransmit until acked or [timeout]. */
    suspend fun put(
        slot: String,
        recordId: Int,
        payload: String,
        timeout: Duration = PUT_TIMEOUT,
    ): Boolean {
        val request = PutRequestCodec.encodeToPlatformBuffer(PutRequest(OP_PUT, "$session/$slot", recordId.toUInt(), payload), factory)
        val acked =
            withTimeoutOrNull(timeout) {
                while (true) {
                    channel.send(request.slice(), to = rendezvous)
                    val reply = withTimeoutOrNull(RETRANSMIT) { receiveReply() }
                    if (reply == true) return@withTimeoutOrNull true
                }
                @Suppress("UNREACHABLE_CODE")
                true
            }
        request.freeNativeMemory()
        return acked ?: false
    }

    /**
     * GET the records of [slot] at or after index [since]. Returns the new records in order (empty on a
     * lost datagram or an as-yet-empty slot — the caller polls again). The caller advances its own `since`
     * by the returned count.
     */
    suspend fun poll(
        slot: String,
        since: Int,
        timeout: Duration = GET_TIMEOUT,
    ): List<String> {
        val request = GetRequestCodec.encodeToPlatformBuffer(GetRequest(OP_GET, "$session/$slot", since.toUInt()), factory)
        val records =
            withTimeoutOrNull(timeout) {
                channel.send(request.slice(), to = rendezvous)
                when (val r = channel.receive()) {
                    is DatagramReadResult.Received ->
                        MailboxResponseCodec.decode(r.datagram.payload, DecodeContext.Empty).records.map { it.payload }
                    is DatagramReadResult.Closed -> emptyList()
                }
            }
        request.freeNativeMemory()
        return records ?: emptyList()
    }

    fun close() = channel.close()

    // Await any datagram from the relay (a PUT ack carries no useful body — arrival IS the ack).
    private suspend fun receiveReply(): Boolean =
        when (channel.receive()) {
            is DatagramReadResult.Received -> true
            is DatagramReadResult.Closed -> false
        }

    companion object {
        private val RETRANSMIT = 300.milliseconds
        private val PUT_TIMEOUT = 15.seconds
        private val GET_TIMEOUT = 1.seconds

        /** Open a signaling client (its own ephemeral UDP socket) to the [host]:[port] rendezvous. */
        suspend fun open(
            host: String,
            port: Int,
            session: String,
            factory: BufferFactory,
        ): UdpSignaling {
            val rendezvous = UdpSocket.resolve(host, port)
            val channel = UdpSocket.bind(localHost = null, localPort = 0)
            return UdpSignaling(channel, rendezvous, session, factory)
        }
    }
}

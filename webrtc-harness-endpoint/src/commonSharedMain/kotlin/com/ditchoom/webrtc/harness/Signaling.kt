@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.codec.DecodeContext
import com.ditchoom.buffer.codec.encodeToPlatformBuffer
import com.ditchoom.buffer.flow.AddressFamily
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
 * **Correlation (required over UDP):** each request carries a fresh [nextNonce] the reply echoes. UDP has
 * no request/response pairing, so [awaitReply] drains and discards (and frees) every datagram whose nonce
 * doesn't match the request it is waiting on — otherwise a delayed/duplicate reply arriving after a
 * per-request timeout would offset the socket by one forever and mis-pair every later reply.
 *
 * **Reliability:** PUT carries a caller-assigned `recordId` (monotonic per slot), so the relay stores
 * records in an id-keyed map and a retransmit is idempotent. `put` retransmits until a **matching** ack;
 * `poll` returns the records at or after `since`. Bounded by a watchdog.
 *
 * **Single-consumer:** one [UdpSignaling] instance is driven by exactly one coroutine (open a second
 * instance for a concurrent activity) so two coroutines never race the one socket's `receive()`.
 *
 * **Buffers:** the request buffer is freed in `finally` (even on cancellation), and every received
 * datagram payload is freed as it is drained — the native factory ([BufferFactory.deterministic]) is
 * malloc-backed and caller-owned.
 */
/**
 * A signaling mailbox slot — the closed set of blobs the two peers exchange over the rendezvous relay.
 * An enum, not a bare string, so a `when` over it is exhaustive and a typo can't invent a dead slot.
 * [wire] is the on-relay key (namespaced by session inside [UdpSignaling.put]/[UdpSignaling.poll]).
 */
internal enum class Slot(
    val wire: String,
) {
    Offer("offer"),
    Answer("answer"),
    OffererCandidate("cand/offerer"),
    AnswererCandidate("cand/answerer"),
}

// [RecordId] — the per-slot record index wrapper — lives in commonMain (SignalingTypes.kt): `@JvmInline`
// value classes are only legal in common sources, not this per-target-compiled shared srcDir.

internal class UdpSignaling internal constructor(
    private val channel: DatagramChannel,
    private val rendezvous: SocketAddress,
    private val session: String,
    // Native factory (deterministic() → malloc-backed): socket-udp's io_uring `send` rejects a GC-heap
    // buffer, so frames must be encoded into native memory. Same factory the datapath uses.
    private val factory: BufferFactory,
) {
    // Monotonic per-instance request correlator. Unique among this socket's in-flight requests (single-
    // consumer), which is all correlation needs; wraps harmlessly at the harness's request counts.
    private var nonceCounter: UInt = 0u

    private fun nextNonce(): UInt = nonceCounter++

    /** PUT [payload] as record [recordId] into [slot]; retransmit until a matching ack or [timeout]. */
    suspend fun put(
        slot: Slot,
        recordId: RecordId,
        payload: String,
        timeout: Duration = PUT_TIMEOUT,
    ): Boolean {
        val nonce = nextNonce()
        val request =
            PutRequestCodec.encodeToPlatformBuffer(PutRequest(OP_PUT, nonce, "$session/${slot.wire}", recordId.value.toUInt(), payload), factory)
        try {
            val acked =
                withTimeoutOrNull(timeout) {
                    while (true) {
                        channel.send(request.slice(), to = rendezvous)
                        // Wait a retransmit interval for an ack echoing OUR nonce (stale acks are drained).
                        if (withTimeoutOrNull(RETRANSMIT) { awaitReply(nonce) } != null) return@withTimeoutOrNull true
                    }
                    @Suppress("UNREACHABLE_CODE")
                    true
                }
            return acked ?: false
        } finally {
            request.freeNativeMemory()
        }
    }

    /**
     * GET the records of [slot] at or after index [since]. Returns the new records in order (empty on a
     * lost datagram or an as-yet-empty slot — the caller polls again). The caller advances its own `since`
     * by the returned count.
     */
    suspend fun poll(
        slot: Slot,
        since: RecordId,
        timeout: Duration = GET_TIMEOUT,
    ): List<String> {
        val nonce = nextNonce()
        val request = GetRequestCodec.encodeToPlatformBuffer(GetRequest(OP_GET, nonce, "$session/${slot.wire}", since.value.toUInt()), factory)
        try {
            val records =
                withTimeoutOrNull(timeout) {
                    channel.send(request.slice(), to = rendezvous)
                    awaitReply(nonce)?.records?.map { it.payload }
                }
            return records ?: emptyList()
        } finally {
            request.freeNativeMemory()
        }
    }

    fun close() = channel.close()

    // Receive datagrams until one whose MailboxResponse echoes [expectedNonce]. Frees EVERY datagram it
    // consumes (the received payloads are caller-owned native memory) and discards non-matching or
    // undecodable ones — this is both the leak fix and the request/response correlation. Bounded by the
    // caller's `withTimeoutOrNull`, which cancels the pending `receive()`.
    private suspend fun awaitReply(expectedNonce: UInt): MailboxResponse? {
        while (true) {
            val datagram =
                when (val r = channel.receive()) {
                    is DatagramReadResult.Received -> r.datagram
                    is DatagramReadResult.Closed -> return null
                }
            val response =
                try {
                    MailboxResponseCodec.decode(datagram.payload, DecodeContext.Empty)
                } catch (e: Exception) {
                    null
                }
            datagram.payload.freeNativeMemory()
            if (response != null && response.nonce == expectedNonce) return response
        }
    }

    companion object {
        private val RETRANSMIT = 500.milliseconds
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
            // Bind the ephemeral socket in the SAME family as the resolved rendezvous. A `null` localHost
            // binds the v4 wildcard (0.0.0.0), so on a v6-only lane — where `resolve` returns the rendezvous'
            // only (AAAA) address — a v4 socket silently drops every send to that v6 target and no signaling
            // ever completes (offer/answer never exchanged). v4 + dual are unaffected: `resolve` yields a v4
            // address there, so this picks "0.0.0.0" exactly as before.
            val localWildcard =
                when (rendezvous.family) {
                    AddressFamily.IPv6 -> "::"
                    AddressFamily.IPv4 -> "0.0.0.0"
                }
            val channel = UdpSocket.bind(localHost = localWildcard, localPort = 0)
            return UdpSignaling(channel, rendezvous, session, factory)
        }
    }
}

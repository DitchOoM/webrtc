@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.codec.DecodeContext
import com.ditchoom.buffer.codec.encodeToPlatformBuffer
import com.ditchoom.buffer.flow.AddressFamily
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.socket.udp.UdpSocket
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The out-of-band **signaling** channel between the two container peers — a tiny UDP client to the
 * rendezvous relay (a stateless keyed mailbox on the public network, reachable from both peers exactly
 * the way coturn is). It moves the ~4 signaling blobs (offer, answer, each side's trickled candidates)
 * with **zero disk and zero TCP**: it rides the SAME `socket-udp` / buffer-flow [AddressedDatagramChannel] the peer
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

    /**
     * The one slot the ORCHESTRATOR writes rather than a peer: `run-interop.sh` publishes a record here
     * (over the mailbox's HTTP face) once it has moved the offerer onto the second carrier, and s8 waits
     * for it before restarting ICE. The mailbox is already reachable from both the harness and a running
     * peer, so this needs no new channel into the container — and it makes the switch an OBSERVED event
     * rather than a sleep either side would otherwise have to guess at (directive #4).
     */
    CarrierSwitch("carrier"),

    /**
     * The reverse-direction offer/answer pair (s10, issue #87). `Offer`/`Answer` above are offerer→answerer
     * and answerer→offerer *for rounds we originate*; a round the PEER originates cannot share them — the
     * record ids would collide with ours, and a peer writing into the slot we write is a second writer on a
     * slot the mailbox keys by (slot, id) alone. So a peer-originated round gets its own two slots, with its
     * own round numbering starting at 0.
     */
    PeerOffer("peer-offer"),
    PeerAnswer("peer-answer"),

    /**
     * The lifecycle word that asks the ANSWERER to restart ICE and re-offer (s10). Written by the offerer
     * once the harness has moved it onto the second carrier, and polled by every reflector family from the
     * loop it already polls the offer slot with — see `docs/DC_SEMANTICS_INTEROP_DESIGN.md` §4 for why the
     * reflector may act on a lifecycle word without ceasing to be dumb: it never learns *why* a fresh ICE
     * generation was asked for, and a lane that never writes this slot never reaches the code.
     */
    PeerRestart("peer-restart"),
}

// [RecordId] — the per-slot record index wrapper — lives in commonMain (SignalingTypes.kt): `@JvmInline`
// value classes are only legal in common sources, not this per-target-compiled shared srcDir.

internal class UdpSignaling internal constructor(
    private val channel: AddressedDatagramChannel,
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
                        // A refused send is paced HERE rather than by the reply wait below. If the socket is
                        // dead the `receive()` inside `awaitReply` returns `Closed` immediately, so
                        // `withTimeoutOrNull(RETRANSMIT)` returns null without ever spending the interval —
                        // and the loop would spin at full tilt for the whole 15s budget instead of
                        // retransmitting ~30 times.
                        if (!trySend(request.slice())) {
                            delay(RETRANSMIT)
                            continue
                        }
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
                    // A refused send is indistinguishable from a lost one to this caller, and the contract
                    // above already covers it: empty means "nothing new, poll again".
                    if (!trySend(request.slice())) return@withTimeoutOrNull null
                    awaitReply(nonce)?.records?.map { it.payload }
                }
            return records ?: emptyList()
        } finally {
            request.freeNativeMemory()
        }
    }

    /**
     * Send one request, **answering** whether it went instead of raising — the harness-side twin of
     * `webrtc-ice`'s `AddressedDatagramSink.sendOrFailure`, and it exists for the same reason.
     *
     * The signaling socket is bound to the peer's address at start-up, so the `interface-swap` topologies
     * (`s8`/`s10`/`s11`) move the route to the rendezvous out from under it mid-run and the kernel answers
     * `ENETUNREACH`. Both call sites run inside `bg.launch { for (r in outbox) sigOut.put(...) }`, and an
     * unhandled throw in a launched coroutine **kills the Kotlin/Native process** — the offerer exits
     * `rc=139` and the whole lane goes red at the exact moment the scenario is trying to prove a carrier
     * switch works. The peer logs then show a successful establishment next to a dead process, which is
     * the deterministic-"flake" shape CLAUDE.md warns costs an investigation every time.
     *
     * Signaling is already lossy-and-retried by construction (PUT retransmits to a matching ack, GET is
     * re-polled), so a refused send needs no new recovery path — only to stop being fatal.
     *
     * [CancellationException] is rethrown: the watchdog cancelling this peer is not a socket condition,
     * and swallowing it would keep the retransmit loop running after its scope died.
     */
    private suspend fun trySend(request: ReadBuffer): Boolean =
        try {
            channel.send(request, to = rendezvous)
            true
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            println("[harness] signaling send refused (retrying): $e")
            false
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

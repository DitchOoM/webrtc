@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.webrtc.sctp.TransportErrorDetection
import com.ditchoom.webrtc.sctp.ZeroChecksumPolicy
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * The timing, sizing, and buffer seams of an [SctpAssociation] (RFC 4960 defaults, tuned for the
 * WebRTC dcSCTP subset — RFC 8831 / ARCHITECTURE §11.2: no multihoming, no stream interleaving). Every value is
 * injected so a test can compress the schedule and assert **observable state**, never a wall-clock
 * budget (directive #4). Nothing here is read from an ambient clock or RNG — the association is pure
 * `handle(event, now)` (ARCHITECTURE §5.1); `now` and the injected [BufferFactory]/`Random` are the only seams.
 */
public data class SctpConfig(
    /** RTO.Initial (RFC 4960 §15) — the retransmission timeout before any RTT sample. */
    public val rtoInitial: Duration = 3.seconds,
    /** RTO.Min (RFC 4960 §15) — the floor an RTT-derived RTO is clamped to. */
    public val rtoMin: Duration = 1.seconds,
    /** RTO.Max (RFC 4960 §15) — the ceiling for an RTO after exponential backoff. */
    public val rtoMax: Duration = 60.seconds,
    /** Max.Init.Retransmits (RFC 4960 §15) — INIT/COOKIE-ECHO attempts before the association fails. */
    public val maxInitRetransmits: Int = 8,
    /** Association.Max.Retrans (RFC 4960 §15) — total DATA retransmit errors before the association aborts. */
    public val maxAssociationRetransmits: Int = 10,
    /** The largest DATA-chunk *user-data* payload per fragment (MTU minus SCTP/DTLS/UDP/IP overhead). */
    public val maxPayloadBytes: Int = 1200,
    /** a_rwnd (RFC 4960 §3.3.2) — the receive window this endpoint advertises. */
    public val receiveWindowBytes: UInt = 1024u * 1024u,
    /** Initial cwnd = min(4*MTU, max(2*MTU, 4380)) (RFC 4960 §7.2.1), expressed in MTUs of [maxPayloadBytes]. */
    public val initialCwndMtus: Int = 4,
    /** SACK delay (RFC 4960 §6.2) — how long a receiver may defer a SACK when nothing forces it out. */
    public val sackDelay: Duration = 200.milliseconds,
    /** Number of outbound streams to request in INIT (RFC 8831 uses many; the DataChannel layer picks ids). */
    public val outboundStreams: UShort = 1024u,
    /** Number of inbound streams to allow in INIT. */
    public val inboundStreams: UShort = 1024u,
    /** T2-shutdown / SHUTDOWN-ACK retransmit budget before the association aborts. */
    public val maxShutdownRetransmits: Int = 5,
    /**
     * Send-buffer high-water mark: once this many user-data bytes are queued-but-unsent, a `send()` stops
     * completing eagerly and suspends its caller until the queue drains to [sendBufferLowWaterBytes].
     *
     * The message that crosses the mark is still enqueued before its caller parks, so the queue is bounded
     * by `sendBufferHighWaterBytes + (one message) × (concurrent senders)`, not by this value alone.
     * Defaults to the advertised [receiveWindowBytes] — one window in flight is the most a peer can accept
     * without SACKing, so queuing appreciably more only adds latency.
     */
    public val sendBufferHighWaterBytes: Int = 1024 * 1024,
    /**
     * Send-buffer low-water mark: parked senders resume once the queue drains to this. Kept well below
     * [sendBufferHighWaterBytes] so a sender is not woken once per SACK to immediately re-park (hysteresis).
     */
    public val sendBufferLowWaterBytes: Int = 512 * 1024,
    /** The buffer allocator for encoded packets and reassembly copies — inject a tracking factory in tests. */
    public val bufferFactory: BufferFactory = BufferFactory.Default,
    /**
     * The largest user message this endpoint will reassemble (RFC 8841 §6). One value with two jobs: the
     * session layer advertises it as `a=max-message-size`, and the reassembly queue refuses a peer's
     * message that crosses it (RFC 4960 §3.3.7 ABORT, Protocol Violation).
     *
     * They must be the same number — advertising one ceiling and enforcing another is either a promise
     * broken or a receive buffer the peer paces — so it is one knob rather than two.
     */
    public val receiveMessageLimit: ReceiveMessageLimit = ReceiveMessageLimit.Default,
    /**
     * What to do when a data channel needs a stream id past what RFC 4960 §5.1.1 negotiated — refuse the
     * open, or ask the peer for more streams (RFC 6525 §4.5). See [StreamGrowthPolicy] for why the default
     * is [StreamGrowthPolicy.Fixed].
     */
    public val streamGrowth: StreamGrowthPolicy = StreamGrowthPolicy.Fixed,
    /**
     * RFC 9653 zero checksum — how far the upper layer permits this association to go.
     *
     * The policy is only ever half the answer: what the association actually advertises and emits is this
     * combined with what the transport underneath guarantees ([TransportErrorDetection]), and a transport
     * that guarantees nothing collapses every setting here back to CRC32c. Defaults to
     * [ZeroChecksumPolicy.Disabled] because the extension is an optimization, and a default that changes
     * the bytes we put on the wire against every peer is not one a consumer asked for.
     */
    public val zeroChecksum: ZeroChecksumPolicy = ZeroChecksumPolicy.Disabled,
    /**
     * Whether this association measures the MTU of the path it rides (RFC 8899), or takes the address
     * family's word for it. [PathMtuPolicy.Fixed] by default — see that type for why probing is opt-in.
     *
     * Either way, [maxPayloadBytes] stops being the whole story the moment a path is assessed: an
     * *unprobed* family ceiling may only lower it (an assumption must not raise a configured size), while
     * a *probe-confirmed* one supersedes it in both directions, because that is the measurement the caller
     * asked for by choosing [PathMtuPolicy.Discover].
     */
    public val pathMtu: PathMtuPolicy = PathMtuPolicy.Fixed,
) {
    /**
     * Two orderings this class only ever *documented*. Both are relations between two knobs, so neither
     * field can defend itself and the type system cannot state them — a `Duration` cannot know about
     * another `Duration`, and both inverted configs are perfectly constructible values whose damage
     * appears much later, in a state machine, as behaviour rather than as an error.
     *
     * Inverting the water marks parks a sender that can never be woken: `send()` suspends at the high
     * mark and resumes at the low one, so a low mark *above* the high one means the resume condition was
     * already true when the park condition fired, and the drain that would signal it never runs. The
     * association stays open and healthy, which is what makes it hard to read — it is a hang, not a
     * failure, with no typed error to catch because nothing has gone wrong on the wire.
     *
     * Inverting the RTO bounds is quieter still. `rtoMin` is a floor and `rtoMax` a ceiling applied in
     * that order, so `rtoMin > rtoMax` clamps every retransmission timeout to the floor and the
     * exponential backoff in RFC 4960 §6.3.3 stops backing off — the association retransmits at a fixed
     * fast cadence into a congested path, which is precisely the collapse the backoff exists to prevent.
     * It still *works* on a good link, so a fixture that does not congest will not see it.
     *
     * Both are caller mistakes rather than peer behaviour, so they are `require` — the house rule that
     * errors are typed and never stringly (directive #3) governs protocol outcomes, and a
     * programming-error precondition is not one of those.
     */
    init {
        require(sendBufferLowWaterBytes <= sendBufferHighWaterBytes) {
            "sendBufferLowWaterBytes ($sendBufferLowWaterBytes) must be <= sendBufferHighWaterBytes " +
                "($sendBufferHighWaterBytes); a low mark above the high one parks a sender that is never resumed"
        }
        require(rtoMin <= rtoMax) {
            "rtoMin ($rtoMin) must be <= rtoMax ($rtoMax); an inverted pair clamps every RTO to the floor " +
                "and defeats the RFC 4960 §6.3.3 backoff"
        }
    }
}

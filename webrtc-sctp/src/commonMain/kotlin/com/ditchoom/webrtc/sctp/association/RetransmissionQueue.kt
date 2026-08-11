@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.webrtc.sctp.DataChunkFlags
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.StreamSequenceNumber
import com.ditchoom.webrtc.sctp.Tsn
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/** The transmission lifecycle of one outstanding DATA chunk on the send side. */
internal enum class TxState {
    /** Sent, counted in flight size, awaiting acknowledgement. */
    InFlight,

    /** Marked for retransmission (fast-retransmit or T3-rtx); no longer counted in flight until re-sent. */
    NeedsRetransmit,

    /** Abandoned under partial reliability (RFC 3758) — will be skipped via FORWARD-TSN, never re-sent. */
    Abandoned,
}

/**
 * Which optional SCTP extensions the peer advertised for **this** association (RFC 3758 FORWARD-TSN,
 * RFC 6525 stream reconfiguration), learned from its INIT/INIT-ACK or recovered from the state cookie.
 *
 * One value rather than two free-floating `var`s, because the two are established together and belong to
 * the association that learned them — so they must die together. Held separately, a teardown that clears
 * one and forgets the other leaves a stale capability believed of the *next* peer, and that asymmetry is
 * invisible at the point it matters (it reads as a plain field access). Replacing a single value at
 * establish and at teardown makes the half-cleared state unconstructible.
 *
 * Booleans here are the legitimate kind: each is a standalone advertised-or-not fact carrying no
 * correlated data, and nothing about one constrains the other.
 */
internal data class PeerExtensions(
    val forwardTsn: Boolean,
    val reConfig: Boolean,
) {
    companion object {
        /** No association, or one whose peer advertised nothing — the only safe default. */
        val None: PeerExtensions = PeerExtensions(forwardTsn = false, reConfig = false)
    }
}

/**
 * Whether an acknowledged chunk may yield an RTT sample, and from which instant (RFC 4960 §6.3.1 C4,
 * and Karn's algorithm at C5: a retransmitted chunk's ack is ambiguous, because which copy it answers is
 * unknowable).
 *
 * A sealed type rather than the obvious `lastSentAt: Instant` + `retransmitCount == 0` pair, because that
 * pair admits two states the protocol does not have: a transmission instant on a chunk that has never
 * been transmitted (the field has to be seeded with *something*, and seeding it with the enqueue instant
 * is exactly the bug this replaces), and a "0 retransmits" flag drifting out of step with the instant
 * beside it. Here the instant exists in precisely the one state that can produce a sample.
 */
internal sealed interface RttOrigin {
    /** Queued, not yet on the wire. No transmission instant exists, so no sample can be derived. */
    data object Untransmitted : RttOrigin

    /** On the wire exactly once, at [transmittedAt] — the only state that may yield a sample. */
    data class SingleTransmission(
        val transmittedAt: Instant,
    ) : RttOrigin

    /** Retransmitted at least once: Karn's algorithm forbids a sample, so no instant is carried. */
    data object Ambiguous : RttOrigin
}

/**
 * One DATA chunk the sender is tracking for reliability (RFC 4960 §6.1).
 *
 * What is retained is the **fully encoded wire packet** ([packet]: common header + this one DATA chunk,
 * CRC32c already placed), not a copy of the user payload. The retransmission queue must own bytes that
 * outlive `send()` — the caller's payload is borrowed for the duration of one `handle` call — so exactly
 * one copy of the user data is architecturally required; encoding at accept time makes that copy *be*
 * the encode, instead of copying into an owned payload buffer and then copying again into the datagram
 * (directive #6). A retransmit is byte-identical to the original send by construction (same tag, ports,
 * TSN, flags, SSN, PPID, payload), so it is simply a fresh view of the same bytes — and the CRC is
 * computed once for the chunk's whole lifetime rather than once per transmission.
 *
 * The packet is owned here until the chunk is acked or abandoned and dropped from the queue, at which
 * point it is surfaced for release ([SctpOutput.ReclaimRetained]) rather than freed on the spot — the
 * driver may still be sending a view of it. [streamId], [ssn] and [flags] are kept because RFC 3758
 * abandonment reads them to build FORWARD-TSN; [reliability] and [enqueuedAt] drive the abandonment
 * decision itself.
 */
internal class OutstandingData(
    val tsn: Tsn,
    val streamId: StreamId,
    val ssn: StreamSequenceNumber,
    val flags: DataChunkFlags,
    /** Payload bytes this chunk contributes to the flight size / peer window (user data only). */
    val bytes: Int,
    /**
     * The encoded wire packet these bytes live in. Surfaced so the association can hand it back to the
     * driver when this chunk leaves the queue; nothing here frees it (see [wirePacket]).
     */
    val packet: PlatformBuffer,
    val reliability: SctpReliability,
    /**
     * When the application handed this fragment over — **not** when it reached the wire. It is the right
     * origin for [SctpReliability.MaxLifetime] (W3C `maxPacketLifeTime` is measured from `send()`, so a
     * message that spent its whole budget queued behind cwnd is correctly abandoned) and the **wrong**
     * origin for an RTT sample, which is what [rttOrigin] exists to keep separate.
     */
    val enqueuedAt: Instant,
) {
    /**
     * Whether this chunk can yield an RTT sample, and from when. A chunk sits in `pendingSend` for as long
     * as cwnd/rwnd say it must, so the gap between [enqueuedAt] and the first transmission is queueing
     * delay — measuring from the former inflates SRTT under any bulk transfer, which inflates RTO, which
     * makes loss recovery systematically slow.
     */
    var rttOrigin: RttOrigin = RttOrigin.Untransmitted

    var retransmitCount: Int = 0
    var missingReports: Int = 0
    var txState: TxState = TxState.InFlight

    /**
     * A fresh read view over the encoded packet, for the initial send and for every retransmit. The
     * position is pinned to 0 first so the view always spans the whole packet regardless of what a
     * previous holder did with its own view.
     *
     * **A view, not the buffer**, precisely so the driver can release what it is handed after each send
     * without touching bytes a later retransmit still needs — the [SctpOutput.Transmit.Retained] half of
     * the contract. On a pooled buffer that is one reference per transmission, balanced by the driver;
     * on a plain one it is free.
     */
    fun wirePacket(): PlatformBuffer {
        packet.position(0)
        return packet.slice()
    }
}

/**
 * What one SACK did to the retransmission queue — applied by the association to RTT/cwnd/timers.
 *
 * [reclaimed] is the ownership half: the encoded packets of every chunk this SACK removed. They are
 * *returned*, never freed here, because a driver may still be sending a view of them — the association
 * turns each into an [SctpOutput.ReclaimRetained] ordered behind the sends that could race it.
 */
internal class SackOutcome(
    val bytesNewlyAcked: Int,
    val cumulativeAdvanced: Boolean,
    val rttSample: kotlin.time.Duration?,
    val fastRetransmitTriggered: Boolean,
    val allDataAcknowledged: Boolean,
    val reclaimed: List<PlatformBuffer>,
)

/**
 * The send-side reliability engine (RFC 4960 §6.1–§6.2, §7.2.4 fast retransmit, RFC 3758 abandonment).
 * Holds the outstanding DATA chunks in TSN send order, processes incoming SACKs into an [SackOutcome],
 * marks chunks for fast/timeout retransmit, and abandons partially-reliable chunks past their limit —
 * advancing the [advancedPeerAckPoint] a FORWARD-TSN must carry. Pure state; the clock arrives as `now`.
 */
internal class RetransmissionQueue(
    private val config: SctpConfig,
    initialTsn: Tsn,
) {
    // Outstanding chunks in send order (LinkedHashMap preserves insertion = TSN order for our sends).
    private val outstanding = LinkedHashMap<UInt, OutstandingData>()

    /** The peer's cumulative ack point on our stream (RFC 4960 §6.1) — everything ≤ this is acked. */
    var cumulativeAckPoint: Tsn = Tsn(initialTsn.value - 1u)
        private set

    /**
     * Advanced Peer Ack Point (RFC 3758 §3.5): the TSN up to which the peer may treat data as acked
     * *including* our abandoned chunks. A FORWARD-TSN advances the peer's cum ack to here. Starts equal
     * to the cumulative ack point and only moves when a chunk is abandoned.
     */
    var advancedPeerAckPoint: Tsn = Tsn(initialTsn.value - 1u)
        private set

    /** Flight size (RFC 4960 §6.1): bytes of DATA sent but neither acked nor marked for retransmit. */
    var outstandingBytes: Int = 0
        private set

    /** The peer's most recently advertised receive window (RFC 4960 §6.2.1). */
    var peerReceiveWindow: UInt = config.receiveWindowBytes
        private set

    val isEmpty: Boolean get() = outstanding.isEmpty()

    fun setPeerReceiveWindow(rwnd: UInt) {
        peerReceiveWindow = rwnd
    }

    /** Register a freshly-sent chunk as outstanding (called after it is placed in a packet). */
    fun onSent(
        data: OutstandingData,
        now: Instant,
    ) {
        // The first (and so far only) transmission: this is the instant an RTT sample must measure from.
        data.rttOrigin = RttOrigin.SingleTransmission(now)
        outstanding[data.tsn.value] = data
        outstandingBytes += data.bytes
    }

    /**
     * Chunks currently marked for retransmit, in TSN send order — the caller ([SctpAssociation.trySend])
     * sends them **paced by cwnd** (RFC 4960 §6.3.3 E3: the collapsed cwnd bounds how much of the lost
     * flight goes out at once), calling [markRetransmitted] as each is actually put on the wire. They are
     * not auto-flipped here, so an unsent remainder stays `NeedsRetransmit` for the next send opportunity.
     */
    fun retransmittable(): List<OutstandingData> = outstanding.values.filter { it.txState == TxState.NeedsRetransmit }

    /**
     * Mark one [NeedsRetransmit][TxState.NeedsRetransmit] chunk as (re)sent: back to [TxState.InFlight],
     * re-counted into the flight size, retransmit count bumped, and — critically — its missing-report
     * counter reset so a fresh set of three SACK gap reports is required before it is fast-retransmitted
     * again (else it would be re-fast-retransmitted on every subsequent gapped SACK, RFC 4960 §7.2.4).
     */
    fun markRetransmitted(data: OutstandingData) {
        data.txState = TxState.InFlight
        // Karn's algorithm (RFC 4960 §6.3.1 C5): from here on, an ack for this TSN cannot be attributed to
        // a particular transmission, so the chunk is permanently ineligible as an RTT sample.
        data.rttOrigin = RttOrigin.Ambiguous
        data.retransmitCount += 1
        data.missingReports = 0
        outstandingBytes += data.bytes
    }

    /**
     * Process a SACK (RFC 4960 §6.2.1): drop cumulatively- and gap-acked chunks, count missing reports
     * for fast retransmit (RFC 4960 §7.2.4), sample RTT from a non-retransmitted cum-acked chunk (Karn's
     * algorithm, §6.3.1 C5), and refresh the peer receive window.
     */
    fun onSack(
        cumulativeTsnAck: Tsn,
        advertisedReceiverWindow: UInt,
        gapAckBlocks: List<Pair<Tsn, Tsn>>,
        now: Instant,
    ): SackOutcome {
        var bytesAcked = 0
        var rttSample: kotlin.time.Duration? = null
        var cumulativeAdvanced = false
        val reclaimed = ArrayList<PlatformBuffer>()

        // 1. Cumulative ack: everything at or before cumulativeTsnAck is acknowledged.
        val cumIterator = outstanding.entries.iterator()
        while (cumIterator.hasNext()) {
            val data = cumIterator.next().value
            if (data.tsn.sackPrecedes(cumulativeTsnAck) || data.tsn.value == cumulativeTsnAck.value) {
                if (data.txState != TxState.NeedsRetransmit && data.txState != TxState.Abandoned) {
                    bytesAcked += data.bytes
                    outstandingBytes -= data.bytes
                }
                // RTT from the highest singly-transmitted, cum-acked chunk (Karn's algorithm) — measured
                // from when it reached the wire, never from when it was queued.
                when (val origin = data.rttOrigin) {
                    is RttOrigin.SingleTransmission -> rttSample = now - origin.transmittedAt
                    RttOrigin.Ambiguous, RttOrigin.Untransmitted -> Unit
                }
                cumIterator.remove()
                reclaimed += data.packet
                cumulativeAdvanced = true
            }
        }
        if (cumulativeAckPoint.sackPrecedes(cumulativeTsnAck)) cumulativeAckPoint = cumulativeTsnAck
        if (advancedPeerAckPoint.sackPrecedes(cumulativeTsnAck)) advancedPeerAckPoint = cumulativeTsnAck

        // 2. Gap ack blocks: absolute TSN ranges (offset from cumulativeTsnAck) that are also received.
        val gapRanges = gapAckBlocks.map { (start, end) -> start.value to end.value }
        // The high-water mark for the missing-report test is the highest TSN the SACK itself reports as
        // received (the top of its gap blocks) — derived from the blocks, NOT from the chunks we still
        // hold, so a chunk already removed (previously acked/retransmitted) can't make it under-report and
        // delay a legitimate fast retransmit (RFC 4960 §7.2.4).
        var highestGapAcked = cumulativeTsnAck
        for ((_, end) in gapRanges) {
            val endTsn = Tsn(end)
            if (highestGapAcked.sackPrecedes(endTsn)) highestGapAcked = endTsn
        }
        val gapIterator = outstanding.entries.iterator()
        while (gapIterator.hasNext()) {
            val data = gapIterator.next().value
            if (gapRanges.any { (s, e) -> inRange(data.tsn.value, s, e) }) {
                if (data.txState != TxState.NeedsRetransmit && data.txState != TxState.Abandoned) {
                    bytesAcked += data.bytes
                    outstandingBytes -= data.bytes
                }
                gapIterator.remove()
                reclaimed += data.packet
            }
        }

        // 3. Missing reports (RFC 4960 §7.2.4): any still-outstanding chunk below the highest gap-acked
        // TSN was skipped by the receiver → count it; three reports trigger a fast retransmit.
        var fastRetransmit = false
        if (gapRanges.isNotEmpty()) {
            for (data in outstanding.values) {
                if (data.txState == TxState.InFlight && data.tsn.sackPrecedes(highestGapAcked)) {
                    data.missingReports += 1
                    if (data.missingReports >= FAST_RETRANSMIT_THRESHOLD) {
                        data.txState = TxState.NeedsRetransmit
                        outstandingBytes -= data.bytes
                        fastRetransmit = true
                    }
                }
            }
        }

        peerReceiveWindow = advertisedReceiverWindow
        if (outstandingBytes < 0) outstandingBytes = 0
        return SackOutcome(bytesAcked, cumulativeAdvanced, rttSample, fastRetransmit, outstanding.isEmpty(), reclaimed)
    }

    /**
     * T3-rtx expiry (RFC 4960 §6.3.3): mark **all** currently in-flight chunks for retransmission — the
     * whole flight is presumed lost. Returns true if there was anything to retransmit.
     */
    fun onT3Timeout(): Boolean {
        var any = false
        for (data in outstanding.values) {
            if (data.txState == TxState.InFlight) {
                data.txState = TxState.NeedsRetransmit
                data.missingReports = 0
                outstandingBytes -= data.bytes
                any = true
            }
        }
        if (outstandingBytes < 0) outstandingBytes = 0
        return any
    }

    /**
     * RFC 3758 §3.5: abandon any partially-reliable chunk whose retransmit or lifetime budget is spent,
     * advancing [advancedPeerAckPoint] over the abandoned prefix. Returns the per-stream `(streamId,
     * ssn)` skips a FORWARD-TSN must carry, or empty if nothing was abandoned.
     */
    fun abandonExpired(now: Instant): List<Pair<StreamId, StreamSequenceNumber>> {
        val abandonedStreams = LinkedHashMap<StreamId, StreamSequenceNumber>()
        var anyAbandoned = false
        for (data in outstanding.values) {
            if (data.txState == TxState.Abandoned) continue
            val expired =
                when (val r = data.reliability) {
                    SctpReliability.Reliable -> false
                    is SctpReliability.MaxRetransmits -> data.retransmitCount > r.maxRetransmits
                    is SctpReliability.MaxLifetime -> (now - data.enqueuedAt) > r.maxLifetime
                }
            if (expired) {
                if (data.txState == TxState.InFlight) outstandingBytes -= data.bytes
                data.txState = TxState.Abandoned
                anyAbandoned = true
                // For an ordered stream, the highest abandoned SSN advances the peer's stream state.
                if (!data.flags.unordered) {
                    val prev = abandonedStreams[data.streamId]
                    if (prev == null || prev.value < data.ssn.value) abandonedStreams[data.streamId] = data.ssn
                }
            }
        }
        if (anyAbandoned) recomputeAdvancedAckPoint()
        if (outstandingBytes < 0) outstandingBytes = 0
        return abandonedStreams.entries.map { it.key to it.value }
    }

    /**
     * Chunks that must be discarded after a completed FORWARD-TSN (abandoned and now covered). Returns
     * their encoded packets for the association to hand back to the driver — see [SackOutcome.reclaimed].
     */
    fun purgeAbandonedThrough(tsn: Tsn): List<PlatformBuffer> {
        val reclaimed = ArrayList<PlatformBuffer>()
        val it = outstanding.entries.iterator()
        while (it.hasNext()) {
            val data = it.next().value
            if (data.txState == TxState.Abandoned &&
                (data.tsn.sackPrecedes(tsn) || data.tsn.value == tsn.value)
            ) {
                it.remove()
                reclaimed += data.packet
            }
        }
        return reclaimed
    }

    /**
     * Drop every remaining chunk — the association is going away (teardown, abort, or a peer restart that
     * re-seeds the TCB). Returns their encoded packets for release, for the same reason every other
     * removal site does: this queue never frees what a driver may still be sending a view of.
     */
    fun drain(): List<PlatformBuffer> {
        val reclaimed = outstanding.values.map { it.packet }
        outstanding.clear()
        outstandingBytes = 0
        return reclaimed
    }

    // Advance the Advanced Peer Ack Point over a contiguous run of abandoned/acked chunks from the
    // current cumulative ack point (RFC 3758 §3.5): the FORWARD-TSN can only skip a gapless prefix. A
    // TSN that is present-and-abandoned advances it; a TSN already removed (acked) below the highest
    // outstanding advances it too; a still-live (InFlight/NeedsRetransmit) chunk stops the walk.
    private fun recomputeAdvancedAckPoint() {
        val highest = highestOutstandingTsn()
        var candidate = cumulativeAckPoint
        while (candidate.sackPrecedes(highest)) {
            val next = candidate.next()
            val data = outstanding[next.value]
            if (data == null || data.txState == TxState.Abandoned) {
                candidate = next
            } else {
                break
            }
        }
        if (advancedPeerAckPoint.sackPrecedes(candidate)) advancedPeerAckPoint = candidate
    }

    private fun highestOutstandingTsn(): Tsn = outstanding.values.maxByOrNull { it.tsn.value }?.tsn ?: cumulativeAckPoint

    // Wrap-aware absolute-TSN range membership (RFC 1982 serial space): a gap block whose absolute end
    // crosses the 2³² boundary has startAbs > endAbs, so a plain `in startAbs..endAbs` would be an empty
    // range and silently miss gap-acked chunks. Matches the serial-number discipline used elsewhere here.
    private fun inRange(
        tsn: UInt,
        startAbs: UInt,
        endAbs: UInt,
    ): Boolean = if (startAbs <= endAbs) tsn in startAbs..endAbs else tsn >= startAbs || tsn <= endAbs

    private companion object {
        private const val FAST_RETRANSMIT_THRESHOLD = 3
    }
}

@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.sctp.DataChunkFlags
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.SctpChunk
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
 * One DATA chunk the sender is tracking for reliability (RFC 4960 §6.1). Carries everything needed to
 * rebuild the wire chunk on a retransmit — the copied [userData] view is retained for the chunk's
 * lifetime and released when it is acked or abandoned. [reliability] and [firstSentAt] drive RFC 3758
 * abandonment.
 */
internal class OutstandingData(
    val tsn: Tsn,
    val streamId: StreamId,
    val ssn: StreamSequenceNumber,
    val ppid: PayloadProtocolId,
    val flags: DataChunkFlags,
    val userData: ReadBuffer,
    val reliability: SctpReliability,
    val firstSentAt: Instant,
) {
    var lastSentAt: Instant = firstSentAt
    var retransmitCount: Int = 0
    var missingReports: Int = 0
    var txState: TxState = TxState.InFlight

    /** Bytes this chunk contributes to the flight size / peer window (the user-data payload only). */
    val bytes: Int get() = userData.remaining()

    /** Rebuild the wire DATA chunk for an initial send or a retransmit (a fresh view of the payload). */
    fun toChunk(): SctpChunk.Data =
        SctpChunk.Data(
            flags = flags,
            tsn = tsn,
            streamId = streamId,
            streamSequenceNumber = ssn,
            payloadProtocolId = ppid,
            userData = userData.slice(),
        )
}

/** What one SACK did to the retransmission queue — applied by the association to RTT/cwnd/timers. */
internal class SackOutcome(
    val bytesNewlyAcked: Int,
    val cumulativeAdvanced: Boolean,
    val rttSample: kotlin.time.Duration?,
    val fastRetransmitTriggered: Boolean,
    val allDataAcknowledged: Boolean,
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

    /** True if any chunk is currently marked [TxState.NeedsRetransmit]. */
    fun hasRetransmitsPending(): Boolean = outstanding.values.any { it.txState == TxState.NeedsRetransmit }

    fun setPeerReceiveWindow(rwnd: UInt) {
        peerReceiveWindow = rwnd
    }

    /** Register a freshly-sent chunk as outstanding (called after it is placed in a packet). */
    fun onSent(data: OutstandingData) {
        outstanding[data.tsn.value] = data
        outstandingBytes += data.bytes
    }

    /** The chunks currently marked for retransmit, cleared back to [TxState.InFlight] and re-counted. */
    fun drainRetransmits(now: Instant): List<OutstandingData> {
        val out = ArrayList<OutstandingData>()
        for (data in outstanding.values) {
            if (data.txState == TxState.NeedsRetransmit) {
                data.txState = TxState.InFlight
                data.lastSentAt = now
                data.retransmitCount += 1
                outstandingBytes += data.bytes
                out += data
            }
        }
        return out
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

        // 1. Cumulative ack: everything at or before cumulativeTsnAck is acknowledged.
        val cumIterator = outstanding.entries.iterator()
        while (cumIterator.hasNext()) {
            val data = cumIterator.next().value
            if (data.tsn.sackPrecedes(cumulativeTsnAck) || data.tsn.value == cumulativeTsnAck.value) {
                if (data.txState != TxState.NeedsRetransmit && data.txState != TxState.Abandoned) {
                    bytesAcked += data.bytes
                    outstandingBytes -= data.bytes
                }
                // RTT from the highest non-retransmitted, cum-acked chunk (Karn's algorithm).
                if (data.retransmitCount == 0) rttSample = now - data.firstSentAt
                cumIterator.remove()
                cumulativeAdvanced = true
            }
        }
        if (cumulativeAckPoint.sackPrecedes(cumulativeTsnAck)) cumulativeAckPoint = cumulativeTsnAck
        if (advancedPeerAckPoint.sackPrecedes(cumulativeTsnAck)) advancedPeerAckPoint = cumulativeTsnAck

        // 2. Gap ack blocks: absolute TSN ranges (offset from cumulativeTsnAck) that are also received.
        val gapRanges = gapAckBlocks.map { (start, end) -> start.value to end.value }
        var highestGapAcked = cumulativeTsnAck
        val gapIterator = outstanding.entries.iterator()
        while (gapIterator.hasNext()) {
            val data = gapIterator.next().value
            if (gapRanges.any { (s, e) -> inRange(data.tsn.value, s, e) }) {
                if (data.txState != TxState.NeedsRetransmit && data.txState != TxState.Abandoned) {
                    bytesAcked += data.bytes
                    outstandingBytes -= data.bytes
                }
                if (highestGapAcked.sackPrecedes(data.tsn)) highestGapAcked = data.tsn
                gapIterator.remove()
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
        return SackOutcome(bytesAcked, cumulativeAdvanced, rttSample, fastRetransmit, outstanding.isEmpty())
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
                    is SctpReliability.MaxLifetime -> (now - data.firstSentAt) > r.maxLifetime
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

    /** The earliest still-unacked TSN, or null if the queue is empty — used to time the T3-rtx timer. */
    fun earliestSentAt(): Instant? =
        outstanding.values
            .filter { it.txState == TxState.InFlight }
            .minByOrNull { it.lastSentAt }
            ?.lastSentAt

    /** Chunks that must be discarded after a completed FORWARD-TSN (abandoned and now covered). */
    fun purgeAbandonedThrough(tsn: Tsn) {
        val it = outstanding.entries.iterator()
        while (it.hasNext()) {
            val data = it.next().value
            if (data.txState == TxState.Abandoned &&
                (data.tsn.sackPrecedes(tsn) || data.tsn.value == tsn.value)
            ) {
                it.remove()
            }
        }
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

    private fun inRange(
        tsn: UInt,
        startAbs: UInt,
        endAbs: UInt,
    ): Boolean = tsn in startAbs..endAbs

    private companion object {
        private const val FAST_RETRANSMIT_THRESHOLD = 3
    }
}

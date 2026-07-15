package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.sctp.DataChunkFlags
import com.ditchoom.webrtc.sctp.ForwardTsnStream
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.StreamSequenceNumber
import com.ditchoom.webrtc.sctp.Tsn

/** A fully reassembled user message ready to hand up to the DataChannel layer. */
internal class ReassembledMessage(
    val streamId: StreamId,
    val ppid: PayloadProtocolId,
    val unordered: Boolean,
    val payload: ReadBuffer,
)

// One stored DATA fragment (its payload copied out of the borrowed datagram) awaiting reassembly.
private class Fragment(
    val flags: DataChunkFlags,
    val streamId: StreamId,
    val ssn: StreamSequenceNumber,
    val ppid: PayloadProtocolId,
    val payload: ReadBuffer,
)

/**
 * The receive-side reassembly + ordered-delivery engine (RFC 4960 §6.2 receiver, §6.9 fragmentation,
 * RFC 3758 §3.6 FORWARD-TSN). Tracks the cumulative TSN and the gap map for SACK generation, copies and
 * reassembles DATA fragments into whole user messages, and gates ordered streams by Stream Sequence
 * Number while delivering unordered messages as soon as they are complete.
 *
 * Serial-number wrap of TSN/SSN is not modeled (the dcSCTP data-channel subset never approaches 2³²
 * within a session, RFC §11.2) — comparisons use plain unsigned order; this is the one documented
 * simplification, mirrored by the codec's [Tsn.sackPrecedes] being available if wrap handling is added.
 */
internal class ReassemblyQueue(
    peerInitialTsn: Tsn,
    private val config: SctpConfig,
) {
    /** Highest TSN below which everything has been received (the value a SACK's Cumulative TSN Ack carries). */
    var cumulativeTsn: Tsn = Tsn(peerInitialTsn.value - 1u)
        private set

    // TSNs received above the cumulative point (the gap map) — drives SACK gap blocks + dup detection.
    private val aboveCumulative = HashSet<UInt>()
    private val duplicates = ArrayList<Tsn>()
    private val fragments = HashMap<UInt, Fragment>()

    // Ordered delivery state: the next SSN to deliver per stream, and assembled-but-waiting messages.
    private val nextOrderedSsn = HashMap<StreamId, Int>()
    private val orderedReady = HashMap<StreamId, HashMap<Int, ReassembledMessage>>()

    /** True when a SACK should be sent without delay (out-of-order data arrived — RFC 4960 §6.2). */
    var sackImmediatelyRequested = false
        private set

    /**
     * Ingest one DATA chunk (RFC 4960 §6.2): dedup, store the copied fragment, advance the cumulative
     * TSN, then reassemble and return every message now deliverable in order. A duplicate or an
     * out-of-order arrival flips [sackImmediatelyRequested] so the association SACKs promptly.
     */
    fun receive(chunk: SctpChunk.Data): List<ReassembledMessage> {
        val tsn = chunk.tsn
        val isDuplicate = !cumulativeTsn.sackPrecedes(tsn) || tsn.value in aboveCumulative
        if (isDuplicate) {
            duplicates += tsn
            sackImmediatelyRequested = true
            return emptyList()
        }
        fragments[tsn.value] =
            Fragment(chunk.flags, chunk.streamId, chunk.streamSequenceNumber, chunk.payloadProtocolId, copyOf(chunk.userData))
        aboveCumulative += tsn.value

        val advancedContiguously = tsn.value == cumulativeTsn.next().value
        advanceCumulative()
        if (!advancedContiguously) sackImmediatelyRequested = true

        return reassembleDeliverable()
    }

    /**
     * FORWARD-TSN (RFC 3758 §3.6): the peer abandoned data up to [newCumulativeTsn]. Advance our
     * cumulative TSN, drop skipped fragments, bump each ordered stream's expected SSN past the abandoned
     * one, and drain any messages that became deliverable. A FORWARD-TSN always forces an immediate SACK.
     */
    fun onForwardTsn(
        newCumulativeTsn: Tsn,
        streams: List<ForwardTsnStream>,
    ): List<ReassembledMessage> {
        sackImmediatelyRequested = true
        if (cumulativeTsn.sackPrecedes(newCumulativeTsn)) {
            // Consume every TSN up to and including the new cumulative point.
            var t = cumulativeTsn.next()
            while (t.sackPrecedes(newCumulativeTsn) || t.value == newCumulativeTsn.value) {
                aboveCumulative.remove(t.value)
                fragments.remove(t.value)
                t = t.next()
            }
            cumulativeTsn = newCumulativeTsn
            advanceCumulative()
        }
        for (s in streams) {
            val skipTo = s.streamSequenceNumber.value.toInt() + 1
            val current = nextOrderedSsn[s.streamId] ?: 0
            if (skipTo > current) nextOrderedSsn[s.streamId] = skipTo
        }
        return reassembleDeliverable()
    }

    /** The SACK to send now (RFC 4960 §3.3.4): cumulative ack, gap blocks, duplicate TSNs; clears dups. */
    fun buildSack(): SctpChunk.Sack {
        val gaps = ArrayList<com.ditchoom.webrtc.sctp.GapAckBlock>()
        val sorted = aboveCumulative.sorted()
        var i = 0
        while (i < sorted.size) {
            val runStart = sorted[i]
            var runEnd = runStart
            while (i + 1 < sorted.size && sorted[i + 1] == runEnd + 1u) {
                runEnd = sorted[i + 1]
                i++
            }
            gaps +=
                com.ditchoom.webrtc.sctp.GapAckBlock(
                    start = (runStart - cumulativeTsn.value).toUShort(),
                    end = (runEnd - cumulativeTsn.value).toUShort(),
                )
            i++
        }
        val dups = duplicates.toList()
        duplicates.clear()
        sackImmediatelyRequested = false
        return SctpChunk.Sack(cumulativeTsn, config.receiveWindowBytes, gaps, dups)
    }

    // Advance the cumulative TSN over the contiguous prefix of the gap map (RFC 4960 §6.2).
    private fun advanceCumulative() {
        while (aboveCumulative.remove(cumulativeTsn.next().value)) {
            cumulativeTsn = cumulativeTsn.next()
        }
    }

    // Assemble every complete B..E fragment run present, delivering unordered messages immediately and
    // stashing ordered ones by SSN, then drain each ordered stream in SSN order.
    private fun reassembleDeliverable(): List<ReassembledMessage> {
        val delivered = ArrayList<ReassembledMessage>()
        for ((beginTsn, run) in collectCompleteRuns()) {
            val head = run.first()
            val message = ReassembledMessage(head.streamId, head.ppid, head.flags.unordered, assemble(run))
            run.indices.forEach { fragments.remove(beginTsn + it.toUInt()) }
            if (head.flags.unordered) {
                delivered += message
            } else {
                orderedReady.getOrPut(head.streamId) { HashMap() }[head.ssn.value.toInt()] = message
            }
        }
        drainOrdered(delivered)
        return delivered
    }

    // Find every contiguous B..E run fully present in [fragments]; returns (beginTsn, fragments-in-order).
    private fun collectCompleteRuns(): List<Pair<UInt, List<Fragment>>> {
        val runs = ArrayList<Pair<UInt, List<Fragment>>>()
        val sortedTsns = fragments.keys.sorted()
        for (startTsn in sortedTsns) {
            val start = fragments[startTsn] ?: continue
            if (!start.flags.beginning) continue
            val run = ArrayList<Fragment>()
            var cur = startTsn
            var complete = false
            while (true) {
                val frag = fragments[cur] ?: break
                // A second Begin (other than the first) marks a new message — the run is truncated.
                if (cur != startTsn && frag.flags.beginning) break
                run += frag
                if (frag.flags.ending) {
                    complete = true
                    break
                }
                cur += 1u
            }
            if (complete) runs += startTsn to run
        }
        return runs
    }

    private fun drainOrdered(out: MutableList<ReassembledMessage>) {
        for ((streamId, ready) in orderedReady) {
            var expected = nextOrderedSsn[streamId] ?: 0
            while (true) {
                val message = ready.remove(expected) ?: break
                out += message
                expected += 1
            }
            nextOrderedSsn[streamId] = expected
        }
    }

    private fun assemble(run: List<Fragment>): ReadBuffer {
        if (run.size == 1) return run.first().payload
        val total = run.sumOf { it.payload.remaining() }
        val dest = config.bufferFactory.allocate(maxOf(1, total), ByteOrder.BIG_ENDIAN)
        for (frag in run) {
            val p = frag.payload.position()
            dest.write(frag.payload)
            frag.payload.position(p)
        }
        dest.resetForRead()
        dest.setLimit(total)
        return dest
    }

    private fun copyOf(view: ReadBuffer): PlatformBuffer {
        val slice = view.slice()
        val len = slice.remaining()
        val copy = config.bufferFactory.allocate(maxOf(1, len), ByteOrder.BIG_ENDIAN)
        copy.write(slice)
        copy.resetForRead()
        copy.setLimit(len)
        return copy
    }
}

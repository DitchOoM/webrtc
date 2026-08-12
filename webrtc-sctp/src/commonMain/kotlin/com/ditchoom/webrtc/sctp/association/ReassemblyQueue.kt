package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.webrtc.sctp.DataChunkFlags
import com.ditchoom.webrtc.sctp.ForwardTsnStream
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.StreamSequenceNumber
import com.ditchoom.webrtc.sctp.Tsn

/**
 * A fully reassembled user message ready to hand up to the DataChannel layer.
 *
 * [payload] is allocated from `SctpConfig.bufferFactory` and is **transferred** — once this leaves the
 * queue the driver owns it, and every message that never leaves (held for ordering, then dropped by a
 * stream reset or a FORWARD-TSN that skips past it) is released here instead.
 */
internal class ReassembledMessage(
    val streamId: StreamId,
    val ppid: PayloadProtocolId,
    val unordered: Boolean,
    val payload: ReadBuffer,
)

// One stored DATA fragment (its payload copied out of the borrowed datagram) awaiting reassembly.
//
// [bytes] is recorded at construction rather than read back off [payload]: assembly moves the payload's
// cursor, and the run accounting below has to agree with `fragments` at every moment, not only while
// nothing has read from it.
private class Fragment(
    val flags: DataChunkFlags,
    val streamId: StreamId,
    val ssn: StreamSequenceNumber,
    val ppid: PayloadProtocolId,
    val bytes: Int,
    val payload: ReadBuffer,
)

/**
 * What happened to one ingested DATA chunk (RFC 4960 §6.2).
 *
 * A sealed answer rather than a bare list because storing a chunk is not the only outcome: a chunk that
 * carries a message past this endpoint's advertised `a=max-message-size` (RFC 8841 §6) is refused, and
 * the refusal is fatal to the association — it cannot be reported as "nothing became deliverable", which
 * is what an empty list means.
 *
 * Track F adds a third variant here (`RefusedForBuffer`, RFC 4960 §6.2's want-of-buffer drop). It is
 * deliberately not forward-declared: a variant nothing produces is a branch nothing exercises.
 */
internal sealed interface ChunkIngest {
    /** Stored, or a duplicate; [messages] is what became deliverable, possibly empty. */
    data class Delivered(
        val messages: List<ReassembledMessage>,
    ) : ChunkIngest

    /**
     * The message this chunk joins already holds more than [ceilingBytes] bytes, so it crosses the
     * ceiling this endpoint advertised. Nothing was stored and nothing was copied — the association
     * ABORTs (RFC 4960 §3.3.7, Protocol Violation).
     */
    data class MessageTooLarge(
        val streamId: StreamId,
        val ceilingBytes: Long,
        val observedBytes: Long,
    ) : ChunkIngest
}

/**
 * A maximal contiguous run of stored fragments believed to belong to ONE user message, and how many
 * bytes of that message are held in it.
 *
 * This index exists so the size check is **O(1) per chunk**. The obvious alternative — walk `fragments`
 * outward from the arriving TSN, summing until a boundary — is correct and is a denial of service: a
 * peer sending one-byte fragments makes every arrival cost a walk proportional to what it has already
 * sent, so reaching a 256 KiB ceiling costs 256K² lookups. The index makes reaching it cost 256K.
 *
 * "Believed to belong to one message" is doing real work. A run must never span a message boundary, or
 * the accounting over-counts and a healthy association is aborted for a message that was never that
 * large — a false positive is strictly worse here than the attack it defends against. So a merge is
 * refused across a B flag, across an E flag, and across the stream/ordering/SSN discontinuity
 * `collectCompleteRuns` already refuses to assemble across.
 */
private class PartialRun(
    var firstTsn: UInt,
    var lastTsn: UInt,
    var bytes: Long,
    var beginsMessage: Boolean,
    var endsMessage: Boolean,
    val streamId: StreamId,
    val unordered: Boolean,
    val ssn: StreamSequenceNumber,
) {
    /** All fragments of one user message share these (RFC 4960 §6.9). */
    fun sameMessageAs(
        streamId: StreamId,
        unordered: Boolean,
        ssn: StreamSequenceNumber,
    ): Boolean = this.streamId == streamId && this.unordered == unordered && (unordered || this.ssn == ssn)
}

/**
 * The receive-side reassembly + ordered-delivery engine (RFC 4960 §6.2 receiver, §6.9 fragmentation,
 * RFC 3758 §3.6 FORWARD-TSN). Tracks the cumulative TSN and the gap map for SACK generation, copies and
 * reassembles DATA fragments into whole user messages, and gates ordered streams by Stream Sequence
 * Number while delivering unordered messages as soon as they are complete.
 *
 * Serial-number wrap of TSN/SSN is not modeled (the dcSCTP data-channel subset never approaches 2³²
 * within a session, ARCHITECTURE §11.2) — comparisons use plain unsigned order; this is the one documented
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

    // The RFC 8841 §6 size accounting (see [PartialRun]). Both maps point at the SAME run objects, keyed
    // by its two endpoints, so an arriving TSN finds in O(1) the run it extends on either side.
    private val runByFirstTsn = HashMap<UInt, PartialRun>()
    private val runByLastTsn = HashMap<UInt, PartialRun>()

    // Ordered delivery state: the next SSN to deliver per stream, and assembled-but-waiting messages.
    private val nextOrderedSsn = HashMap<StreamId, Int>()
    private val orderedReady = HashMap<StreamId, HashMap<Int, ReassembledMessage>>()

    /** True when a SACK should be sent without delay (out-of-order data arrived — RFC 4960 §6.2). */
    var sackImmediatelyRequested = false
        private set

    /**
     * Ingest one DATA chunk (RFC 4960 §6.2): dedup, refuse an oversized message, store the copied
     * fragment, advance the cumulative TSN, then reassemble and return every message now deliverable in
     * order. A duplicate or an out-of-order arrival flips [sackImmediatelyRequested] so the association
     * SACKs promptly.
     *
     * The order of the two guards is fixed and load-bearing. **Dedup first**, so a retransmission of a
     * chunk already stored is not counted a second time into the run it is already part of — which would
     * abort a healthy association on a lossy path. **Size before the copy**, so a refusal costs nothing:
     * checking after `copyOf` would make the ceiling a peer-paced allocator, which is the opposite of
     * what it is for.
     */
    fun receive(chunk: SctpChunk.Data): ChunkIngest {
        val tsn = chunk.tsn
        val isDuplicate = !cumulativeTsn.sackPrecedes(tsn) || tsn.value in aboveCumulative
        if (isDuplicate) {
            duplicates += tsn
            sackImmediatelyRequested = true
            return ChunkIngest.Delivered(emptyList())
        }
        val bytes = chunk.userData.remaining()
        refuseOversized(chunk, projectedMessageBytes(chunk, bytes.toLong()))?.let { return it }

        fragments[tsn.value] =
            Fragment(
                chunk.flags,
                chunk.streamId,
                chunk.streamSequenceNumber,
                chunk.payloadProtocolId,
                bytes,
                copyOf(chunk.userData),
            )
        admitToRun(chunk, bytes.toLong())
        aboveCumulative += tsn.value

        val cumBefore = cumulativeTsn.value
        val advancedContiguously = tsn.value == cumulativeTsn.next().value
        advanceCumulative()
        // SACK immediately (RFC 4960 §6.2 / RFC 7053 §5.2) on: out-of-order data (a gap opened); a
        // gap FILLED (the cumulative TSN jumped by more than the one arriving chunk); or the sender's
        // explicit SACK-IMMEDIATELY 'I' bit.
        val gapFilled = (cumulativeTsn.value - cumBefore) > 1u
        if (!advancedContiguously || gapFilled || chunk.flags.immediate) sackImmediatelyRequested = true

        return ChunkIngest.Delivered(reassembleDeliverable())
    }

    // ── the RFC 8841 §6 receive ceiling ──

    /**
     * How many bytes of the message [chunk] belongs to would be held once it is stored — its own payload
     * plus whatever contiguous run it joins on either side.
     *
     * A **lower bound** on the finished message, deliberately. More fragments may still arrive, so this
     * says "the peer has already sent at least this much of one message". Refusing as soon as that
     * crosses the ceiling is the earliest a refusal is defensible, and it does not need the message to be
     * complete — which is the whole point, since a message that is never completed is exactly the shape
     * an attacker sends.
     */
    private fun projectedMessageBytes(
        chunk: SctpChunk.Data,
        bytes: Long,
    ): Long = bytes + (runBefore(chunk)?.bytes ?: 0L) + (runAfter(chunk)?.bytes ?: 0L)

    /**
     * [ChunkIngest.MessageTooLarge] when [projected] crosses this endpoint's advertised ceiling, or null.
     *
     * `Unbounded` has no comparison at all rather than one against a very large number: RFC 8841 §6's
     * "no limit" is the absence of a ceiling, and the `when` is what keeps it from ever being spelled as
     * a value some arithmetic could get backwards.
     */
    private fun refuseOversized(
        chunk: SctpChunk.Data,
        projected: Long,
    ): ChunkIngest.MessageTooLarge? =
        when (val limit = config.receiveMessageLimit) {
            ReceiveMessageLimit.Unbounded -> null
            is ReceiveMessageLimit.Bytes ->
                if (projected > limit.value) {
                    ChunkIngest.MessageTooLarge(chunk.streamId, limit.value, projected)
                } else {
                    null
                }
        }

    // The run ending immediately below this chunk's TSN that it may legally extend, or null. A run that
    // already carries its message's E flag is finished, and a chunk carrying B starts a new message, so
    // neither may be joined — those two tests are what keep two adjacent messages from being summed.
    private fun runBefore(chunk: SctpChunk.Data): PartialRun? =
        runByLastTsn[chunk.tsn.value - 1u]?.takeIf {
            !it.endsMessage &&
                !chunk.flags.beginning &&
                it.sameMessageAs(chunk.streamId, chunk.flags.unordered, chunk.streamSequenceNumber)
        }

    // The mirror image: the run starting immediately above, which this chunk may precede.
    private fun runAfter(chunk: SctpChunk.Data): PartialRun? =
        runByFirstTsn[chunk.tsn.value + 1u]?.takeIf {
            !it.beginsMessage &&
                !chunk.flags.ending &&
                it.sameMessageAs(chunk.streamId, chunk.flags.unordered, chunk.streamSequenceNumber)
        }

    // Fold a newly stored chunk into the index: it bridges two runs, extends one, or starts its own.
    private fun admitToRun(
        chunk: SctpChunk.Data,
        bytes: Long,
    ) {
        val tsn = chunk.tsn.value
        val before = runBefore(chunk)
        val after = runAfter(chunk)
        when {
            before != null && after != null -> {
                // The chunk was the last hole between two halves of one message; `before` absorbs both.
                runByLastTsn.remove(before.lastTsn)
                runByFirstTsn.remove(after.firstTsn)
                runByLastTsn.remove(after.lastTsn)
                before.lastTsn = after.lastTsn
                before.bytes += bytes + after.bytes
                before.endsMessage = after.endsMessage
                runByLastTsn[before.lastTsn] = before
            }
            before != null -> {
                runByLastTsn.remove(before.lastTsn)
                before.lastTsn = tsn
                before.bytes += bytes
                before.endsMessage = chunk.flags.ending
                runByLastTsn[tsn] = before
            }
            after != null -> {
                runByFirstTsn.remove(after.firstTsn)
                after.firstTsn = tsn
                after.bytes += bytes
                after.beginsMessage = chunk.flags.beginning
                runByFirstTsn[tsn] = after
            }
            else -> {
                val fresh =
                    PartialRun(
                        firstTsn = tsn,
                        lastTsn = tsn,
                        bytes = bytes,
                        beginsMessage = chunk.flags.beginning,
                        endsMessage = chunk.flags.ending,
                        streamId = chunk.streamId,
                        unordered = chunk.flags.unordered,
                        ssn = chunk.streamSequenceNumber,
                    )
                runByFirstTsn[tsn] = fresh
                runByLastTsn[tsn] = fresh
            }
        }
    }

    // Drop the run a delivered message occupied. Exact rather than a rebuild because a complete run is,
    // by construction, one whole entry: `collectCompleteRuns` accepts precisely the B..E same-message
    // spans [admitToRun] merges into one, so what it delivers is what this removes.
    private fun forgetRun(firstTsn: UInt) {
        val run = runByFirstTsn.remove(firstTsn) ?: return
        runByLastTsn.remove(run.lastTsn)
    }

    /**
     * Rebuild the whole index from `fragments`.
     *
     * The three paths that *remove* fragments without delivering them — FORWARD-TSN, a stream reset, and
     * teardown — can **split** a run rather than retire one, and a split is the case an incremental
     * update gets wrong quietly: the surviving halves keep the removed fragments' bytes and the ceiling
     * then fires on a message that is not that large. They are all rare (an abandonment, a channel
     * close), so they pay O(n log n) to be certainly right rather than O(1) to be probably right.
     */
    private fun rebuildRuns() {
        runByFirstTsn.clear()
        runByLastTsn.clear()
        var current: PartialRun? = null
        for (tsn in fragments.keys.sorted()) {
            val fragment = fragments[tsn] ?: continue
            val extends =
                current != null &&
                    current.lastTsn + 1u == tsn &&
                    !current.endsMessage &&
                    !fragment.flags.beginning &&
                    current.sameMessageAs(fragment.streamId, fragment.flags.unordered, fragment.ssn)
            if (extends && current != null) {
                runByLastTsn.remove(current.lastTsn)
                current.lastTsn = tsn
                current.bytes += fragment.bytes.toLong()
                current.endsMessage = fragment.flags.ending
                runByLastTsn[tsn] = current
            } else {
                val fresh =
                    PartialRun(
                        firstTsn = tsn,
                        lastTsn = tsn,
                        bytes = fragment.bytes.toLong(),
                        beginsMessage = fragment.flags.beginning,
                        endsMessage = fragment.flags.ending,
                        streamId = fragment.streamId,
                        unordered = fragment.flags.unordered,
                        ssn = fragment.ssn,
                    )
                runByFirstTsn[tsn] = fresh
                runByLastTsn[tsn] = fresh
                current = fresh
            }
        }
    }

    /**
     * Whether the run index still describes `fragments` exactly — the executable form of the one claim
     * the type system cannot make here (the plan's residue R6).
     *
     * Checked by every receive-side fixture rather than in production, because a drift is not something
     * the association can act on: it would mean the ceiling fires early or late, and both are bugs to be
     * caught before shipping rather than handled at runtime.
     *
     * Four things, and the last is the one an incremental update loses: every fragment lies in exactly
     * one run, each run's byte total is its fragments', each run's end flags are its endpoints', and each
     * run is **maximal** — the fragment just outside it must not be one it should have absorbed. Without
     * maximality a missed merge passes every other check while under-counting, which is the direction
     * that lets a message past the ceiling.
     */
    internal fun runsAgreeWithFragments(): Boolean {
        if (runByFirstTsn.size != runByLastTsn.size) return false
        var covered = 0
        for (run in runByFirstTsn.values) {
            if (runByLastTsn[run.lastTsn] !== run) return false
            if (run.lastTsn < run.firstTsn) return false
            var total = 0L
            var tsn = run.firstTsn
            while (true) {
                val fragment = fragments[tsn] ?: return false
                if (!run.sameMessageAs(fragment.streamId, fragment.flags.unordered, fragment.ssn)) return false
                if (tsn != run.firstTsn && fragment.flags.beginning) return false
                if (tsn != run.lastTsn && fragment.flags.ending) return false
                total += fragment.bytes.toLong()
                covered += 1
                if (tsn == run.lastTsn) break
                tsn += 1u
            }
            if (total != run.bytes) return false
            if (fragments[run.firstTsn]?.flags?.beginning != run.beginsMessage) return false
            if (fragments[run.lastTsn]?.flags?.ending != run.endsMessage) return false
            if (mergeableWithNeighbour(run)) return false
        }
        return covered == fragments.size
    }

    // Whether a run touches another run it should have absorbed — a missed merge, which under-counts and
    // is therefore the direction that lets an oversized message through. Adjacency alone is not a fault:
    // two adjacent runs of DIFFERENT messages, or either side of a B/E boundary, are correctly separate.
    private fun mergeableWithNeighbour(run: PartialRun): Boolean {
        val below = runByLastTsn[run.firstTsn - 1u]
        if (below != null &&
            !below.endsMessage &&
            !run.beginsMessage &&
            below.sameMessageAs(run.streamId, run.unordered, run.ssn)
        ) {
            return true
        }
        val above = runByFirstTsn[run.lastTsn + 1u]
        return above != null &&
            !above.beginsMessage &&
            !run.endsMessage &&
            above.sameMessageAs(run.streamId, run.unordered, run.ssn)
    }

    /**
     * Record [tsn] as received while storing nothing (RFC 4960 §3.3.10.1): the chunk named a stream
     * outside the negotiated range, so its payload is refused and the association answers with an ERROR —
     * but the TSN itself *did* arrive.
     *
     * Acknowledging it is not a nicety. A receiver that leaves its cumulative point below a refused TSN
     * invites the peer to retransmit that chunk until its error counter aborts the whole association, so
     * the refusal would cost every other data channel on it. This is the same shape as answering a
     * RE-CONFIG request we will not perform instead of ignoring it.
     */
    fun discard(tsn: Tsn) {
        val isDuplicate = !cumulativeTsn.sackPrecedes(tsn) || tsn.value in aboveCumulative
        if (isDuplicate) {
            duplicates += tsn
            sackImmediatelyRequested = true
            return
        }
        aboveCumulative += tsn.value
        val cumBefore = cumulativeTsn.value
        val advancedContiguously = tsn.value == cumulativeTsn.next().value
        advanceCumulative()
        val gapFilled = (cumulativeTsn.value - cumBefore) > 1u
        if (!advancedContiguously || gapFilled) sackImmediatelyRequested = true
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
                // The peer abandoned this fragment, so its copy has no reader left: this is its last one.
                fragments.remove(t.value)?.payload?.freeIfNeeded()
                t = t.next()
            }
            cumulativeTsn = newCumulativeTsn
            advanceCumulative()
        }
        for (s in streams) {
            val skipTo = s.streamSequenceNumber.value.toInt() + 1
            val current = nextOrderedSsn[s.streamId] ?: 0
            if (skipTo > current) {
                nextOrderedSsn[s.streamId] = skipTo
                // Drop any already-reassembled-but-held ordered messages the skip jumps over — else a
                // message the peer abandoned (yet whose fragments we happened to fully receive) sits in
                // orderedReady forever, growing the map under sustained partial-reliability abandonment.
                // Each one is a reassembly buffer that will now never be delivered, so this is where it
                // is released; dropping the map entry alone would leak the copy behind it.
                orderedReady[s.streamId]?.let { ready ->
                    val skipped = ready.keys.filter { it < skipTo }
                    for (ssn in skipped) ready.remove(ssn)?.payload?.freeIfNeeded()
                }
            }
        }
        // The abandoned span can have taken the front off a held run, leaving a survivor that must not
        // keep carrying its bytes — before anything is delivered below, since delivery reads the index.
        rebuildRuns()
        return reassembleDeliverable()
    }

    /**
     * Apply an inbound stream reset (RFC 6525 §5.2.2): the peer reset its outgoing streams, so every
     * trace of the affected streams' *sequencing* state goes with it — the next ordered message on such a
     * stream arrives with Stream Sequence Number 0 again.
     *
     * Three things are dropped, not just the SSN counter:
     * - the expected-SSN cursor, so a later message at SSN 0 is delivered rather than held forever
     *   waiting for the SSNs the reset just erased;
     * - reassembled-but-undelivered ordered messages, which belong to the pre-reset SSN space and can
     *   never become deliverable now that the cursor is gone;
     * - partial fragment runs, whose remaining fragments the peer will never send.
     *
     * The cumulative TSN is deliberately untouched: a stream reset re-sequences streams, it does not
     * renumber TSNs (that is the SSN/TSN reset of §4.3, which this subset refuses).
     */
    fun resetStreams(scope: StreamResetScope) {
        when (scope) {
            StreamResetScope.AllStreams -> {
                nextOrderedSsn.clear()
                releaseHeld(orderedReady.values)
                orderedReady.clear()
                releaseFragments(fragments.values)
                fragments.clear()
            }
            is StreamResetScope.Streams -> {
                for (id in scope.ids) {
                    nextOrderedSsn.remove(id)
                    orderedReady.remove(id)?.let { releaseHeld(listOf(it)) }
                }
                // The TSNs, materialised BEFORE anything is removed. This used to keep the `Map.Entry`
                // objects and read `entry.key` after the first removal, which works on the JVM (a
                // `HashMap.Node` survives its map being modified) and throws
                // `ConcurrentModificationException` on Kotlin/JS, where an entry is a live view that
                // `checkForComodification`s on every access. A throw here is a throw inside
                // `association.handle` — into the serialized drive loop, taking the session down (T0).
                //
                // Reachable by any peer closing a data channel while two or more of its DATA fragments
                // are held, which is an ordinary lossy close rather than an attack. Unseen because it
                // needs TWO fragments to drop: with one, the single `remove` happens after the last
                // `entry.key` read and nothing is invalidated.
                val dropped = ArrayList<UInt>()
                for ((tsn, fragment) in fragments) if (fragment.streamId in scope.ids) dropped += tsn
                for (tsn in dropped) fragments.remove(tsn)?.payload?.freeIfNeeded()
            }
        }
        // A reset drops one stream's fragments out of a TSN space it shares with every other stream, so
        // what is left can be two halves of a run that was one — see [rebuildRuns].
        rebuildRuns()
    }

    /**
     * Discard everything still held — the association is going away. Unlike the send side there is no
     * ordering hazard here: nothing outside this queue ever gets a view of a fragment copy or of a message
     * still waiting on its Stream Sequence Number, so the last reader is this call.
     */
    fun drain() {
        releaseHeld(orderedReady.values)
        orderedReady.clear()
        releaseFragments(fragments.values)
        fragments.clear()
        runByFirstTsn.clear()
        runByLastTsn.clear()
        nextOrderedSsn.clear()
        aboveCumulative.clear()
        duplicates.clear()
    }

    private fun releaseHeld(streams: Collection<HashMap<Int, ReassembledMessage>>) {
        for (ready in streams) {
            for (message in ready.values) message.payload.freeIfNeeded()
        }
    }

    private fun releaseFragments(held: Collection<Fragment>) {
        for (fragment in held) fragment.payload.freeIfNeeded()
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
            // A Gap Ack Block offset is a u16 (RFC 4960 §3.3.4). A run more than 65535 TSNs above the
            // cumulative point cannot be represented — and casting it to UShort would wrap into a
            // malformed (end < start) block the peer mis-decodes. Since `sorted` is ascending, once one
            // run overflows so do all the rest, so stop emitting blocks here (the missing low TSN is
            // recovered by T3 first, then these gaps become reportable).
            if (runStart - cumulativeTsn.value > 0xFFFFu) break
            gaps +=
                com.ditchoom.webrtc.sctp.GapAckBlock(
                    start = (runStart - cumulativeTsn.value).toUShort(),
                    end = (runEnd - cumulativeTsn.value).coerceAtMost(0xFFFFu).toUShort(),
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
            // A complete run is exactly one index entry (see [forgetRun]), so this retires it whole
            // rather than needing the rebuild the removal paths above pay for.
            forgetRun(beginTsn)
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
                // All fragments of a user message share one stream id, ordering, and (when ordered) SSN
                // (RFC 4960 §6.9). A malformed peer that splices a B on (stream 1, ssn 4) to an E on
                // (stream 2, ssn 9) must not be assembled into one message attributed to the head —
                // treat a stream/ordering/SSN discontinuity as an incomplete run (dropped, not delivered).
                if (cur != startTsn &&
                    (
                        frag.streamId != start.streamId ||
                            frag.flags.unordered != start.flags.unordered ||
                            (!start.flags.unordered && frag.ssn != start.ssn)
                    )
                ) {
                    break
                }
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
                // The Stream Sequence Number is a u16 that wraps (RFC 4960 §6.6): mask so that after the
                // 65535th ordered message on a stream `expected` folds back to 0 to match the sender's
                // wrapped SSN — otherwise it climbs to 65536, never matches an incoming ssn, and every
                // subsequent ordered message is stuck in `ready` forever.
                expected = (expected + 1) and 0xFFFF
            }
            nextOrderedSsn[streamId] = expected
        }
    }

    /**
     * Join a complete B..E run into the one buffer the message is delivered as, **consuming the run**:
     * every fragment copy in it is either transferred (the single-fragment case, where the fragment's own
     * buffer *is* the message and no copy is made) or released here, once its bytes are in [dest]. The
     * caller drops the run from [fragments] straight after, so this is the last reader either way.
     */
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
        for (frag in run) frag.payload.freeIfNeeded()
        return dest
    }

    private fun copyOf(view: ReadBuffer): PlatformBuffer {
        // The slice is taken only to read `view` without disturbing its cursor, and it is dead the moment
        // the copy is made — but on a pooled datagram `slice()` is `addRef()`, and `TrackedSlice`
        // re-parents to the ROOT chunk, so dropping it pinned the received datagram once per call. The
        // copy itself is genuinely owned by the caller and is NOT released here.
        val slice = view.slice()
        return try {
            val len = slice.remaining()
            val copy = config.bufferFactory.allocate(maxOf(1, len), ByteOrder.BIG_ENDIAN)
            copy.write(slice)
            copy.resetForRead()
            copy.setLimit(len)
            copy
        } finally {
            slice.freeIfNeeded()
        }
    }
}

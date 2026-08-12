@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.webrtc.sctp.DataChunkFlags
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.StreamSequenceNumber
import com.ditchoom.webrtc.sctp.Tsn
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime

/**
 * **The receive ceiling** (RFC 8841 §6): a peer that sends a message larger than the
 * `a=max-message-size` this endpoint advertised is refused, and the refusal costs nothing.
 *
 * The property under test is the *accounting*, not the comparison. A ceiling checked at assemble time
 * would be protocol-correct and worthless — by then the whole message has been copied into this
 * process's memory, which is the thing the ceiling exists to bound. So the check runs on arrival of each
 * fragment, against the bytes of the message already held, and the index that makes it O(1) is what has
 * to be right.
 *
 * Two ways for that accounting to be wrong, and they fail in opposite directions:
 *
 * - **Over-counting** aborts a healthy association. Two independent messages summed together, or a
 *   retransmission counted twice, and a working session dies on traffic well under its own ceiling. This
 *   is the worse failure of the two, and `two_pipelined_messages`, `a_run_spliced_across_two_streams`,
 *   `a_begin_or_end_flag`, `a_retransmitted_fragment`, `a_forward_tsn_that_cuts_into_a_run` and
 *   `a_stream_reset` are all aimed at it.
 * - **Under-counting** lets an oversized message through — a missed merge, most plausibly when fragments
 *   arrive out of order and are joined from both sides. `fragments_arriving_in_reverse_order` and
 *   `a_chunk_that_fills_a_hole` are aimed at that one.
 *
 * Every fixture asserts `runsAgreeWithFragments()` afterwards, which is the executable form of the one
 * claim the type system cannot make here: that the index still describes the fragments exactly. It
 * checks maximality too, so a missed merge is caught even when the byte totals happen to add up.
 */
class ReceiveMessageLimitTest {
    private val stream0 = StreamId(0)
    private val stream1 = StreamId(1)

    private fun queue(ceiling: ReceiveMessageLimit = ReceiveMessageLimit.Bytes(CEILING.toLong())) =
        reassemblyQueue(peerInitialTsn = Tsn(1u), config = SctpConfig(receiveMessageLimit = ceiling))

    private fun data(
        tsn: Int,
        size: Int,
        ssn: Int = 0,
        streamId: StreamId = stream0,
        beginning: Boolean = true,
        ending: Boolean = true,
        unordered: Boolean = false,
    ): SctpChunk.Data =
        SctpChunk.Data(
            flags = DataChunkFlags.of(beginning = beginning, ending = ending, unordered = unordered, immediate = false),
            tsn = Tsn(tsn.toUInt()),
            streamId = streamId,
            streamSequenceNumber = StreamSequenceNumber(ssn.toUShort()),
            payloadProtocolId = PayloadProtocolId.WebRtcBinary,
            userData = payload(size, seed = tsn),
        )

    private fun ReassemblyQueue.expectAccepted(chunk: SctpChunk.Data): List<ReassembledMessage> {
        val ingest = receive(chunk)
        val delivered = assertIs<ChunkIngest.Delivered>(ingest, "chunk ${chunk.tsn.value} was refused: $ingest").messages
        assertTrue(runsAgreeWithFragments(), "the run index drifted from `fragments` after TSN ${chunk.tsn.value}")
        assertTrue(heldBytesAgreeWithContents(), "the held-bytes ledger drifted after TSN ${chunk.tsn.value}")
        return delivered
    }

    private fun ReassemblyQueue.expectRefused(chunk: SctpChunk.Data): ChunkIngest.MessageTooLarge {
        val ingest = receive(chunk)
        val refusal = assertIs<ChunkIngest.MessageTooLarge>(ingest, "chunk ${chunk.tsn.value} was accepted: $ingest")
        assertTrue(runsAgreeWithFragments(), "a refusal must leave the index untouched")
        return refusal
    }

    private fun release(messages: List<ReassembledMessage>) {
        for (message in messages) message.payload.freeIfNeeded()
    }

    @Test
    fun a_single_chunk_over_the_ceiling_is_refused() {
        val q = queue()
        val refusal = q.expectRefused(data(tsn = 1, size = CEILING + 1))
        assertEquals(stream0, refusal.streamId)
        assertEquals(CEILING.toLong(), refusal.ceilingBytes)
        assertEquals((CEILING + 1).toLong(), refusal.observedBytes)
    }

    /**
     * The anti-vacuity half. Without it every fixture here passes on a queue that refuses everything —
     * and a message at exactly the advertised ceiling is one this endpoint *promised* to receive.
     */
    @Test
    fun a_message_at_exactly_the_ceiling_is_delivered() {
        val q = queue()
        val delivered = q.expectAccepted(data(tsn = 1, size = CEILING))
        assertEquals(1, delivered.size)
        assertEquals(CEILING, delivered.first().payload.remaining())
        release(delivered)
    }

    /**
     * The refusal fires **as the run crosses the ceiling**, not when the message finally ends — a
     * message that never ends is exactly the shape that makes the ceiling worth having. Half of `CEILING`
     * per fragment, so the third one is where it must fire, and the message has no `E` fragment at all.
     */
    @Test
    fun a_run_that_crosses_the_ceiling_is_refused_before_the_message_ends() {
        val q = queue()
        val half = CEILING / 2
        q.expectAccepted(data(tsn = 1, size = half, beginning = true, ending = false))
        q.expectAccepted(data(tsn = 2, size = half, beginning = false, ending = false))
        val refusal = q.expectRefused(data(tsn = 3, size = half, beginning = false, ending = false))
        assertEquals((half * 3).toLong(), refusal.observedBytes)
    }

    /**
     * **The false positive that matters most.** Two messages of three quarters of the ceiling each, held
     * at the same time on the same stream, must not be summed — an accounting that adds them aborts a
     * healthy association on every lossy path, which is worse than having no ceiling at all.
     *
     * Their fragments are TSN-adjacent, so an index that merged runs on contiguity alone gets this wrong;
     * what keeps them apart is the second message's `B` flag.
     */
    @Test
    fun two_pipelined_messages_under_the_ceiling_do_not_trip_it_together() {
        val q = queue()
        val threeQuarters = CEILING / 4 * 3
        val first = threeQuarters / 2
        // Message one: TSN 1..2, held incomplete because TSN 1's B arrives without its E yet.
        q.expectAccepted(data(tsn = 1, size = first, ssn = 0, beginning = true, ending = false))
        // Message two begins at TSN 3 — adjacent to message one's fragments and a different message.
        q.expectAccepted(data(tsn = 3, size = first, ssn = 1, beginning = true, ending = false))
        q.expectAccepted(data(tsn = 4, size = threeQuarters - first, ssn = 1, beginning = false, ending = true))
        // …and completing message one still does not trip it: 1.5 ceilings are held, in two messages.
        val delivered = q.expectAccepted(data(tsn = 2, size = threeQuarters - first, ssn = 0, beginning = false, ending = true))
        assertEquals(2, delivered.size, "both messages deliver, in SSN order")
        assertEquals(threeQuarters, delivered.first().payload.remaining())
        release(delivered)
    }

    /**
     * A **malformed** peer splicing a run across two streams — TSN 1 carries stream 0's `B` and TSN 2
     * carries stream 1's `E`, with no `B` between them to separate them. `collectCompleteRuns` already
     * refuses to assemble that (`fragments_from_different_streams_are_not_spliced`), and the accounting
     * has to refuse to sum it for the same reason: two three-quarter-ceiling messages on two streams are
     * not one-and-a-half-ceiling message, and treating them as one aborts an association over a peer's
     * malformed framing rather than dropping it.
     *
     * This is the case the stream/ordering/SSN test in the merge exists for. Well-formed traffic cannot
     * reach it — a message's fragments are TSN-contiguous (RFC 4960 §6.9), so two well-formed messages
     * are always separated by a `B` — which is exactly why it needs a fixture rather than an argument.
     */
    @Test
    fun a_run_spliced_across_two_streams_is_not_summed() {
        val q = queue()
        val threeQuarters = CEILING / 4 * 3
        q.expectAccepted(
            data(tsn = 1, size = threeQuarters, streamId = stream0, unordered = true, beginning = true, ending = false),
        )
        // No B, so contiguity alone would join it to the run above — the stream id is what refuses.
        q.expectAccepted(
            data(tsn = 2, size = threeQuarters, streamId = stream1, unordered = true, beginning = false, ending = true),
        )
        assertTrue(runsAgreeAfter(q), "two separate runs, neither carrying the other's bytes")
    }

    /**
     * The **B and E flags** as merge boundaries, isolated. Every other fixture here that keeps two
     * messages apart does so by SSN or by stream id, so those two guards were untested until this one:
     * an **unordered** stream has no meaningful SSN (the `unordered ||` short-circuit in `sameMessageAs`
     * makes every unordered chunk on a stream "the same message"), leaving the flags as the only
     * discriminant left.
     *
     * All three layouts are malformed — classic SCTP fragments a message into contiguous TSNs
     * (RFC 4960 §6.9), so a well-formed peer's `B` is always preceded by an `E` and the two guards are
     * defence in depth. That is precisely why they need a fixture rather than an argument: a peer that
     * frames like this drops its messages (`collectCompleteRuns` truncates the run) and must not be able
     * to make the accounting sum them into an ABORT of a session that is otherwise fine.
     */
    @Test
    fun a_begin_or_end_flag_stops_a_merge_that_no_ssn_or_stream_would() {
        val threeQuarters = CEILING / 4 * 3

        fun chunk(
            tsn: Int,
            beginning: Boolean,
            ending: Boolean,
        ) = data(
            tsn = tsn,
            size = threeQuarters,
            streamId = stream0,
            unordered = true,
            beginning = beginning,
            ending = ending,
        )

        // A second B: the arriving chunk starts a new message, so it may not join the run below it.
        val forward = queue()
        forward.expectAccepted(chunk(tsn = 1, beginning = true, ending = false))
        forward.expectAccepted(chunk(tsn = 2, beginning = true, ending = true))

        // The same pair in reverse: now the run ABOVE begins a message, so the arriving chunk may not
        // be prepended to it. Symmetric guard, opposite side of the merge.
        val reverse = queue()
        reverse.expectAccepted(chunk(tsn = 2, beginning = true, ending = true))
        reverse.expectAccepted(chunk(tsn = 1, beginning = true, ending = false))

        // An E on the arriving chunk: it ends its own message, so an orphan continuation above is not
        // part of it however contiguous the TSNs are.
        val ending = queue()
        ending.expectAccepted(chunk(tsn = 2, beginning = false, ending = false))
        ending.expectAccepted(chunk(tsn = 1, beginning = true, ending = true))
    }

    /**
     * A **retransmission** must not be counted a second time into the run it is already part of. This is
     * the ordinary lossy path, not an attack, and double-counting it aborts a healthy association: the
     * dedup guard runs before the size projection precisely so that it cannot.
     */
    @Test
    fun a_retransmitted_fragment_is_not_counted_twice() {
        val q = queue()
        val twoThirds = CEILING / 3 * 2
        q.expectAccepted(data(tsn = 1, size = twoThirds, beginning = true, ending = false))
        // The same TSN again — a duplicate. Counted again it would be 4/3 of the ceiling and abort.
        q.expectAccepted(data(tsn = 1, size = twoThirds, beginning = true, ending = false))
        val delivered = q.expectAccepted(data(tsn = 2, size = CEILING - twoThirds, beginning = false, ending = true))
        assertEquals(1, delivered.size, "the message completes at exactly the ceiling")
        release(delivered)
    }

    /**
     * **Reverse arrival** — the under-count case. Each fragment merges with the run *above* it, so an
     * index that only ever extended a run downward would see one fragment at a time and never notice.
     */
    @Test
    fun fragments_arriving_in_reverse_order_still_reach_the_ceiling() {
        val q = queue()
        val third = CEILING / 3 + 1
        q.expectAccepted(data(tsn = 3, size = third, beginning = false, ending = true))
        q.expectAccepted(data(tsn = 2, size = third, beginning = false, ending = false))
        val refusal = q.expectRefused(data(tsn = 1, size = third, beginning = true, ending = false))
        assertEquals((third * 3).toLong(), refusal.observedBytes, "all three are one message, counted from both sides")
    }

    /**
     * The both-sides merge, isolated: a chunk that fills the hole between two halves of one message must
     * bridge them. Without the bridge each half stays under the ceiling forever and an arbitrarily large
     * message walks through by arriving with a hole in it — the sharpest under-count there is.
     */
    @Test
    fun a_chunk_that_fills_a_hole_bridges_the_two_runs_it_joins() {
        val q = queue()
        val third = CEILING / 3 + 1
        q.expectAccepted(data(tsn = 1, size = third, beginning = true, ending = false))
        q.expectAccepted(data(tsn = 3, size = third, beginning = false, ending = true))
        val refusal = q.expectRefused(data(tsn = 2, size = third, beginning = false, ending = false))
        assertEquals((third * 3).toLong(), refusal.observedBytes)
    }

    /**
     * A FORWARD-TSN cuts a span out of the TSN axis, which can take the **front off a held run** — and
     * the survivor must stop carrying the abandoned bytes. An index left un-rebuilt keeps charging them
     * to a message that no longer exists, so the next legitimate fragment of the surviving message
     * aborts a healthy session.
     *
     * TSN 1 is deliberately never received: the cumulative point has to stay *below* the held fragments
     * for the FORWARD-TSN to remove any of them. (Without that gap the fixture is vacuous — the
     * `sackPrecedes` guard skips the whole removal, and it passes just as green with no rebuild at all.)
     */
    @Test
    fun a_forward_tsn_that_cuts_into_a_run_gives_back_the_abandoned_bytes() {
        val q = queue()
        val third = CEILING / 3
        // TSN 1 is lost. TSN 2..3 are one unordered message, two thirds of the ceiling, held above the gap.
        q.expectAccepted(data(tsn = 2, size = third, unordered = true, beginning = true, ending = false))
        q.expectAccepted(data(tsn = 3, size = third, unordered = true, beginning = false, ending = false))

        // The peer abandons everything up to TSN 2, which takes the run's own first fragment with it.
        q.onForwardTsn(Tsn(2u), emptyList())
        assertTrue(runsAgreeAfter(q), "the index was rebuilt after the abandoned span cut into the run")

        // One third is now held, so a further two thirds is exactly the ceiling and must be ACCEPTED.
        // Still charging the abandoned third makes it four thirds, and the association aborts — which is
        // what turns this line red without the rebuild above. The message itself is never delivered
        // (its `B` fragment was abandoned, so `collectCompleteRuns` will never assemble it), and that is
        // correct: what is under test is the accounting, not the reassembly.
        q.expectAccepted(data(tsn = 4, size = third * 2, unordered = true, beginning = false, ending = true))

        // …and the queue is still live afterwards: a fresh complete message of its own delivers.
        val delivered = q.expectAccepted(data(tsn = 5, size = third, unordered = true, beginning = true, ending = true))
        assertEquals(1, delivered.size, "the queue kept working after the abandonment")
        release(delivered)
    }

    /**
     * A stream reset drops one stream's fragments, so every run they were in must go with them. Left
     * behind, those runs describe fragments that no longer exist — which `runsAgreeWithFragments` catches
     * directly, and which the ceiling would otherwise keep charging a channel that has been closed.
     */
    @Test
    fun a_stream_reset_takes_the_runs_of_the_streams_it_drops() {
        val q = queue()
        val third = CEILING / 3
        q.expectAccepted(data(tsn = 1, size = third, streamId = stream0, unordered = true, beginning = true, ending = false))
        q.expectAccepted(data(tsn = 2, size = third, streamId = stream0, unordered = true, beginning = false, ending = false))
        q.expectAccepted(data(tsn = 3, size = third, streamId = stream1, unordered = true, beginning = true, ending = false))

        q.resetStreams(StreamResetScope.Streams(setOf(stream0)))
        assertTrue(runsAgreeAfter(q), "stream 0's run went with its fragments")
        // Stream 1's own accounting is intact and still holds exactly one third, so two more complete it
        // at exactly the ceiling — one byte of stream 0's abandoned bytes surviving would refuse this.
        val delivered =
            q.expectAccepted(
                data(tsn = 4, size = third * 2, streamId = stream1, unordered = true, beginning = false, ending = true),
            )
        assertEquals(1, delivered.size, "stream 1's message completes; stream 0's bytes went with the reset")
        release(delivered)
    }

    /** `Unbounded` is the absence of a ceiling, not a very large one — nothing is ever refused. */
    @Test
    fun an_unbounded_receiver_refuses_nothing() {
        val q = queue(ReceiveMessageLimit.Unbounded)
        val delivered = q.expectAccepted(data(tsn = 1, size = CEILING * 8))
        assertEquals(1, delivered.size)
        release(delivered)
    }

    private fun runsAgreeAfter(q: ReassemblyQueue): Boolean = q.runsAgreeWithFragments()

    private companion object {
        // Big enough that the fractions below are distinct sizes, small enough to keep the fixtures cheap.
        private const val CEILING = 3000
    }
}

/**
 * The receive ceiling end to end, over two real associations. The `ReassemblyQueueTest` above proves the
 * accounting; this proves what the association *does* about it — which is the half a unit test of the
 * queue cannot see.
 */
class PeerMessageTooLargeTest {
    @Test
    fun a_peer_message_over_the_ceiling_aborts_the_association_with_a_typed_reason() {
        val ceiling = 2048L
        val sim = SctpSim(config = SctpConfig(receiveMessageLimit = ReceiveMessageLimit.Bytes(ceiling)))
        sim.associateA()
        sim.run()
        assertEquals(SctpAssociationState.Established, sim.a.state)
        assertEquals(SctpAssociationState.Established, sim.b.state)

        // The association layer has no send gate — that is `SctpDataChannelStack`'s, one layer up — so
        // this stands in for a peer that ignored what we advertised, which is the only way here.
        val oversized: ReadBuffer = payload((ceiling * 2).toInt(), seed = 3)
        sim.post(
            toA = true,
            SctpEvent.SendMessage(SctpSendOptions(StreamId(0), PayloadProtocolId.WebRtcBinary), oversized),
        )
        sim.run()

        val reason = assertIs<SctpFailureReason.PeerMessageTooLarge>(sim.abortsB.firstOrNull(), "B aborted for the right reason")
        assertEquals(StreamId(0), reason.streamId)
        assertEquals(ceiling, reason.ceilingBytes)
        assertTrue(reason.observedBytes > ceiling, "it reports what was HELD when the ceiling was crossed")
        assertEquals(0, sim.inboxB.size, "no part of the oversized message was ever delivered")
        assertEquals(SctpAssociationState.Closed, sim.b.state)

        // The ABORT reached A rather than being emitted into the void: A tore down on receiving it, which
        // is what makes this an abort of the ASSOCIATION and not a one-sided hang.
        assertTrue(sim.abortsA.any { it is SctpFailureReason.AbortReceived }, "A received the ABORT and tore down")
        assertEquals(SctpAssociationState.Closed, sim.a.state)
    }

    /**
     * The discriminating pair. The identical timeline one byte under the ceiling must **deliver** — with
     * this the fixture above says "an oversized message aborts", and without it, it says only "this
     * association aborts", which a stack that aborted on any fragmented message would satisfy.
     */
    @Test
    fun the_same_timeline_at_the_ceiling_delivers_and_the_association_survives() {
        val ceiling = 2048L
        val sim = SctpSim(config = SctpConfig(receiveMessageLimit = ReceiveMessageLimit.Bytes(ceiling)))
        sim.associateA()
        sim.run()

        val atCeiling: ReadBuffer = payload(ceiling.toInt(), seed = 3)
        sim.post(
            toA = true,
            SctpEvent.SendMessage(SctpSendOptions(StreamId(0), PayloadProtocolId.WebRtcBinary), atCeiling),
        )
        sim.run()

        assertEquals(1, sim.inboxB.size, "a message at exactly the ceiling is delivered")
        assertEquals(
            ceiling.toInt(),
            sim.inboxB
                .first()
                .payload
                .remaining(),
        )
        assertTrue(sim.abortsB.isEmpty(), "nothing aborted")
        assertEquals(SctpAssociationState.Established, sim.b.state)
        assertEquals(SctpAssociationState.Established, sim.a.state)
    }
}

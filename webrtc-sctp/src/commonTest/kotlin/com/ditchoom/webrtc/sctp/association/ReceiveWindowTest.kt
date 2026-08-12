@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.webrtc.sctp.DataChunkFlags
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.StreamSequenceNumber
import com.ditchoom.webrtc.sctp.Tsn
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime

// A window small enough that a handful of chunks closes it — the arithmetic, not the default, is on trial.
private const val WINDOW_BYTES = 4_000
private const val CHUNK_BYTES = 1_000

/**
 * **Receive-side flow control** (RFC 4960 §3.3.2 a_rwnd, §6.2 receiver): what this endpoint advertises it
 * can still take, what it stores above that, and what it refuses.
 *
 * Three properties, and the middle one is a deliberate departure from a literal reading of the RFC:
 *
 * - The advertised window **falls as messages are held and rises as they are credited**. A window that
 *   only ever falls is the failure receive-side flow control introduces if the credit half is forgotten,
 *   and it is invisible until a long-lived session stalls.
 * - A chunk above the advertised window is still **stored**, up to the overrun ceiling. Applying RFC 4960
 *   §6.2's drop rule at the advertised window deadlocks a receiver whose buffer is full of half-reassembled
 *   messages — `a_partial_message_completes_across_a_closed_window` is the executable form of that, and it
 *   fails against the literal reading.
 * - A chunk above the **overrun ceiling** is refused, and the refusal costs nothing: nothing stored,
 *   nothing copied, nothing gap-acked.
 */
class ReceiveWindowTest {
    private val stream0 = StreamId(0)

    private fun config(
        overrun: ReceiveOverrunWindows = ReceiveOverrunWindows.Default,
        limit: ReceiveMessageLimit = ReceiveMessageLimit.Bytes(WINDOW_BYTES.toLong()),
    ) = SctpConfig(receiveWindowBytes = WINDOW_BYTES.toUInt(), receiveOverrun = overrun, receiveMessageLimit = limit)

    private fun data(
        tsn: Int,
        size: Int = CHUNK_BYTES,
        ssn: Int = 0,
        beginning: Boolean = true,
        ending: Boolean = true,
        unordered: Boolean = true,
    ): SctpChunk.Data =
        SctpChunk.Data(
            flags = DataChunkFlags.of(beginning = beginning, ending = ending, unordered = unordered, immediate = false),
            tsn = Tsn(tsn.toUInt()),
            streamId = stream0,
            streamSequenceNumber = StreamSequenceNumber(ssn.toUShort()),
            payloadProtocolId = PayloadProtocolId.WebRtcBinary,
            userData = payload(size, seed = tsn),
        )

    // ── the accountant on its own ──

    @Test
    fun the_advertised_window_falls_with_what_is_held_and_rises_with_what_is_credited() {
        val window = ReceiveWindow(WINDOW_BYTES.toUInt(), ReceiveOverrunWindows.Default)
        assertEquals(WINDOW_BYTES.toUInt(), window.advertised(0), "nothing held: the whole window is offered")

        // Bytes the reassembly queue is holding are charged even though no receipt exists for them yet.
        assertEquals((WINDOW_BYTES - CHUNK_BYTES).toUInt(), window.advertised(CHUNK_BYTES), "held fragments close the window")

        val first = window.issue(CHUNK_BYTES)
        val second = window.issue(CHUNK_BYTES)
        assertEquals((WINDOW_BYTES - 2 * CHUNK_BYTES).toUInt(), window.advertised(0), "delivered-but-unconsumed is charged too")
        assertEquals((2 * CHUNK_BYTES).toLong(), window.outstandingBytes)

        assertEquals(CHUNK_BYTES, window.credit(first), "a credit returns the bytes it was holding")
        assertEquals((WINDOW_BYTES - CHUNK_BYTES).toUInt(), window.advertised(0), "and the window reopens by exactly that")
        assertEquals(CHUNK_BYTES, window.credit(second))
        assertEquals(WINDOW_BYTES.toUInt(), window.advertised(0), "every receipt back: the whole window again")
    }

    // A receipt credited twice must credit ONCE. Two credit sites for one message is the shape S6 warns
    // about, and the failure is an over-advertisement — space offered that this endpoint does not have,
    // which nothing observes until memory runs out.
    @Test
    fun a_receipt_credited_twice_credits_once() {
        val window = ReceiveWindow(WINDOW_BYTES.toUInt(), ReceiveOverrunWindows.Default)
        val receipt = window.issue(CHUNK_BYTES)
        assertEquals(CHUNK_BYTES, window.credit(receipt))
        assertEquals(0, window.credit(receipt), "the second credit for one message moves nothing")
        assertEquals(WINDOW_BYTES.toUInt(), window.advertised(0), "…and cannot open the window past its capacity")
        assertEquals(0L, window.outstandingBytes)
    }

    // A receipt outliving its association is ordinary — the driver hands messages to an application
    // coroutine and the teardown is another. It must be a no-op, not an under-flow.
    @Test
    fun a_receipt_from_a_torn_down_association_credits_nothing() {
        val window = ReceiveWindow(WINDOW_BYTES.toUInt(), ReceiveOverrunWindows.Default)
        val receipt = window.issue(CHUNK_BYTES)
        window.forgetAll()
        assertEquals(0L, window.outstandingBytes, "a teardown drops every charge whole")
        assertEquals(0, window.credit(receipt), "and a late credit for one of them finds nothing")
        assertEquals(WINDOW_BYTES.toUInt(), window.advertised(0))
    }

    // The window is what is ADVERTISED; the overrun ceiling is what is STORED. They are different numbers
    // and the gap between them is the whole departure.
    @Test
    fun the_overrun_ceiling_is_a_multiple_of_the_window_not_the_window() {
        val window = ReceiveWindow(WINDOW_BYTES.toUInt(), ReceiveOverrunWindows(2))
        assertEquals(0u, window.advertised(WINDOW_BYTES), "at capacity the advertisement is zero")
        assertTrue(window.admits(WINDOW_BYTES, CHUNK_BYTES), "…and yet a chunk above it is still stored")
        assertTrue(window.admits(2 * WINDOW_BYTES - CHUNK_BYTES, CHUNK_BYTES), "up to exactly two windows")
        assertTrue(!window.admits(2 * WINDOW_BYTES, 1), "and not one byte beyond")
        assertEquals(0u, window.advertised(3 * WINDOW_BYTES), "an over-taken window advertises 0, never a wrapped u32")
    }

    // ── the queue over the accountant ──

    @Test
    fun a_chunk_past_the_overrun_ceiling_is_refused_and_costs_nothing() {
        // One window of overrun, so the ceiling IS the window and the refusal is easy to reach. The bytes
        // are held as four SEPARATE ordered messages blocked behind a missing SSN 0, not as one long run:
        // one message of 4000 bytes would trip the RFC 8841 §6 ceiling first, which is a different refusal.
        val config = config(overrun = ReceiveOverrunWindows(1))
        val window = ReceiveWindow(config.receiveWindowBytes, config.receiveOverrun)
        val q = ReassemblyQueue(Tsn(1u), config, window)
        for (n in 1..4) {
            val ingest = assertIs<ChunkIngest.Delivered>(q.receive(data(tsn = n + 1, ssn = n, unordered = false)))
            assertEquals(emptyList(), ingest.messages, "SSN $n is held while SSN 0 is missing")
        }
        assertEquals(4 * CHUNK_BYTES, q.bufferedBytes, "four assembled-but-order-blocked messages are held")
        assertEquals(0u, window.advertised(q.bufferedBytes), "the window is shut")

        val refused = data(tsn = 6, ssn = 5, unordered = false)
        assertEquals(ChunkIngest.RefusedForBuffer, q.receive(refused), "past the ceiling, the chunk is refused")
        refused.userData.freeIfNeeded()
        assertEquals(4 * CHUNK_BYTES, q.bufferedBytes, "a refusal stores nothing")
        assertTrue(q.heldBytesAgreeWithContents())
        assertTrue(q.runsAgreeWithFragments(), "a refusal leaves the run index untouched")
        assertTrue(q.sackImmediatelyRequested, "and it SACKs at once rather than waiting out the delay")

        // Nothing gap-acked: the TSN never entered the gap map, so the SACK reports it as still missing and
        // the peer retransmits it once the window reopens. That is the whole recovery path.
        val sack = q.buildSack(window.advertised(q.bufferedBytes))
        assertEquals(Tsn(0u), sack.cumulativeTsnAck, "the refused TSN did not advance the cumulative point")
        assertEquals(0u, sack.advertisedReceiverWindow, "…and the SACK tells the peer to stop")
        assertTrue(sack.gapAckBlocks.none { it.end.toInt() >= 6 }, "the refused TSN 6 was not reported as received")
        q.drain()
    }

    /**
     * **The deliberate departure, as a fixture.** Four fragments of one message fill the advertised window
     * exactly; the fifth — the one carrying the E flag, which is what would release all five — is above it.
     *
     * Applying RFC 4960 §6.2's drop rule at the *advertised* window refuses that fifth chunk, so the
     * message never completes, its bytes are never released, the window never reopens, and the association
     * is deadlocked with both peers behaving correctly. Applied at the overrun ceiling it completes.
     */
    @Test
    fun a_partial_message_completes_across_a_closed_window() {
        val config = config(limit = ReceiveMessageLimit.Bytes(8_000))
        val window = ReceiveWindow(config.receiveWindowBytes, config.receiveOverrun)
        val q = ReassemblyQueue(Tsn(1u), config, window)
        for (tsn in 1..4) {
            val ingest = assertIs<ChunkIngest.Delivered>(q.receive(data(tsn, beginning = tsn == 1, ending = false)))
            assertEquals(emptyList(), ingest.messages, "an unfinished message delivers nothing")
        }
        // The precondition, asserted rather than assumed: the window really is shut at this point, so the
        // chunk below genuinely is one a window-tight §6.2 drop would refuse.
        assertEquals(0u, window.advertised(q.bufferedBytes), "four fragments fill the advertised window exactly")

        val completing = q.receive(data(tsn = 5, beginning = false, ending = true))
        val messages = assertIs<ChunkIngest.Delivered>(completing, "the completing chunk must not be refused").messages
        assertEquals(1, messages.size, "the message completes across a window that is advertising zero")
        assertEquals(5 * CHUNK_BYTES, messages.first().bytes)
        assertEquals(0, q.bufferedBytes, "and every byte it was holding is released by the delivery")
        assertTrue(q.heldBytesAgreeWithContents())
        for (message in messages) message.payload.freeIfNeeded()
    }

    // Held bytes are the queue's; delivered-but-uncredited bytes are the window's; the advertisement is
    // their sum against capacity. A message moving between the two must not change the total.
    @Test
    fun a_delivered_message_moves_its_charge_it_does_not_release_it() {
        val window = ReceiveWindow(WINDOW_BYTES.toUInt(), ReceiveOverrunWindows.Default)
        val q = ReassemblyQueue(Tsn(1u), config(), window)
        val messages = assertIs<ChunkIngest.Delivered>(q.receive(data(tsn = 1))).messages
        assertEquals(1, messages.size)
        assertEquals(0, q.bufferedBytes, "the queue no longer holds it")

        val receipt = window.issue(messages.first().bytes)
        assertEquals(
            (WINDOW_BYTES - CHUNK_BYTES).toUInt(),
            window.advertised(q.bufferedBytes),
            "delivering does not reopen the window — the application still has the memory",
        )
        window.credit(receipt)
        assertEquals(WINDOW_BYTES.toUInt(), window.advertised(q.bufferedBytes), "consuming it does")
        for (message in messages) message.payload.freeIfNeeded()
    }

    // ── the knobs ──

    @Test
    fun an_overrun_below_one_window_is_unconstructible() {
        assertFailsWith<IllegalArgumentException> { ReceiveOverrunWindows(0) }
        assertFailsWith<IllegalArgumentException> { ReceiveOverrunWindows(-1) }
        assertEquals(2, ReceiveOverrunWindows.Default.value, "the default leaves a whole window of slack")
    }

    /**
     * A message this endpoint *permits* but can never *buffer* is a deadlock built out of two individually
     * reasonable knobs: every chunk past the ceiling is refused, the run never completes, its bytes are
     * never released, and the window stays shut. It is refused at construction rather than documented.
     */
    @Test
    fun a_receive_ceiling_above_the_overrun_ceiling_is_refused_at_construction() {
        assertFailsWith<IllegalArgumentException> {
            SctpConfig(
                receiveWindowBytes = 1_000u,
                receiveOverrun = ReceiveOverrunWindows(2),
                receiveMessageLimit = ReceiveMessageLimit.Bytes(4_001),
            )
        }
        // Exactly at the ceiling is legal — the message fits, with nothing to spare.
        SctpConfig(
            receiveWindowBytes = 1_000u,
            receiveOverrun = ReceiveOverrunWindows(2),
            receiveMessageLimit = ReceiveMessageLimit.Bytes(2_000),
        )
        // Unbounded states no number, so there is nothing to compare and nothing to refuse.
        SctpConfig(receiveWindowBytes = 1_000u, receiveMessageLimit = ReceiveMessageLimit.Unbounded)
    }
}

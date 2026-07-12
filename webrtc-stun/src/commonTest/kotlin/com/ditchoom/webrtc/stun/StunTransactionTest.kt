@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.ReadBuffer
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The sans-io [StunTransaction] driven over a synthetic clock (no wall time, no I/O). Asserts the
 * RFC 8489 §6.2.1 retransmission schedule as observable state (the arming deadlines and emitted
 * sends), never a wall-clock budget (directive #4).
 */
class StunTransactionTest {
    private val txId = TransactionId(0xDEADBEEFu, 0x0BADF00Du, 0xFEEDFACEu)
    private val t0 = Instant.fromEpochMilliseconds(0)

    private fun newTransaction(): StunTransaction {
        val request = StunMessageBuilder.of(StunClass.Request, StunMethod.Binding, txId).encode()
        return StunTransaction(txId, request)
    }

    @Test
    fun startSendsFirstRequestAndArmsInitialRto() {
        val tx = newTransaction()
        val out = tx.handle(StunTransactionEvent.Start, t0)
        assertEquals(1, out.count { it is StunTransactionOutput.SendRequest })
        assertEquals(t0 + 500.milliseconds, tx.nextDeadline())
    }

    @Test
    fun retransmitsWithDoublingRtoUpToRcThenTimesOut() {
        val tx = newTransaction()
        var now = t0
        val intervals = mutableListOf<Long>()

        var sends = tx.handle(StunTransactionEvent.Start, now).sends()
        var failed = false
        var prev = now
        while (!failed) {
            val deadline = tx.nextDeadline() ?: error("timer disarmed before timeout")
            intervals += (deadline - prev).inWholeMilliseconds
            now = deadline
            prev = deadline
            val out = tx.handle(StunTransactionEvent.TimerExpired, now)
            sends += out.sends()
            failed = out.any { it is StunTransactionOutput.Failed }
        }

        assertEquals(StunRetransmitPolicy.DEFAULT_RC, sends, "exactly Rc requests are sent")
        // Retransmit gaps double: 500, 1000, 2000, 4000, 8000, 16000, then the 16×RTO final wait.
        assertEquals(listOf(500L, 1000, 2000, 4000, 8000, 16000, 8000), intervals)
        assertTrue(tx.isTerminal)
        assertNull(tx.nextDeadline())
    }

    @Test
    fun matchingResponseCompletesAndStopsRetransmission() {
        val tx = newTransaction()
        tx.handle(StunTransactionEvent.Start, t0)

        val response = decodeResponse()
        val out = tx.handle(StunTransactionEvent.ResponseReceived(response), t0 + 120.milliseconds)
        assertEquals(1, out.count { it is StunTransactionOutput.Completed })
        assertTrue(tx.isTerminal)
        assertNull(tx.nextDeadline())
        // A late timer after completion is a no-op.
        assertTrue(tx.handle(StunTransactionEvent.TimerExpired, t0 + 999.milliseconds).isEmpty())
    }

    @Test
    fun responseWithDifferentTransactionIdIsIgnored() {
        val tx = newTransaction()
        tx.handle(StunTransactionEvent.Start, t0)
        val other =
            StunMessageBuilder
                .of(StunClass.SuccessResponse, StunMethod.Binding, TransactionId(1u, 2u, 3u))
                .encode()
        val otherMsg = (StunMessage.decode(other) as StunDecodeResult.Success).message
        assertTrue(tx.handle(StunTransactionEvent.ResponseReceived(otherMsg), t0 + 10.milliseconds).isEmpty())
        assertTrue(!tx.isTerminal)
        assertEquals(t0 + 500.milliseconds, tx.nextDeadline())
    }

    @Test
    fun seededTransactionIdsAreDeterministic() {
        // Directive #2: entropy is injected, so a fixed seed replays the same id.
        assertEquals(TransactionId.random(Random(42)), TransactionId.random(Random(42)))
    }

    private fun decodeResponse(): StunMessage {
        val bytes: ReadBuffer =
            StunMessageBuilder.of(StunClass.SuccessResponse, StunMethod.Binding, txId).encode()
        return (StunMessage.decode(bytes) as StunDecodeResult.Success).message
    }

    private fun List<StunTransactionOutput>.sends(): Int = count { it is StunTransactionOutput.SendRequest }
}

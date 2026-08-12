@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.minutes
import kotlin.time.ExperimentalTime

// A window a handful of messages closes. The interesting states are all at the closed end, and the default
// 1 MiB would need a thousand messages to reach them.
private const val WINDOW_BYTES = 4_000
private const val MESSAGE_BYTES = 1_000
private const val MESSAGES = 24

/**
 * **RFC 4960 §6.1 rule A's zero-window probe, and the error-counter excuse it comes with** (RFC 8540 §3.20).
 *
 * The bug: `consecutiveRtxErrors` was incremented on every T3 expiry with no exception, so a peer whose
 * application stalled for about ten backed-off RTOs aborted us — every data channel on the association,
 * with `RetransmissionLimitReached`, over a path that was working perfectly. It was unreachable
 * webrtc↔webrtc only because neither side ever advertised a window below its configured maximum, which is
 * exactly what receive-side flow control has just changed.
 *
 * **These fixtures come in a pair and the second is not optional.** A test that only asserts "the
 * association survived a stalled receiver" is green on an association that has stopped failing altogether,
 * which is a far worse bug than the one being fixed. So the same timeline runs again with a receiver that
 * has gone *silent* rather than merely full, and there the association MUST abort on schedule.
 */
class ZeroWindowProbeTest {
    private val stream = StreamId(0)

    private fun config() =
        SctpConfig(
            receiveWindowBytes = WINDOW_BYTES.toUInt(),
            receiveOverrun = ReceiveOverrunWindows(2),
            // The ceiling comes down with the window: SctpConfig refuses a pair where a message this
            // endpoint permits could not fit in the buffer it is willing to hold.
            receiveMessageLimit = ReceiveMessageLimit.Bytes(WINDOW_BYTES.toLong()),
            bufferFactory = BufferFactory.managed(),
        )

    private fun established(): SctpSim {
        val sim = SctpSim(config = config())
        sim.associateA()
        sim.run()
        assertEquals(SctpAssociationState.Established, sim.a.state, "precondition: the handshake completed")
        return sim
    }

    private fun SctpSim.sendFromA(count: Int) {
        repeat(count) { i ->
            post(true, SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(MESSAGE_BYTES, seed = i)))
        }
    }

    /**
     * A receiver whose application has stopped reading closes its window, keeps SACKing, and must **not**
     * be aborted — however long it takes. Then it starts reading again and the rest of the data flows,
     * which is what separates flow control from a deadlock.
     */
    @Test
    fun a_stalled_receiver_is_probed_not_aborted() {
        val sim = established()
        sim.consumerB = InboxConsumer.Stalled
        sim.sendFromA(MESSAGES)

        // Ten minutes of virtual time: far past the ~10 backed-off RTOs at which the unconditional error
        // counter used to abort, and far past `rtoMax`. Bounded rather than run-to-quiescence because a
        // shut window never IS quiescent — the persist timer keeps re-arming, which is the point.
        sim.runUntil(sim.now + 10.minutes)

        assertEquals(
            emptyList<SctpFailureReason>(),
            sim.abortsA,
            "a stalled receiver must not abort the sender (RFC 4960 §6.1 rule A)",
        )
        assertEquals(emptyList<SctpFailureReason>(), sim.abortsB, "…nor the receiver")
        assertEquals(SctpAssociationState.Established, sim.a.state, "the association is still up")

        // Anti-vacuity, and the half that proves flow control ACTED rather than that nothing happened:
        // the receiver stopped the sender well short of everything it queued.
        assertTrue(
            sim.inboxB.size < MESSAGES,
            "the closed window must have stopped the sender; all $MESSAGES arrived, so nothing was flow-controlled",
        )
        assertTrue(sim.inboxB.isNotEmpty(), "…but the window was open to begin with, so some arrived")
        assertTrue(sim.b.outstandingReceiveBytes > 0, "the receiver is holding what its application has not read")

        // The application catches up. Everything else arrives, so the closed window was a pause and not a
        // deadlock — the assertion a liveness test alone cannot make.
        val stalledAt = sim.inboxB.size
        sim.resumeConsumer(toA = false)
        sim.runUntil(sim.now + 10.minutes)
        assertEquals(MESSAGES, sim.inboxB.size, "every message arrives once the application reads again")
        assertTrue(stalledAt < MESSAGES, "precondition: it really had stalled before resuming")
        assertEquals(emptyList<SctpFailureReason>(), sim.abortsA, "and nothing aborted along the way")
        assertEquals(0L, sim.b.outstandingReceiveBytes, "every receipt came back")
    }

    /**
     * **The discriminating half.** The same timeline against a receiver that has gone silent — no SACKs at
     * all — must still abort, on the RFC 4960 §8.1 budget.
     *
     * RFC 8540 §3.20 keys the excuse on the sender *continuing to receive SACKs* while probing, and this is
     * what that clause buys: the excuse is granted once per intervening SACK and consumed by the expiry it
     * excuses, so a peer that dies with its window shut gets exactly one free expiry and is then charged
     * like any other dead peer. An excuse that stood rather than being consumed would trade this bug for a
     * session that never gives up on a corpse.
     */
    @Test
    fun a_silent_receiver_still_aborts() {
        val sim = established()
        sim.consumerB = InboxConsumer.Stalled
        // Everything bound for A is dropped from here on: the receiver is not merely full, it is gone.
        sim.dropFilter = { toA -> toA }
        sim.sendFromA(MESSAGES)

        sim.runUntil(sim.now + 20.minutes)

        assertEquals(
            listOf<SctpFailureReason>(SctpFailureReason.RetransmissionLimitReached),
            sim.abortsA,
            "a silent peer must still exhaust the RFC 4960 §8.1 budget — the probe excuse is consumed, not standing",
        )
        assertEquals(SctpAssociationState.Closed, sim.a.state)
    }

    /**
     * The window need not be exactly zero to block a sender, and reading rule A as though it must is how
     * the send path went **silent with data queued and no timer armed anywhere**.
     *
     * A peer advertising less than one fragment's worth blocks the head of the queue just as completely as
     * a peer advertising nothing, and with nothing outstanding there is no T3 to fire. Before this, that
     * state was permanent. It was unreachable while every endpoint advertised its full configured window;
     * a receiver near its ceiling advertises exactly this.
     */
    @Test
    fun a_small_nonzero_window_is_probed_rather_than_stalling_forever() {
        val sim = established()
        sim.consumerB = InboxConsumer.Stalled
        // Fill B's window to within a sliver: with 1000-byte messages and a 4000-byte window, four
        // messages leave it at exactly 0, so three leave it at 1000 — non-zero, and still too small for
        // the two-fragment message that follows.
        sim.sendFromA(3)
        sim.runUntil(sim.now + 1.minutes)
        assertTrue(sim.b.outstandingReceiveBytes > 0, "precondition: the receiver is holding data")

        val queuedBefore = sim.inboxB.size
        // A message larger than what is left of the window, so the head of the queue cannot be admitted.
        sim.post(
            true,
            SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(WINDOW_BYTES, seed = 99)),
        )
        sim.runUntil(sim.now + 5.minutes)
        assertEquals(emptyList<SctpFailureReason>(), sim.abortsA, "a window too small for the head of the queue is probed, not fatal")

        // And it is a pause: the application reads, the window reopens, the blocked message lands.
        sim.resumeConsumer(toA = false)
        sim.runUntil(sim.now + 5.minutes)
        assertTrue(sim.inboxB.size > queuedBefore, "the message blocked by the small window arrives once it reopens")
        assertEquals(emptyList<SctpFailureReason>(), sim.abortsA)
    }

    /**
     * A timer that nothing cancels is a session that never goes quiet. The persist timer joins
     * [AssociationDeadlines], so `cancelAll` covers it by construction — this asserts the construction
     * rather than the intent.
     */
    @Test
    fun the_persist_timer_does_not_outlive_the_association() {
        val sim = established()
        sim.consumerB = InboxConsumer.Stalled
        sim.sendFromA(MESSAGES)
        sim.runUntil(sim.now + 1.minutes)
        assertTrue(sim.a.nextDeadline(sim.now) != null, "precondition: something is armed while the window is shut")

        sim.a.close()
        assertEquals(null, sim.a.nextDeadline(sim.now), "close() leaves no timer armed, persist included")
    }
}

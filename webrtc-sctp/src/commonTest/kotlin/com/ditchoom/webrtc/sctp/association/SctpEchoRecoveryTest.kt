@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * W7 regression fixture (directive #5) for the impaired-lane echo flake fixed in 4abd83b — the SCTP RTO
 * defaults that overran the harness's echo teardown budget.
 *
 * The race, expressed in virtual time: the **answerer** (endpoint B) echoes the ping, so the pong is B's
 * *first* DATA chunk — and B has therefore taken no RTT sample yet (RTT is measured only from a SACK of a
 * DATA chunk: `RttEstimator.observe` is fed exclusively by `RetransmissionQueue.onSack`, and B has SACKed
 * A's ping but never sent DATA of its own). B's T3-rtx timer thus fires at **RTO.Initial**, not an
 * RTT-derived value. On a ~40 ms path a single lost pong then waits the *whole* RTO.Initial to recover:
 * 3 s with the RFC 4960 default, which raced (and lost to) the harness's echo/linger windows.
 *
 * The transport is correct at either RTO — heavy-loss delivery and ordering are covered in
 * [SctpAssociationTest]. What this pins is the **recovery latency** the low-RTT WebRTC path needs, so a
 * revert of the `rtoInitial = 500ms` tuning fails here — loudly, in milliseconds — instead of re-flaking
 * the L2 container matrix.
 */
class SctpEchoRecoveryTest {
    private val stream0 = StreamId(0)
    private val oneWay = 20.milliseconds // ~40 ms round trip — a LAN / WebRTC path

    // The harness echo budget is seconds; 1 s cleanly separates a 500 ms recovery (pass) from a 3 s one (miss).
    private val echoBudget = 1.seconds
    private val ping = SctpSendOptions(stream0, PayloadProtocolId.WebRtcString)
    private val pong = SctpSendOptions(stream0, PayloadProtocolId.WebRtcString)

    /**
     * Establish, deliver a ping A→B to quiescence (so no stray SACK is in flight toward A), then have B
     * send the echo pong with its **first** transmit dropped. Returns the sim and the instant the pong was
     * originally sent — the origin the recovery budget is measured from.
     */
    private fun echoWithFirstPongDropped(config: SctpConfig): Pair<SctpSim, Instant> {
        val sim = SctpSim(config = config, impairment = Impairment(delay = oneWay))
        sim.associateA()
        sim.run()
        assertEquals(SctpAssociationState.Established, sim.a.state, "opener established")
        assertEquals(SctpAssociationState.Established, sim.b.state, "answerer established")

        sim.post(toA = true, SctpEvent.SendMessage(ping, payload(4, seed = 1)))
        sim.run()
        assertEquals(1, sim.inboxB.size, "B received the ping")
        assertEquals(0, sim.inboxA.size, "A has received no user message yet")

        // Drop exactly B's first datagram toward A — the echo pong's initial DATA — then leave the path clean.
        var dropped = false
        sim.dropFilter = { toA ->
            val drop = toA && !dropped
            if (drop) dropped = true
            drop
        }
        val sentAt = sim.now
        sim.post(toA = false, SctpEvent.SendMessage(pong, payload(4, seed = 2)))
        return sim to sentAt
    }

    @Test
    fun echo_pong_lost_recovers_within_budget_with_webrtc_rto() {
        val (sim, sentAt) = echoWithFirstPongDropped(SctpConfig(rtoInitial = 500.milliseconds, rtoMin = 100.milliseconds))

        // The first transmit was dropped and the 500 ms RTO has not yet fired: nothing arrives early.
        sim.runUntil(sentAt + 100.milliseconds)
        assertEquals(0, sim.inboxA.size, "the pong's first transmit was dropped — no premature delivery")

        // The RTO.Initial retransmit (500 ms) recovers the pong well inside the echo budget.
        sim.runUntil(sentAt + echoBudget)
        assertEquals(1, sim.inboxA.size, "the WebRTC-tuned RTO retransmits and delivers the lost pong within the budget")
        assertEquals(
            payload(4, seed = 2).bytes(),
            sim.inboxA
                .single()
                .payload
                .bytes(),
            "the recovered pong is intact",
        )
    }

    @Test
    fun rfc_default_rto_misses_the_low_rtt_echo_budget() {
        // Same single loss, RFC 4960 defaults (3 s initial): this is the *witness* for why the default was wrong.
        val (sim, sentAt) = echoWithFirstPongDropped(SctpConfig()) // rtoInitial = 3 s

        sim.runUntil(sentAt + echoBudget)
        assertEquals(0, sim.inboxA.size, "with the RFC default RTO the lost pong has NOT retransmitted within the budget")

        // But the transport is still correct: given unbounded time the 3 s retransmit lands. Tuning, not a bug.
        sim.run()
        assertEquals(1, sim.inboxA.size, "the pong is eventually delivered — a tuning issue, not a correctness bug")
    }
}

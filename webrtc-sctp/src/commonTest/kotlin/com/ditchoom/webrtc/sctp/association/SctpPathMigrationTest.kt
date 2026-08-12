@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * RFC 8261 §6.1's congestion reset, and specifically the half of it that decides whether a session
 * survives: *"If the SCTP layer is notified about a path change by its lower layers, SCTP SHOULD retest
 * the path MTU and **reset the congestion state to the initial state**."*
 *
 * The RFC 4960 §8.1 consecutive-error budget is the sharpest of the quantities that reset covers, because
 * it is the one whose staleness is fatal rather than merely slow. A migration is most often performed
 * *because* the old path stopped working — an RFC 8445 §9 ICE restart after a Wi-Fi→cellular walk is the
 * canonical case — so the association arrives on the new path having already charged most of its ten
 * expiries to the path it just left. Without the reset the next expiry aborts, and every data channel dies
 * on a path that was never given a chance to carry anything.
 *
 * ## Why these four run one timeline and differ only in the event
 *
 * "The association did not abort" is green on an association that simply never fails, which is why the
 * **negative control** is not optional here: the same black hole, the same instants, and no path event at
 * all must abort with [SctpFailureReason.RetransmissionLimitReached]. The two restatement arms then close
 * the other side — a first assessment and a repeat of the current identity must abort at **exactly** the
 * control's instant, so an implementation that reset on every path event (or on any event at all) is red
 * rather than merely more forgiving than intended.
 *
 * Every instant here is virtual and derived from the control run rather than written down, so nothing is
 * a wall-clock budget (directive #4) and the arithmetic of the RFC 4960 §6.3.3 backoff ladder is not
 * duplicated in the assertions.
 */
class SctpPathMigrationTest {
    private val stream = StreamId(0)

    // IPv4, because this fixture is about the congestion reset and not about the ceiling: an IPv4 profile
    // leaves the fragmentation ceiling at the configured 1200 (see SctpFragmentCeilingTest), so the
    // timeline is identical to the profile-less control's in everything except the reset under test.
    private fun profile(ordinal: UInt) =
        SctpPathProfile.Assessed(
            identity = PathIdentity(ordinal),
            family = PathAddressFamily.Ipv4,
            overhead = PathOverheadBytes(65), // 20 IPv4 + 8 UDP + 37 DTLS 1.2
        )

    /**
     * An established association with data outstanding and every datagram toward the peer discarded — so
     * the only thing that can ever happen next is a T3-rtx ladder ending in the §8.1 abort.
     */
    private fun blackHoled(assessFirstPath: Boolean): SctpSim {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        if (assessFirstPath) sim.post(toA = true, SctpEvent.PathChanged(profile(FIRST_PATH)))
        sim.dropFilter = { toA -> !toA }
        sim.post(
            toA = true,
            SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(64)),
        )
        return sim
    }

    /** The control's abort instant — every other arm is measured against it. */
    private fun controlAbort(): Instant {
        val control = blackHoled(assessFirstPath = true)
        control.run()
        assertEquals(
            listOf<SctpFailureReason>(SctpFailureReason.RetransmissionLimitReached),
            control.abortsA,
            "the negative control must actually abort, or every 'did not abort' below is vacuous",
        )
        return control.now
    }

    @Test
    fun a_black_holed_path_spends_its_error_budget_and_aborts() {
        val abortAt = controlAbort()
        assertTrue(abortAt > Instant.fromEpochSeconds(0), "the abort is reached by the backoff ladder, not immediately")
    }

    @Test
    fun a_migration_clears_the_error_budget_the_departing_path_had_spent() {
        val abortAt = controlAbort()
        val sim = blackHoled(assessFirstPath = true)
        sim.runUntil(midpoint(abortAt))
        val at = sim.now

        val backedOff = sim.a.nextDeadline(at)
        sim.post(toA = true, SctpEvent.PathChanged(profile(SECOND_PATH)))

        // The T3 that was armed described the departing path: it was computed from an RTO the RFC 4960
        // §6.3.3 backoff had doubled repeatedly. Re-arming it from the fresh RTO is the difference between
        // the new path's first retransmission happening on its own schedule and up to rtoMax of silence.
        assertNotNull(backedOff, "a black-holed sender has an armed T3")
        assertTrue(
            backedOff > at + SctpConfig().rtoInitial,
            "the pre-migration deadline must be strictly later than a fresh RTO, or the re-arm proves nothing",
        )
        assertEquals(at + SctpConfig().rtoInitial, sim.a.nextDeadline(at), "T3 is disarmed and re-armed from the new path's RTO")

        sim.runUntil(abortAt)
        assertTrue(
            sim.abortsA.isEmpty(),
            "the budget the departing path spent must not be charged to the new one",
        )

        // Liveness (ARCHITECTURE §5.3 #5): the reset postpones the abort, it does not remove it. A black
        // hole that never gives up would be a worse bug than the one being fixed.
        sim.run()
        assertEquals(listOf<SctpFailureReason>(SctpFailureReason.RetransmissionLimitReached), sim.abortsA)
        assertTrue(sim.now > abortAt, "and it aborts strictly later than the control did")
    }

    @Test
    fun restating_the_current_path_discards_nothing() {
        val abortAt = controlAbort()
        val sim = blackHoled(assessFirstPath = true)
        sim.runUntil(midpoint(abortAt))
        sim.post(toA = true, SctpEvent.PathChanged(profile(FIRST_PATH)))
        sim.run()

        assertEquals(listOf<SctpFailureReason>(SctpFailureReason.RetransmissionLimitReached), sim.abortsA)
        assertEquals(abortAt, sim.now, "a repeat of the current identity is not a migration")
    }

    @Test
    fun the_first_assessment_discards_nothing() {
        val abortAt = controlAbort()
        val sim = blackHoled(assessFirstPath = false)
        sim.runUntil(midpoint(abortAt))
        sim.post(toA = true, SctpEvent.PathChanged(profile(FIRST_PATH)))
        sim.run()

        assertEquals(listOf<SctpFailureReason>(SctpFailureReason.RetransmissionLimitReached), sim.abortsA)
        assertEquals(abortAt, sim.now, "learning what the path is is not the path changing")
    }

    /** The profile is adopted whether or not it was a migration — a restatement may carry a new overhead. */
    @Test
    fun a_restatement_still_adopts_the_profile_it_carries() {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        sim.post(toA = true, SctpEvent.PathChanged(profile(FIRST_PATH)))
        val relayed =
            SctpPathProfile.Assessed(
                identity = PathIdentity(FIRST_PATH),
                family = PathAddressFamily.Ipv4,
                overhead = PathOverheadBytes(101), // the same path, re-measured through a TURN relay
            )
        sim.post(toA = true, SctpEvent.PathChanged(relayed))
        assertEquals(relayed, sim.a.pathProfile)
    }

    private fun midpoint(abortAt: Instant): Instant = Instant.fromEpochSeconds(0) + (abortAt - Instant.fromEpochSeconds(0)) / 2

    private companion object {
        private const val FIRST_PATH: UInt = 1u
        private const val SECOND_PATH: UInt = 2u
    }
}

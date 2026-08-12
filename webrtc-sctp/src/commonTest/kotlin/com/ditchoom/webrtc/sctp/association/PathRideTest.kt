@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime

/**
 * [PathRide] exists so that the four things measured about a path are reset **together**. These fixtures
 * assert the togetherness, not the individual arithmetic — RFC 4960 §6.3.1's recurrence and §7.2's window
 * rules are pinned by [RetransmissionQueueRttTest] and the congestion fixtures respectively.
 *
 * The failure this guards is a partial reset, which is invisible by construction: an association carrying
 * one stale quantity behaves plausibly and only misbehaves under the conditions that quantity governs. A
 * cwnd left over from a path that is gone shows up as a throughput anomaly on the new one; a stale error
 * budget shows up as an abort that arrives too early, and only after the path was already in trouble.
 */
class PathRideTest {
    private val config = SctpConfig()

    @Test
    fun a_new_path_discards_every_measurement_at_once() {
        val first = PathRide.first(config).established(peerRwnd = 512_000u)
        first.rtt.observe(400.milliseconds)
        first.congestion.onDataAcked(bytesAcked = 4_000, fullyUtilized = true)
        first.retransmitFailed()

        val grownCwnd = first.congestion.cwnd
        val backedOffRto = first.rtt.rto

        val moved = first.onNewPath()

        assertNotEquals(first.epoch, moved.epoch, "the epoch must advance, or stale samples stay eligible")
        assertEquals(0, moved.retransmitErrors, "the error budget is charged to the path, not the association")
        assertNotEquals(grownCwnd, moved.congestion.cwnd, "cwnd measured a link that is gone")
        assertEquals(config.rtoInitial, moved.rtt.rto, "RTO must return to RTO.Initial with no samples")
        assertTrue(backedOffRto != config.rtoInitial, "the fixture must actually have moved RTO first")
    }

    /**
     * The peer's advertised window is a property of the peer's receiver, not of the link between us, so it
     * survives a migration — the association did not restart and the peer never re-advertised. Getting
     * this wrong reseeds ssthresh from a window nobody advertised, which silently changes when slow start
     * ends on the new path.
     */
    @Test
    fun the_peers_advertised_window_survives_a_path_change() {
        val established = PathRide.first(config).established(peerRwnd = 512_000u)
        val moved = established.onNewPath()

        assertEquals(
            established.congestion.ssthresh,
            moved.congestion.ssthresh,
            "ssthresh reseeds from the peer's window, which a path change does not invalidate",
        )
    }

    /**
     * Establishment is not a migration: the handshake happened on the path being ridden, so a T1 RTT
     * sample is a genuine measurement of it and is exactly what RFC 4960 §6.3.1 wants seeding the first
     * RTO. Discarding it here would throw away the only sample available at the moment the association
     * starts sending.
     */
    @Test
    fun establishment_keeps_the_epoch_and_the_handshake_sample() {
        val initial = PathRide.first(config)
        initial.rtt.observe(80.milliseconds)
        val handshakeRto = initial.rtt.rto

        val established = initial.established(peerRwnd = 128_000u)

        assertEquals(initial.epoch, established.epoch, "establishing is not moving; the path is unchanged")
        assertEquals(handshakeRto, established.rtt.rto, "the handshake's RTT sample must seed the first RTO")
    }

    /**
     * The budget is `Association.Max.Retrans` **exceeded**, not reached (RFC 4960 §8.1) — the last
     * permitted retransmission must still be allowed. An off-by-one here aborts an association one
     * retransmission early, which on a lossy-but-usable link is the difference between recovering and
     * dropping every channel.
     */
    @Test
    fun the_error_budget_is_spent_only_once_it_is_exceeded() {
        val ride = PathRide.first(config)
        repeat(config.maxAssociationRetransmits) {
            assertFalse(ride.retransmitFailed(), "failure ${it + 1} is within the budget and must not abort")
        }
        assertTrue(ride.retransmitFailed(), "the failure past the budget must abort")
    }

    @Test
    fun forward_progress_restores_the_whole_budget() {
        val ride = PathRide.first(config)
        repeat(config.maxAssociationRetransmits) { ride.retransmitFailed() }

        ride.onProgress()

        assertEquals(0, ride.retransmitErrors, "a peer that acknowledged new data has cleared the failures")
        repeat(config.maxAssociationRetransmits) {
            assertFalse(ride.retransmitFailed(), "the budget must be whole again, not merely decremented")
        }
    }

    /**
     * A restart advances the epoch for a different reason than a migration does — the path may be
     * identical, but the peer's association is a new one, and a chunk from the old association must not be
     * able to contribute a sample to it. Same operation, and the fixture asserts they agree so the two
     * names cannot drift into two behaviours.
     */
    @Test
    fun a_restart_discards_measurements_exactly_as_a_migration_does() {
        val base = PathRide.first(config).established(peerRwnd = 256_000u)
        base.rtt.observe(120.milliseconds)
        base.retransmitFailed()

        val restarted = base.onRestart()

        assertNotEquals(base.epoch, restarted.epoch, "a restart must make previous chunks unrecognisable")
        assertEquals(0, restarted.retransmitErrors, "the previous association's failures do not carry over")
        assertEquals(config.rtoInitial, restarted.rtt.rto, "the previous association's RTT is not this one's")
    }
}

@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import kotlin.jvm.JvmInline
import kotlin.time.ExperimentalTime

/**
 * Which path a measurement was taken on.
 *
 * Minted internally and only ever compared for equality — never ordered, never persisted, never sent.
 * It exists because every quantity in [PathRide] is a property of *a path* rather than of the
 * association, while the chunks those quantities are derived from outlive the path they were sent on: a
 * DATA chunk transmitted before a migration can be acknowledged after one, and the round trip that ack
 * appears to measure spans two different networks. The epoch is what lets the sample be recognised as
 * belonging to a path that is no longer underneath us.
 *
 * A counter rather than an identity handed down from the session layer, because the two answer different
 * questions: `PathIdentity` (Track G) says *which* 5-tuple, and is the session layer's to mint; this says
 * *how many times the path has changed under this association*, which only the association can know and
 * only it needs.
 */
@JvmInline
internal value class PathEpoch(
    val value: Int,
) {
    fun next(): PathEpoch = PathEpoch(value + 1)
}

/**
 * Everything the association measures **about the path it is currently riding**, as one value.
 *
 * Held separately, these four are a set of fields that must be reset together and had no name saying so.
 * RFC 4960 §7.2.1 and RFC 8261 §6.1 are explicit that a new path invalidates all of them at once — cwnd
 * and ssthresh were measured against a link that is gone, SRTT/RTTVAR describe a round trip nobody will
 * take again, and the consecutive-error budget is counting failures charged to a path that is no longer
 * the one being used. Reset three of the four and the association keeps a stale opinion with no field
 * marked stale; that is not a hypothetical, it is the ordinary outcome of adding a fifth quantity later
 * and updating the three reset sites the author happened to find.
 *
 * So the reset is a **constructor**, not a sequence of assignments: [onNewPath] returns a whole new ride,
 * and a quantity added to this class is reset correctly by having been added to it. This is the same
 * argument [AssociationDeadlines.cancelAll] makes about timers, applied to measurements.
 *
 * **Congestion is non-nullable here**, which closes a gap that a separate `Congestion{Unestablished |
 * Established}` would only have restated: [Tcb.NoAssociation] already says "there is no association, so
 * no window", and a second type for the same fact means two places to keep in agreement. Nothing
 * transmits before Established, so the pre-handshake controller is never consulted; it exists so the
 * field can be a `val`.
 *
 * **T3-rtx deliberately stays in [AssociationDeadlines]** even though a path change must disarm it. The
 * plan's field sketch listed it here, but it is one of the five timers that class was built to hold and
 * cancel totally, and splitting one timer out to sit beside the measurements would give timers two homes
 * to serve one migration. The migration therefore does both — a fresh ride and a disarmed T3 — and the
 * timer stays where every other timer is.
 */
internal class PathRide private constructor(
    private val config: SctpConfig,
    private val peerRwnd: UInt,
    /** Which path these measurements belong to; see [PathEpoch]. */
    val epoch: PathEpoch,
    /** SRTT/RTTVAR and the derived RTO for the current path (RFC 4960 §6.3.1). */
    val rtt: RttEstimator,
    /** cwnd/ssthresh for the current path (RFC 4960 §7.2). Never absent — see the class KDoc. */
    val congestion: CongestionControl,
) {
    /**
     * Consecutive T3-rtx expiries with no forward progress (RFC 4960 §8.1 `Association.Max.Retrans`).
     * Path-scoped: a failure charged to a path that has since been replaced must not count against the
     * new one, or a migration performed *because* the old path was failing would inherit a budget that is
     * already spent and abort the association it was meant to rescue.
     */
    var retransmitErrors: Int = 0
        private set

    /**
     * Charge one retransmission failure to this path. Returns true once the RFC 4960 §8.1 budget is
     * spent, which is the caller's signal to abort.
     *
     * The increment and the comparison are one call because they were two lines at each of the sites that
     * do this, and a site that increments without comparing is an association that never gives up.
     */
    fun retransmitFailed(): Boolean {
        retransmitErrors += 1
        return retransmitErrors > config.maxAssociationRetransmits
    }

    /** Forward progress: the peer acknowledged something new, so the error budget is whole again. */
    fun onProgress() {
        retransmitErrors = 0
    }

    /**
     * The handshake completed and the peer's receive window is known — re-seed congestion against it
     * (RFC 4960 §7.2.1 initialises ssthresh to the peer's advertised rwnd).
     *
     * The epoch and the RTT estimator survive: this is the same path, and any sample taken during the
     * handshake (INIT → INIT-ACK) is a genuine measurement of it, which is exactly the sample RFC 4960
     * §6.3.1 wants seeding the first RTO.
     */
    fun established(peerRwnd: UInt): PathRide = PathRide(config, peerRwnd, epoch, rtt, CongestionControl(config, peerRwnd))

    /**
     * The association moved to a different path. Everything measured is discarded and the epoch advances,
     * so an ack that arrives for a chunk sent on the old path is recognisable and cannot contribute an
     * RTT sample spanning both.
     *
     * The peer's advertised window carries over: it is a property of the *peer's* receiver, not of the
     * path between us, and the association did not restart.
     */
    fun onNewPath(): PathRide = discardMeasurements()

    /**
     * The peer restarted the association (RFC 4960 §5.2.4). The path may be identical, but everything
     * measured describes a peer state that no longer exists, and the epoch must still advance so that no
     * chunk from the previous association can be mistaken for one of this association's.
     *
     * A separate name from [onNewPath] for the same operation, because the two call sites are answering
     * different questions and a reader at either one should not have to know that the other exists.
     */
    fun onRestart(): PathRide = discardMeasurements()

    private fun discardMeasurements(): PathRide =
        PathRide(config, peerRwnd, epoch.next(), RttEstimator(config), CongestionControl(config, peerRwnd))

    companion object {
        /**
         * The ride an association starts on, before the handshake has said anything about the peer. The
         * congestion controller is seeded with a zero window — it is never consulted before Established
         * (nothing transmits until then), and seeding it here is what keeps the field non-nullable.
         */
        fun first(config: SctpConfig): PathRide = PathRide(config, 0u, PathEpoch(0), RttEstimator(config), CongestionControl(config, 0u))
    }
}

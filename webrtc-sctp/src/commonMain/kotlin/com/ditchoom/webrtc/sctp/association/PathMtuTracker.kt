@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.PadBytes
import kotlin.jvm.JvmInline
import kotlin.time.Duration
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

// The SCTP bytes a probe packet spends on framing: the RFC 4960 §3.1 common header (12), the HEARTBEAT
// chunk carrying a 4-byte nonce as its Heartbeat Info parameter (4 chunk header + 4 parameter header + 4
// value = 12), and the PAD chunk's own header (4). Everything above this is padding.
private const val PROBE_FRAMING_BYTES = 12 + 12 + 4

private const val PMTU_ALIGNMENT = 4

/**
 * A path-MTU probe's identity: an opaque counter echoed back inside the HEARTBEAT-ACK's Heartbeat Info
 * parameter (RFC 4960 §3.3.5/§3.3.6, which require the ACK to repeat the parameter verbatim).
 *
 * It exists so a late answer cannot confirm the wrong size. Without it, a probe of 1500 that times out
 * and is followed by a probe of 1390 would be confirmed by the *first* one's ACK arriving late — the
 * search would raise the ceiling to a size the path has just demonstrated it will not carry, which is the
 * one outcome a PMTU search must never produce.
 */
@JvmInline
internal value class ProbeNonce(
    val value: UInt,
)

/** One probe on the wire, or waiting to go out. */
private data class Probe(
    val nonce: ProbeNonce,
    /** The full IP-datagram size this probe is measuring — headers, DTLS, UDP and IP included. */
    val size: PmtuBytes,
    /** How many copies of this size have gone unanswered (RFC 8899 §5.1.2 MAX_PROBES). */
    val attempts: Int,
)

/**
 * What the association must do about a change inside the tracker. A list of these rather than a mutated
 * pile of nullable fields, mirroring the sans-io `handle(event) -> List<Output>` contract the whole core
 * is built on (ARCHITECTURE §5.1): the tracker owns the search and knows nothing about packets, timers or
 * queues.
 */
internal sealed interface PathMtuEffect {
    /** Put a probe of this shape on the wire: a HEARTBEAT carrying [nonce], padded by [padding] bytes. */
    data class Probe(
        val nonce: ProbeNonce,
        val padding: PadBytes,
    ) : PathMtuEffect

    /** The measured ceiling moved. The association re-fragments from here and reports it. */
    data class CeilingChanged(
        val ceiling: FragmentCeilingBytes,
        val cause: PathMtuChangeCause,
    ) : PathMtuEffect
}

/**
 * Whether anything about the path's MTU has actually been **measured**.
 *
 * The distinction is what decides whether `SctpConfig.maxPayloadBytes` still caps the fragment ceiling.
 * An unprobed family-derived ceiling is an *assumption*, and an assumption may only lower the size a
 * caller configured — raising it would put fragments on the wire that nobody asked for on the strength of
 * a guess about the link. A probe-confirmed ceiling is a *measurement* of the path this association is on,
 * which is exactly what the caller asked for by choosing [PathMtuPolicy.Discover], so it supersedes the
 * configured value in both directions.
 *
 * Sealed rather than a nullable ceiling, because "not measured" is a state with its own rule rather than
 * a missing number.
 */
internal sealed interface MeasuredCeiling {
    /** Nothing has been probed: the ceiling comes from configuration and the address family. */
    data object NotMeasured : MeasuredCeiling

    /** A probe settled this ceiling — it beats configuration. */
    data class Confirmed(
        val ceiling: FragmentCeilingBytes,
    ) : MeasuredCeiling
}

/**
 * RFC 8899 Packetization Layer Path MTU Discovery for one SCTP path.
 *
 * ## The probe, and why it works against every peer
 *
 * A probe is one packet containing a HEARTBEAT (RFC 4960 §3.3.5) followed by an RFC 4820 PAD chunk sized
 * to bring the whole datagram to the candidate size. The confirmation is the HEARTBEAT-ACK, which RFC
 * 4960 §3.3.6 requires echo the Heartbeat Info parameter verbatim — so the nonce comes back and the
 * answer is attributable to the size that produced it.
 *
 * The peer needs to implement nothing. Chunk type 132's high bits are `10`, so RFC 4960 §3.2 tells a
 * receiver that has never heard of RFC 4820 to **skip the chunk and keep processing the packet** — and
 * the HEARTBEAT beside it is answered as usual. A probe is therefore confirmed by dcSCTP, usrsctp, Pion
 * and werift alike, without negotiation and without a capability to gate on. That matters here more than
 * usual: a capability-gated probe that silently degenerates on peers that lack it is the failure mode
 * this repository has recorded repeatedly.
 *
 * ## Losing a probe is not a congestion signal
 *
 * RFC 8899 §3 is explicit that a probe's loss must not be fed to congestion control, and this shape gets
 * that for free rather than by remembering: a HEARTBEAT is not DATA, so it never enters the
 * retransmission queue, never counts toward the flight size, and its loss reaches neither cwnd nor the
 * RFC 4960 §8.1 error budget. The only thing an unanswered probe costs is the probe.
 *
 * ## What it is not
 *
 * It does not read ICMP. RFC 8899 exists precisely because a UDP-encapsulated flow behind a NAT cannot
 * rely on Packet Too Big reaching it, so nothing here waits for one.
 */
internal class PathMtuTracker(
    private val policy: PathMtuPolicy,
) {
    private sealed interface Search {
        /** No path assessed yet, or [PathMtuPolicy.Fixed]: nothing is ever probed. */
        data object Idle : Search

        /**
         * RFC 8899 §5.2 BASE — proving the size already being emitted is genuinely carried. Always the
         * first phase, because an association that is black-holing its full-size fragments right now
         * learns that here and nowhere else.
         */
        data class Base(
            val probe: Probe,
        ) : Search

        /**
         * RFC 8899 §5.2 SEARCHING — [low] is confirmed, [high] is refuted or out of scope, and the probe
         * in flight is measuring somewhere between them.
         */
        data class Raising(
            val low: PmtuBytes,
            val high: PmtuBytes,
            val probe: Probe,
        ) : Search

        /** RFC 8899 §5.2 SEARCH_COMPLETE — resting until the raise timer re-opens the search. */
        data object Complete : Search
    }

    private var profile: SctpPathProfile = SctpPathProfile.Unassessed
    private var search: Search = Search.Idle
    private var nextNonce: UInt = 0u

    /** What has been measured, if anything — see [MeasuredCeiling]. */
    var measured: MeasuredCeiling = MeasuredCeiling.NotMeasured
        private set

    /**
     * When the tracker next needs the clock: a PROBE_TIMER while a probe is in flight, a PMTU_RAISE_TIMER
     * while the search rests, and [Deadline.Unarmed] whenever nothing is being measured. Folded into
     * [AssociationDeadlines] by the association so `cancelAll()` stays total.
     */
    var deadline: Deadline = Deadline.Unarmed
        private set

    /**
     * The lower layer named the path, or moved it (RFC 8261 §6.1's *"retest the path MTU"*).
     *
     * Every measurement is discarded unconditionally — even when the family and the overhead are
     * unchanged, because the identity is what says the packets are taking a different route, and a size
     * confirmed on the old route is a statement about a link nobody is using any more.
     */
    fun onPathAssessed(
        assessed: SctpPathProfile.Assessed,
        now: Instant,
        probeTimeout: Duration,
    ): List<PathMtuEffect> {
        profile = assessed
        measured = MeasuredCeiling.NotMeasured
        val effects = ArrayList<PathMtuEffect>(2)
        effects += PathMtuEffect.CeilingChanged(assessed.unprobedFragmentCeiling, PathMtuChangeCause.PathAssessed(assessed.family))
        when (policy) {
            PathMtuPolicy.Fixed -> {
                search = Search.Idle
                deadline = Deadline.Unarmed
            }
            is PathMtuPolicy.Discover -> {
                val probe = mint(assessed.family.unprobedPathMtu)
                search = Search.Base(probe)
                effects += emit(probe, assessed, now, probeTimeout)
            }
        }
        return effects
    }

    /** A HEARTBEAT-ACK came back. Confirms a size only when its nonce is the one in flight. */
    fun onProbeAcknowledged(
        nonce: ProbeNonce,
        now: Instant,
        probeTimeout: Duration,
    ): List<PathMtuEffect> {
        val assessed = profile as? SctpPathProfile.Assessed ?: return emptyList()
        val discover = policy as? PathMtuPolicy.Discover ?: return emptyList()
        val confirmed =
            when (val current = search) {
                Search.Idle, Search.Complete -> return emptyList()
                is Search.Base -> if (current.probe.nonce == nonce) current.probe.size else return emptyList()
                is Search.Raising -> if (current.probe.nonce == nonce) current.probe.size else return emptyList()
            }
        val high =
            when (val current = search) {
                is Search.Raising -> current.high
                else -> discover.searchCeiling
            }
        return settle(confirmed, PathMtuChangeCause.ProbeConfirmed, assessed, discover, high, now, probeTimeout)
    }

    /** The probe or raise timer came due. */
    fun onTimer(
        now: Instant,
        probeTimeout: Duration,
    ): List<PathMtuEffect> {
        if (!deadline.dueAt(now)) return emptyList()
        val assessed = profile as? SctpPathProfile.Assessed ?: return emptyList()
        val discover = policy as? PathMtuPolicy.Discover ?: return emptyList()
        return when (val current = search) {
            Search.Idle -> emptyList()
            // RFC 8899 §5.1.1 PMTU_RAISE_TIMER: re-open the search from what is confirmed.
            Search.Complete -> reopen(assessed, discover, now, probeTimeout)
            is Search.Base -> onBaseUnanswered(current, assessed, discover, now, probeTimeout)
            is Search.Raising -> onRaiseUnanswered(current, assessed, discover, now, probeTimeout)
        }
    }

    // ── the two refusal paths ──

    private fun onBaseUnanswered(
        current: Search.Base,
        assessed: SctpPathProfile.Assessed,
        discover: PathMtuPolicy.Discover,
        now: Instant,
        probeTimeout: Duration,
    ): List<PathMtuEffect> {
        if (current.probe.attempts + 1 < discover.maxProbes.value) {
            val retry = current.probe.copy(attempts = current.probe.attempts + 1)
            search = Search.Base(retry)
            return listOf(emit(retry, assessed, now, probeTimeout))
        }
        // RFC 8899 §5.2 ERROR, with this stack's stated deviation: drop to the family minimum — which is
        // urgent, since datagrams at the refuted size are being lost as we speak — and then search back up
        // with the refuted size as the ceiling, rather than sitting at the minimum until a raise timer.
        val floor = assessed.family.minimumPathMtu
        val effects = ArrayList<PathMtuEffect>(2)
        effects += confirmCeiling(floor, PathMtuChangeCause.BaseRefuted, assessed)
        effects += beginRaise(floor, current.probe.size, assessed, discover, now, probeTimeout)
        return effects
    }

    private fun onRaiseUnanswered(
        current: Search.Raising,
        assessed: SctpPathProfile.Assessed,
        discover: PathMtuPolicy.Discover,
        now: Instant,
        probeTimeout: Duration,
    ): List<PathMtuEffect> {
        if (current.probe.attempts + 1 < discover.maxProbes.value) {
            val retry = current.probe.copy(attempts = current.probe.attempts + 1)
            search = Search.Raising(current.low, current.high, retry)
            return listOf(emit(retry, assessed, now, probeTimeout))
        }
        // The candidate is refuted: it becomes the new upper bound. `low` is untouched — it was confirmed.
        return beginRaise(current.low, current.probe.size, assessed, discover, now, probeTimeout)
    }

    // ── the search itself ──

    private fun settle(
        confirmed: PmtuBytes,
        cause: PathMtuChangeCause,
        assessed: SctpPathProfile.Assessed,
        discover: PathMtuPolicy.Discover,
        high: PmtuBytes,
        now: Instant,
        probeTimeout: Duration,
    ): List<PathMtuEffect> {
        val effects = ArrayList<PathMtuEffect>(2)
        effects += confirmCeiling(confirmed, cause, assessed)
        effects += beginRaise(confirmed, high, assessed, discover, now, probeTimeout)
        return effects
    }

    /**
     * Aim the next probe between [low] (confirmed) and [high] (refuted or out of scope), or stop.
     *
     * Returns the effects to append — a single [PathMtuEffect.Probe] when there is a size worth trying, or
     * nothing at all when the interval has closed to within the configured granularity.
     */
    private fun beginRaise(
        low: PmtuBytes,
        high: PmtuBytes,
        assessed: SctpPathProfile.Assessed,
        discover: PathMtuPolicy.Discover,
        now: Instant,
        probeTimeout: Duration,
    ): List<PathMtuEffect> {
        val ceiling = if (high <= discover.searchCeiling) high else discover.searchCeiling
        val candidateValue = align(low.value + (ceiling.value - low.value) / 2)
        if (ceiling.value - low.value <= discover.granularity.value || candidateValue <= low.value) {
            search = Search.Complete
            // RFC 8899 §5.1.1's PMTU_RAISE_TIMER re-opens a completed search in case the path grew — but
            // only where there is something above to find. A search that converged against the configured
            // search ceiling has already asked for everything it will ever ask for, so re-opening it would
            // wake the driver every raise interval to compute the same answer. Disarming there is also
            // what lets an association reach genuine quiescence, which the sans-io `nextDeadline` contract
            // (ARCHITECTURE §5.1) is built on: a timer that is always armed is a driver that never sleeps.
            deadline = if (ceiling >= discover.searchCeiling) Deadline.Unarmed else Deadline.At(now + discover.raiseInterval)
            return emptyList()
        }
        val probe = mint(PmtuBytes(candidateValue))
        search = Search.Raising(low, ceiling, probe)
        return listOf(emit(probe, assessed, now, probeTimeout))
    }

    /** PMTU_RAISE_TIMER fired: try again above what is confirmed, up to the search ceiling. */
    private fun reopen(
        assessed: SctpPathProfile.Assessed,
        discover: PathMtuPolicy.Discover,
        now: Instant,
        probeTimeout: Duration,
    ): List<PathMtuEffect> {
        val low =
            when (val current = measured) {
                MeasuredCeiling.NotMeasured -> assessed.family.minimumPathMtu
                is MeasuredCeiling.Confirmed -> pmtuOf(current.ceiling, assessed)
            }
        return beginRaise(low, discover.searchCeiling, assessed, discover, now, probeTimeout)
    }

    private fun confirmCeiling(
        pmtu: PmtuBytes,
        cause: PathMtuChangeCause,
        assessed: SctpPathProfile.Assessed,
    ): PathMtuEffect {
        val ceiling = FragmentCeilingBytes.of(pmtu, assessed.overhead)
        measured = MeasuredCeiling.Confirmed(ceiling)
        return PathMtuEffect.CeilingChanged(ceiling, cause)
    }

    private fun emit(
        probe: Probe,
        assessed: SctpPathProfile.Assessed,
        now: Instant,
        probeTimeout: Duration,
    ): PathMtuEffect.Probe {
        deadline = Deadline.At(now + probeTimeout)
        return PathMtuEffect.Probe(probe.nonce, paddingFor(probe.size, assessed))
    }

    private fun mint(size: PmtuBytes): Probe = Probe(ProbeNonce(nextNonce++), size, attempts = 0)

    /**
     * How much padding brings a probe packet to [size] on this path. Floored to the 4-byte boundary every
     * SCTP chunk sits on, so the datagram that actually goes out is at most [size] — never over it, which
     * would confirm a size the path was never asked about.
     */
    private fun paddingFor(
        size: PmtuBytes,
        assessed: SctpPathProfile.Assessed,
    ): PadBytes = PadBytes(align((size.value - assessed.overhead.value - PROBE_FRAMING_BYTES).coerceAtLeast(0)))

    /** The datagram size a fragment ceiling came from — the inverse of [FragmentCeilingBytes.of]. */
    private fun pmtuOf(
        ceiling: FragmentCeilingBytes,
        assessed: SctpPathProfile.Assessed,
    ): PmtuBytes = PmtuBytes(ceiling.value + assessed.overhead.value + SCTP_DATA_PACKET_BYTES)

    private fun align(value: Int): Int = value - value % PMTU_ALIGNMENT
}

// RFC 4960 §3.1 common header (12) + one DATA chunk's header (§3.3.1: 4 TLV + 12 fixed). Duplicated from
// SctpPathProfile.kt's file-private constant rather than shared through a companion, because a `const val`
// in a private companion is still emitted as a public static field.
private const val SCTP_DATA_PACKET_BYTES = 28

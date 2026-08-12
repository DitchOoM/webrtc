@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import kotlin.jvm.JvmInline
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.ExperimentalTime

// File-private, not a `const val` in a private companion — the latter is still emitted as a public
// static field.
private const val PROBE_BUDGET_MAX = 16
private const val PMTU_STEP_MIN = 4
private const val PMTU_STEP_MAX = 64
private const val PMTU_ALIGNMENT = 4

// RFC 8899 §5.1.1 RECOMMENDS a PMTU_RAISE_TIMER of 600 seconds.
private val PMTU_RAISE_INTERVAL = 10.minutes

// RFC 8899 §5.1.2 RECOMMENDS MAX_PROBES = 3.
private const val DEFAULT_MAX_PROBES = 3

// The ubiquitous Ethernet MTU: the largest datagram worth spending probes on, since a path above it is
// rare enough that the search cost outweighs the gain.
private const val DEFAULT_SEARCH_CEILING = 1500

// A 32-byte granularity converges a 1280→1500 search in three probes and leaves at most 32 bytes of the
// path unused — a rounding error against an 1100-byte payload, and cheaper than the probes that would
// recover it.
private const val DEFAULT_GRANULARITY = 32

/**
 * How many probes of one size may go unanswered before that size is treated as refuted (RFC 8899 §5.1.2
 * MAX_PROBES).
 *
 * Bounded at `[1, 16]`. Zero would mean a size refuted before it was ever tried, which is not a budget;
 * the ceiling is well past anything useful, since each probe costs a full PROBE_TIMER of waiting and a
 * path that drops three sized packets in a row is not going to accept the seventeenth.
 */
@JvmInline
public value class ProbeBudget(
    public val value: Int,
) {
    init {
        require(value in 1..PROBE_BUDGET_MAX) { "probe budget $value is outside 1..$PROBE_BUDGET_MAX" }
    }
}

/**
 * How close the search must get before it stops (RFC 8899 §5.3's search granularity): once the confirmed
 * and refuted sizes are within this many bytes of each other, the remaining gap is not worth a probe.
 *
 * Four-byte aligned and bounded at `[4, 64]`, matching the alignment every SCTP chunk already has. A
 * granularity finer than four bytes cannot change the fragment ceiling at all, so it would buy probes
 * that provably do nothing.
 */
@JvmInline
public value class PmtuStep(
    public val value: Int,
) {
    init {
        require(value in PMTU_STEP_MIN..PMTU_STEP_MAX) { "PMTU step $value is outside $PMTU_STEP_MIN..$PMTU_STEP_MAX" }
        require(value % PMTU_ALIGNMENT == 0) { "PMTU step $value is not a multiple of $PMTU_ALIGNMENT" }
    }
}

/**
 * Whether this association measures the path MTU it rides, or takes the address family's word for it.
 *
 * **[Fixed] is the default, deliberately.** Probing is not free — it puts sized packets on a path that a
 * middlebox may treat as an attack, it costs a HEARTBEAT-ACK round trip per step, and the whole gain is a
 * few hundred bytes per fragment. The value of the family-derived ceiling ([SctpPathProfile]) is that it
 * is already correct where correctness matters: it is what stops an IPv6 datagram exceeding RFC 8200 §5's
 * guaranteed 1280 and being dropped. Discovery is what turns "correct" into "efficient", and that is an
 * opt-in.
 */
public sealed interface PathMtuPolicy {
    /**
     * No probing. The ceiling is whatever the address family admits without measurement
     * ([PathAddressFamily.unprobedPathMtu]), capped by `SctpConfig.maxPayloadBytes`.
     */
    public data object Fixed : PathMtuPolicy

    /**
     * RFC 8899 Packetization Layer Path MTU Discovery, over SCTP's own probe vocabulary: a HEARTBEAT
     * padded with an RFC 4820 PAD chunk to the candidate size, confirmed by the HEARTBEAT-ACK it draws.
     *
     * The search is in two phases, which is RFC 8899 §5.2's BASE → SEARCHING progression:
     *
     * 1. **Confirm what is already being emitted.** The first probe is sized at the family's unprobed
     *    value — the size this association is *already* putting on the wire — so the first thing the
     *    search establishes is whether the assumption underneath every datagram so far is even true. A
     *    search that started above it would spend its budget on a raise while the base silently
     *    black-holed.
     * 2. **Raise toward [searchCeiling]**, halving the interval between the largest confirmed size and
     *    the smallest refuted one until they are within [granularity].
     *
     * **Deviation from §5.2's ERROR state, stated rather than hidden:** when the base is refuted the RFC
     * drops to MIN_PMTU and stays there until a timer retries the base. Here the drop happens (it must —
     * datagrams at the refuted size are being lost right now) and then the *same* search runs upward from
     * MIN_PMTU with the refuted size as its ceiling. Sitting at 576 bytes on a 1400-byte IPv4 path until
     * a ten-minute timer fires is a worse outcome than the four probes it takes to find 1400, and the
     * machinery is already there.
     *
     * There is no configurable base size. The base is the family's unprobed value by construction, which
     * is both what the association is already emitting and already family-aware — a configured one could
     * be set below the family minimum, which is a state with no meaning and no defence.
     */
    public data class Discover(
        /** The largest size worth probing for. Above this the search stops even if the path would carry more. */
        public val searchCeiling: PmtuBytes = PmtuBytes(DEFAULT_SEARCH_CEILING),
        /** RFC 8899 §5.1.2 MAX_PROBES — unanswered probes of one size before it is refuted. */
        public val maxProbes: ProbeBudget = ProbeBudget(DEFAULT_MAX_PROBES),
        /** RFC 8899 §5.1.1 PMTU_RAISE_TIMER — how long a completed search rests before re-opening. */
        public val raiseInterval: Duration = PMTU_RAISE_INTERVAL,
        /** How close the search must converge before it stops. */
        public val granularity: PmtuStep = PmtuStep(DEFAULT_GRANULARITY),
    ) : PathMtuPolicy
}

/**
 * Why the fragmentation ceiling moved — carried on [SctpOutput.PathMtuChanged] so a driver can tell a
 * measurement from a migration from a failure, which the number alone cannot.
 *
 * Three genuinely different events hide behind "the ceiling changed", and they call for different
 * reactions: the first is routine, the second is a path change worth correlating with an ICE restart, and
 * the third means datagrams were being lost until now.
 */
public sealed interface PathMtuChangeCause {
    /**
     * The lower layer named the path (RFC 8261 §6.1), so the ceiling is now derived from its address
     * family rather than from configuration alone. The ordinary first event of a session.
     */
    public data class PathAssessed(
        public val family: PathAddressFamily,
    ) : PathMtuChangeCause

    /** A probe of this size was answered: the path demonstrably carries it (RFC 8899 §5.2 SEARCHING). */
    public data object ProbeConfirmed : PathMtuChangeCause

    /**
     * The size the association was **already emitting** went unanswered for the whole probe budget, so
     * the path does not carry it and has not been carrying it. The ceiling drops to the family minimum
     * and the search restarts from there.
     *
     * This is the one worth logging loudly: every full-size fragment sent before this was lost, and
     * nothing else in the stack could have said so — a black-holed MTU presents as a peer that stopped
     * acknowledging.
     */
    public data object BaseRefuted : PathMtuChangeCause
}

/**
 * DATA chunks that were encoded before the ceiling dropped and are now too large for the path to carry.
 *
 * They exist because classic SCTP assigns a TSN at enqueue and the encoded packet is the retained copy
 * (RFC 4960 §6.1) — there is no re-fragmentation after the fact, and RFC 8260 I-DATA, which would allow
 * it, is deliberately not implemented here.
 *
 * Sealed rather than an `Int` that is sometimes zero, because [None] is the overwhelmingly common case
 * and a caller reading `backlog == 0` has to know that zero is not a count of anything. [Present] is a
 * real event with a real consequence: those chunks are skipped via RFC 3758 FORWARD-TSN where the peer
 * supports it, and where it does not they cannot be skipped at all and will retransmit until the
 * association's error budget runs out.
 */
public sealed interface OversizedBacklog {
    /** Nothing queued or outstanding exceeds the new ceiling. */
    public data object None : OversizedBacklog

    /** [chunks] DATA chunks cannot be delivered at the new ceiling. */
    public data class Present(
        public val chunks: Int,
    ) : OversizedBacklog {
        init {
            require(chunks >= 1) { "an oversized backlog of $chunks is None, not Present" }
        }
    }
}

@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The association control block (RFC 4960 §1.4 TCB): either there is an established association, with
 * every structure it needs, or there is none.
 *
 * Held as three independently-nullable fields (`retransmissionQueue`, `reassemblyQueue`, `congestion`),
 * a **partly** populated control block was constructible — and the code said so: `establishControlBlocks`
 * assigned the three in sequence and then reached for `retransmissionQueue!!`, a bang that is only safe
 * because of an assignment three lines above it. Every consumer then re-asked the same question
 * separately, so `onT3Timeout` unwrapped two of them and duplicated its disarm-and-return in both arms
 * for a state that cannot happen.
 *
 * The queues are created together, in one place, and die together in `clearControlBlocks`. [Live] says so:
 * one unwrap answers for both, and there is no bang anywhere.
 *
 * Congestion control has since moved out to [PathRide], which is a different lifetime rather than a
 * smaller one: cwnd and ssthresh belong to the *path*, and a path can be replaced under an association
 * that is not being torn down. Keeping it here would have made a migration reach into the control block
 * to replace one field of it, which is exactly the partial population this type exists to forbid.
 */
internal sealed interface Tcb {
    /** No association — before the handshake completes, and after any teardown. */
    data object NoAssociation : Tcb

    /** An established association: both queues exist for exactly as long as it does. */
    class Live(
        val retransmission: RetransmissionQueue,
        val reassembly: ReassemblyQueue,
        /** What the handshake settled — a `var` because RFC 6525 §4.5 raises the stream counts in place. */
        var negotiated: Negotiated,
    ) : Tcb
}

/**
 * Everything the two endpoints agreed on while forming this association: which extensions the peer
 * advertised, and how many streams exist in each direction (RFC 4960 §5.1.1).
 *
 * It lives **on [Tcb.Live]** rather than beside it, and that placement is the point. Every field here is
 * a fact about one particular peer, learned during one particular handshake, and each was previously a
 * free-standing field that a teardown had to remember to clear — the shape that let
 * `clearControlBlocks` reset `peerSupportsReConfig` and forget `peerSupportsForwardTsn`, so a departed
 * peer's advertised capability survived into the association state. Here the whole value dies with the
 * control block it describes, so "partial reliability available with no association" is unconstructible
 * rather than merely unwritten.
 *
 * [incomingStreams] is `min(our MIS, the peer's OS)` and [outgoingStreams] is `min(our OS, the peer's
 * MIS)` — two different minima that a symmetric configuration makes equal, which is exactly why one
 * value standing for both would pass every fixture this repo runs.
 */
internal data class Negotiated(
    val extensions: PeerExtensions,
    val outgoingStreams: StreamCount,
    val incomingStreams: StreamCount,
) {
    companion object {
        /** No association: nothing advertised, no streams in either direction. */
        val None: Negotiated = Negotiated(PeerExtensions.None, StreamCount.None, StreamCount.None)
    }
}

/**
 * Unwrap to the established control block, or run [onNone] — which must not return (typically `return`,
 * sometimes after disarming a timer). Inline, so the non-local return reads exactly like the `?: return`
 * it replaces while the state itself stays sealed rather than nullable.
 */
internal inline fun Tcb.liveOrElse(onNone: () -> Nothing): Tcb.Live =
    when (this) {
        Tcb.NoAssociation -> onNone()
        is Tcb.Live -> this
    }

/**
 * One timer of the association: armed to fire at an instant, or not armed at all (ARCHITECTURE §5.1 —
 * the association owns no clock, so a timer *is* an absolute deadline and nothing else).
 *
 * A sealed pair rather than `Instant?`. Null carries exactly one meaning here, which is why the public
 * [SctpAssociation.nextDeadline] still uses it, but *inside* the association there are five of these
 * beside one another and a null in that company reads as "absent" in five subtly different sentences.
 * The variant names the state, so `is Deadline.At` at a comparison site says which question is being
 * asked instead of leaving the reader to infer it from the field name.
 */
internal sealed interface Deadline {
    /** No timer running. Nothing to compare `now` against, so there is no instant to carry. */
    data object Unarmed : Deadline

    /** Armed: fires once `now` reaches [instant]. */
    data class At(
        val instant: Instant,
    ) : Deadline

    /** True when this timer is armed and [now] has reached it. */
    fun dueAt(now: Instant): Boolean =
        when (this) {
            Unarmed -> false
            is At -> now >= instant
        }
}

/**
 * Every timer the association can arm, as **one value**.
 *
 * Held as five independent fields, cancelling them was five assignments a caller had to remember, and
 * `cancelAllTimers` enumerated them by hand — so a timer added later is cancelled everywhere the author
 * thought to look and left running everywhere they did not. That is not hypothetical: the RFC 4960 §6.1
 * zero-window probe and the RFC 8899 PMTU probe both arrive in this same change set, and each would have
 * been one more line to forget in a function whose name promises it cancels everything.
 *
 * [cancelAll] is therefore a fresh instance rather than a sequence of assignments: a new timer added
 * below defaults to [Deadline.Unarmed] and is cancelled correctly without anyone editing [cancelAll].
 * [earliest] is the one place that still enumerates, and it is a single expression a new timer must join
 * — visible, and in one file, rather than spread across the state machine.
 */
internal data class AssociationDeadlines(
    /** T1-init / T1-cookie (RFC 4960 §5.1): the handshake retransmit timer. */
    val handshake: Deadline = Deadline.Unarmed,
    /** T3-rtx (RFC 4960 §6.3.2): the retransmission timer for outstanding DATA. */
    val t3: Deadline = Deadline.Unarmed,
    /** The delayed-SACK timer (RFC 4960 §6.2). */
    val sack: Deadline = Deadline.Unarmed,
    /** T2-shutdown (RFC 4960 §9.2): SHUTDOWN / SHUTDOWN-ACK retransmission. */
    val shutdown: Deadline = Deadline.Unarmed,
    /** The RFC 6525 §5.1.2 reconfiguration-request retransmit timer. */
    val reConfig: Deadline = Deadline.Unarmed,
) {
    /**
     * The earliest armed deadline, or [Deadline.Unarmed] when nothing is armed. The single enumeration
     * point: a timer added to this class must be added here too, and nowhere else.
     */
    fun earliest(): Deadline {
        var soonest: Deadline = Deadline.Unarmed
        for (candidate in listOf(handshake, t3, sack, shutdown, reConfig)) {
            val current = soonest
            soonest =
                when {
                    candidate !is Deadline.At -> current
                    current !is Deadline.At -> candidate
                    candidate.instant < current.instant -> candidate
                    else -> current
                }
        }
        return soonest
    }

    /** Cancel every timer. Total by construction — see the class KDoc. */
    fun cancelAll(): AssociationDeadlines = AssociationDeadlines()
}

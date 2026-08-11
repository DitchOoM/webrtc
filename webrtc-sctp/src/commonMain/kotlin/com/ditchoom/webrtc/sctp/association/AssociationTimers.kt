@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import kotlin.time.ExperimentalTime
import kotlin.time.Instant

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

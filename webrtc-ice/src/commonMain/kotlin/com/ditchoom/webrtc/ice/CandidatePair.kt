package com.ditchoom.webrtc.ice

/**
 * The state of a candidate pair on the checklist (RFC 8445 §6.1.2.6). A pair walks
 * `Frozen → Waiting → InProgress → (Succeeded | Failed)`; [Succeeded] means a connectivity check
 * completed both ways (a valid pair). Modeled as a sealed-style enum so a `when` over it is exhaustive
 * and an illegal transition is caught by the agent's own guard, never encoded as a boolean soup.
 */
public enum class CandidatePairState {
    /** Waiting on its foundation — a same-foundation pair is being checked first (the frozen algorithm). */
    Frozen,

    /** Unfrozen and eligible to be checked when the pacing timer (Ta) next fires. */
    Waiting,

    /** A connectivity check has been sent and is awaiting a response or retransmission. */
    InProgress,

    /** The check succeeded — the pair is valid and may be nominated. */
    Succeeded,

    /** The check failed (timed out, or an unrecoverable error response). */
    Failed,
}

/**
 * A **candidate pair** (RFC 8445 §6.1.2): a local candidate paired with a remote one, the unit a
 * connectivity check runs over. Checks are sent **from [local].base to [remote].address**. This is the
 * immutable *identity* of a pair; the agent tracks its mutable state (checklist position, in-flight
 * transaction, nomination) separately, so the identity is a clean map key and diffable fixture value.
 */
public data class CandidatePair(
    public val local: IceCandidate,
    public val remote: IceCandidate,
) {
    /** The pair foundation (RFC 8445 §6.1.2.6): the two candidate foundations, for the frozen algorithm. */
    public val foundation: Pair<Foundation, Foundation> get() = local.foundation to remote.foundation

    /**
     * The pair priority (RFC 8445 §6.1.2.3): with `G` the controlling agent's candidate priority and `D`
     * the controlled agent's, `2^32·min(G,D) + 2·max(G,D) + (G>D ? 1 : 0)`. Computed in [ULong] because
     * the `2^32·min` term reaches ~2^63 — beyond a signed `Long` — while still fitting 64 unsigned bits.
     * [localRole] tells us which of [local]/[remote] plays `G`.
     */
    public fun priority(localRole: IceRole): ULong {
        val g = (if (localRole == IceRole.Controlling) local.priority else remote.priority).toULong()
        val d = (if (localRole == IceRole.Controlling) remote.priority else local.priority).toULong()
        val min = minOf(g, d)
        val max = maxOf(g, d)
        val tie = if (g > d) 1uL else 0uL
        return (min shl PAIR_PRIORITY_SHIFT) + (2uL * max) + tie
    }

    private companion object {
        const val PAIR_PRIORITY_SHIFT = 32
    }
}

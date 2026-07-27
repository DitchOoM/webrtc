package com.ditchoom.webrtc.ice

// `CandidatePairState` used to live here: a public enum for the RFC 8445 §6.1.2.6 checklist states.
// It is gone, and deliberately so. It was public API with **no consumer** — it appeared on no public
// signature and was referenced only from inside `IceAgent` — while the agent had to carry the pair's
// in-flight transaction in a *separate* nullable field beside it. Those two fields desynchronised and
// shipped a bug (a timed-out consent check dropped the transaction without touching the state, parking
// the pair `InProgress` with nothing in flight, forever). The checklist state is now `IceAgent`'s
// private sealed `CheckState`, which carries the in-flight check inside the one case that has one, so
// the desync is unrepresentable. Nothing public replaces it: the checklist is the agent's own business,
// and `IceConnectionState` + `IcePath` are what a consumer actually observes.

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

package com.ditchoom.webrtc.ice

import kotlin.jvm.JvmInline

/**
 * W3 placeholder. The real module is a sans-io agent core — `handle(event, now): List<Output>` plus
 * `nextDeadline(now): Instant?`, no dispatcher/clock/random/I/O inside it (RFC §5.1). Placeholder only.
 */
public object Ice {
    public const val MODULE: String = "webrtc-ice"
}

/** ICE username fragment, wrapped so it cannot be swapped with a password or any other credential. */
@JvmInline
public value class Ufrag(
    public val value: String,
)

/** ICE password, distinct in the type system from [Ufrag] even though both wrap a `String`. */
@JvmInline
public value class IcePassword(
    public val value: String,
)

/**
 * Which **ICE generation** a trickled candidate belongs to (RFC 8838 §3.1: *"the candidate is associated
 * with a specific ICE generation, identified by the username fragment"*).
 *
 * A trickled candidate arrives out of band from the description that declared the generation it was
 * gathered in, so across an ICE restart (RFC 8445 §9) the two can cross on the wire: a candidate for the
 * *new* generation can land before the offer that announces it, and a candidate for the *old* one can
 * land after. Untagged, both are indistinguishable from a candidate of whatever generation happens to be
 * current — the first is silently naturalized into the wrong one, the second is naturalized into the
 * right-looking-but-dead one, and only ICE peer-reflexive learning (RFC 8445 §7.3.1.3) recovers the path.
 *
 * [Untagged] is a first-class case, not a degraded one: the ufrag is optional on the wire, every foreign
 * peer in the interop matrix trickles without it, and an untagged candidate is handled exactly as it was
 * before this type existed. Sealed rather than a `Ufrag?` so a call site cannot read "no tag" as "no
 * candidate" or forget which of the two it is holding.
 */
public sealed interface CandidateGeneration {
    /** The candidate names no generation — apply it to the generation that is current right now. */
    public data object Untagged : CandidateGeneration

    /**
     * The candidate belongs to the generation whose **sender-side** ufrag is [ufrag] — i.e. the value the
     * sender advertises as its own `a=ice-ufrag`, which is the receiver's *remote* ufrag.
     */
    public data class Tagged(
        public val ufrag: Ufrag,
    ) : CandidateGeneration
}

/**
 * Why a trickled remote candidate was deliberately **not** added to the checklist (RFC 8838 §3.1).
 *
 * Reported rather than dropped in silence: "the candidate never arrived", "the candidate was malformed"
 * and "the candidate named a generation we have left" are three different diagnoses of the same symptom,
 * and only a typed reason distinguishes them at 3 a.m. Strings are diagnostics, never discriminants
 * (standing directive #3).
 */
public sealed interface CandidateDiscardReason {
    /**
     * The candidate names a generation this agent has already left — the peer signaled newer credentials
     * after it was sent (RFC 8445 §9). Adding it would extend the *current* checklist with an address
     * whose generation no longer authenticates, which is how a late candidate turns into a check that can
     * only fail.
     */
    public data class SupersededGeneration(
        public val ufrag: Ufrag,
    ) : CandidateDiscardReason

    /**
     * The candidate names a generation that has not been applied yet, and the bounded hold buffer was
     * full — so the **oldest** held candidate was evicted to make room (see
     * [IceAgent][com.ditchoom.webrtc.ice.IceAgent]'s hold bound). A peer that trickles candidates for
     * generations it never signals is either broken or hostile; either way the hold must not grow.
     */
    public data class UnappliedGenerationOverflow(
        public val ufrag: Ufrag,
    ) : CandidateDiscardReason
}

/**
 * Why an ICE agent gave up (RFC 8445), as an exhaustive sealed set that maps into the library's typed
 * error vocabulary. Strings are diagnostics, never discriminants (standing directive #3). Consumers
 * `when` over this with no `else`; adding a reason is a compile error at every call site until handled.
 */
public sealed interface IceFailureReason {
    public object NoCandidatePairs : IceFailureReason

    public object ConsentExpired : IceFailureReason

    public data class AllPairsFailed(
        val pairsTried: Int,
    ) : IceFailureReason
}

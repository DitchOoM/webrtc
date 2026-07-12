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

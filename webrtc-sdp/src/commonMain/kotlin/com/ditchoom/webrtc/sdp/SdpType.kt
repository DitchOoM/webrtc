package com.ditchoom.webrtc.sdp

/**
 * The type of a session description in the JSEP offer/answer exchange (RFC 8829 §4.1.1 / the W3C
 * `RTCSdpType`). A dataless closed set, so an enum; [token] is the wire/JS spelling.
 */
public enum class SdpType(
    public val token: String,
) {
    /** An initial or subsequent offer (`createOffer`). */
    Offer("offer"),

    /** A provisional answer — negotiation is not yet final (RFC 8829 §4.1.10.2). */
    PrAnswer("pranswer"),

    /** A final answer; applying it returns signaling to `stable`. */
    Answer("answer"),

    /** Discards a not-yet-applied local/remote offer, returning to the last stable state (RFC 8829 §4.1.8.2). */
    Rollback("rollback"),
    ;

    public companion object {
        /** The [SdpType] for a wire token, or null if unrecognized (typed-reject discipline). */
        public fun fromToken(token: String): SdpType? = entries.firstOrNull { it.token == token }
    }
}

/**
 * The [SdpType]s that actually **carry a description**. [SdpType.Rollback] is deliberately not a member:
 * it applies no description at all, it discards one.
 *
 * That distinction is a type here rather than a runtime check because modelling it as one 4-valued type
 * is what let `SetLocalDescription(SdpType.Rollback, someDescription)` be constructed — a combination the
 * machine answered by silently discarding the argument, and which a runtime `MissingDescription` error had
 * to police from the other side (issue #77). With this split, [JsepEvent.SetLocalDescription.Apply] takes
 * a type that cannot be rollback and a description that cannot be null, and the illegal pairs are simply
 * unrepresentable (DESIGN_PRINCIPLES §4).
 */
public enum class AppliedSdpType(
    /** The wire/W3C [SdpType] this applies. */
    public val sdpType: SdpType,
) {
    Offer(SdpType.Offer),
    PrAnswer(SdpType.PrAnswer),
    Answer(SdpType.Answer),
    ;

    public companion object {
        /**
         * The [AppliedSdpType] for [type], or null when [type] is [SdpType.Rollback] — which is not a
         * failure but the *other* case: a caller holding a W3C-shaped `SdpType` branches on this null to
         * build [JsepEvent.SetLocalDescription.Rollback] instead of an `Apply`.
         */
        public fun of(type: SdpType): AppliedSdpType? = entries.firstOrNull { it.sdpType == type }
    }
}

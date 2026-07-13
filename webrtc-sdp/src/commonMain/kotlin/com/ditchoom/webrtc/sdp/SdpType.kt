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

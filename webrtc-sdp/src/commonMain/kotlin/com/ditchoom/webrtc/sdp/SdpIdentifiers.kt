package com.ditchoom.webrtc.sdp

import kotlin.jvm.JvmInline

/**
 * A media-section identifier (`a=mid:`, RFC 5888 / RFC 9143), wrapped so it is never interchangeable
 * with a bare string — a BUNDLE group is a `List<Mid>`, and the compiler refuses a raw `String` there
 * (DESIGN_PRINCIPLES §2). A mid is a non-empty token; the invariant is enforced at construction so an
 * invalid one cannot exist.
 */
@JvmInline
public value class Mid(
    public val value: String,
) {
    init {
        require(value.isNotBlank()) { "mid must not be blank" }
    }
}

/**
 * The DTLS role negotiated in SDP (`a=setup:`, RFC 8842 / RFC 4145 §4). A dataless closed set, so an
 * enum — but the wire token is not the enum name, so [token] carries it and [fromToken] is the total,
 * null-on-unknown parse (never a throw).
 */
public enum class SetupRole(
    public val token: String,
) {
    /** Offerer's default: willing to be client or server; the answerer chooses (RFC 8842 §5.1). */
    ActPass("actpass"),

    /** This endpoint will be the DTLS client (sends ClientHello). */
    Active("active"),

    /** This endpoint will be the DTLS server. */
    Passive("passive"),

    /** Placeholder before a role is chosen (`a=setup:holdconn`, RFC 4145) — rare, modeled for totality. */
    HoldConn("holdconn"),
    ;

    public companion object {
        /** The [SetupRole] for a wire token, or null if unrecognized (typed-reject discipline). */
        public fun fromToken(token: String): SetupRole? = entries.firstOrNull { it.token == token }
    }
}

/**
 * A certificate fingerprint carried in SDP (`a=fingerprint:<hash-func> <hex>`, RFC 8122 §5). This is
 * the SDP-line representation only — the DTLS layer (W4) owns certificate identity; here it is a pair
 * of text fields interpreted from the attribute value, kept exactly as written for round-trip fidelity.
 */
public data class Fingerprint(
    public val hashFunction: String,
    public val value: String,
)

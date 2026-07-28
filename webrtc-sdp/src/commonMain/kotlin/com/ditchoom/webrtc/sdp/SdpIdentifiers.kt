package com.ditchoom.webrtc.sdp

import kotlin.jvm.JvmInline
import kotlin.random.Random

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

/**
 * The identifier of a **DTLS association** as signaled in SDP (`a=tls-id`, RFC 8842 §5.3). Each endpoint
 * generates its own; it is stable for the life of that endpoint's association and changes **only** when
 * the endpoint intends to establish a new one (§5.5). That makes it the explicit statement of what an
 * unchanged `a=fingerprint` only implies — an offer/answer that repeats the previous value is asking to
 * keep the association it already has, and one carrying a new value is asking for a fresh handshake.
 *
 * Wrapped so it is never a bare `String` at an API boundary (DESIGN_PRINCIPLES §2) — the compiler refuses
 * to pass it where a [Mid] or an ICE ufrag is expected, and the RFC 8842 §5.3 grammar
 * (`tls-id-value = 20*(token-char)`) is enforced at construction, so a malformed one cannot exist. Parse
 * an untrusted value with [fromValue] (null on malformed) or [SdpSection.tlsId] (a typed
 * [TlsIdAttribute]); the constructor is for values already known to be well-formed.
 */
@JvmInline
public value class TlsId(
    public val value: String,
) {
    init {
        require(isWellFormed(value)) { "tls-id must be at least $MIN_LENGTH SDP token characters (RFC 8842 §5.3)" }
    }

    public companion object {
        /** RFC 8842 §5.3: `tls-id-value = 20*(token-char)` — at least 20 characters. */
        public const val MIN_LENGTH: Int = 20

        /**
         * The generated length: 24 characters over a 64-symbol alphabet is 144 bits, comfortably past the
         * "at least 120 bits of randomness" RFC 8842 §5.3 requires of a generated value.
         */
        private const val GENERATED_LENGTH = 24

        /** 64 RFC 4566 `token-char`s — one alphabet symbol per 6 bits drawn, no rejection sampling. */
        private const val TLS_ID_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-."

        /** The [TlsId] for a signaled value, or null if it does not meet the grammar (typed-reject discipline). */
        public fun fromValue(value: String): TlsId? = if (isWellFormed(value)) TlsId(value) else null

        /**
         * A fresh tls-id from [random] — the seam production wires to `CryptoRandom` and a test to a seed
         * (standing directive #2). RFC 8842 §5.3 requires a cryptographically random source here, which is
         * a property of the injected [Random], not of this function.
         */
        public fun random(random: Random): TlsId =
            TlsId(
                buildString(GENERATED_LENGTH) {
                    repeat(GENERATED_LENGTH) { append(TLS_ID_CHARS[random.nextInt(TLS_ID_CHARS.length)]) }
                },
            )

        private fun isWellFormed(value: String): Boolean = value.length >= MIN_LENGTH && value.all(::isTokenChar)

        /** RFC 4566 `token-char = %x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39 / %x41-5A / %x5E-7E`. */
        private fun isTokenChar(c: Char): Boolean =
            c == '!' ||
                c in '#'..'\'' ||
                c in '*'..'+' ||
                c in '-'..'.' ||
                c in '0'..'9' ||
                c in 'A'..'Z' ||
                c in '^'..'~'
    }
}

/**
 * What a section says about `a=tls-id` (RFC 8842 §5.3) — three genuinely different situations, so three
 * cases rather than a nullable that conflates two of them:
 *
 * - [Absent] — no `a=tls-id` line. **Legal and common**: the attribute is optional, and no peer in this
 *   stack's interop matrix emits one. A reader must fall back to inferring association continuity from an
 *   unchanged `a=fingerprint`, exactly as before the attribute existed (RFC 8842 §5.5).
 * - [Present] — a well-formed value, usable for the §5.5 same-association comparison.
 * - [Malformed] — the line is there but its value does not meet the §5.3 grammar. A **typed reject**, never
 *   a throw (T0 discipline): the raw text rides along as a diagnostic, never as a discriminant.
 */
public sealed interface TlsIdAttribute {
    /** No `a=tls-id` in this section — the peer says nothing about DTLS association identity. */
    public data object Absent : TlsIdAttribute

    /** A well-formed `a=tls-id`. */
    public data class Present(
        public val tlsId: TlsId,
    ) : TlsIdAttribute

    /** An `a=tls-id` whose value is not `20*(token-char)`; [value] is the verbatim text, a diagnostic only. */
    public data class Malformed(
        public val value: String,
    ) : TlsIdAttribute
}

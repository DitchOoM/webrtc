package com.ditchoom.webrtc.ice

import kotlin.jvm.JvmInline
import kotlin.random.Random

/**
 * The ICE role (RFC 8445 §6.1). Exactly one agent is **controlling** — it decides which valid pair is
 * nominated for use — and the other is **controlled**. In JSEP the offerer is controlling. A role is a
 * closed, dataless pair, so an enum (DESIGN_PRINCIPLES §3).
 */
public enum class IceRole {
    Controlling,
    Controlled,
    ;

    public val opposite: IceRole get() = if (this == Controlling) Controlled else Controlling
}

/**
 * The 64-bit ICE **tie-breaker** (RFC 8445 §5.2) an agent picks at start-up and carries in every check
 * as ICE-CONTROLLING / ICE-CONTROLLED. When both agents believe they hold the same role (a role
 * conflict, §7.3.1.1), the larger tie-breaker wins and keeps its role; the loser switches. Wrapped so
 * it is never a bare `Long` (it is compared as **unsigned**, which a bare `Long` would get wrong).
 */
@JvmInline
public value class TieBreaker(
    public val value: Long,
) {
    /** Unsigned comparison, per RFC 8445 §7.3.1.1 (the tie-breaker is an unsigned 64-bit number). */
    public operator fun compareTo(other: TieBreaker): Int = value.toULong().compareTo(other.value.toULong())

    public companion object {
        /** A fresh tie-breaker from injected entropy (directive #2 — seeded [Random] replays in tests). */
        public fun random(random: Random): TieBreaker = TieBreaker(random.nextLong())
    }
}

/**
 * ICE short-term credentials (RFC 8445 §5.3): the username fragment and password an agent advertises,
 * against which a peer's connectivity checks are authenticated. Generated from injected entropy so a
 * test replays the exact ufrag/pwd (directive #2).
 */
public data class IceCredentials(
    public val ufrag: Ufrag,
    public val password: IcePassword,
) {
    public companion object {
        // RFC 8445 §5.3: ufrag >= 4 chars, pwd >= 22 chars, drawn from the ICE-char set (RFC 3986
        // unreserved plus '+' and '/'). These are the minimum lengths; longer is fine.
        private const val UFRAG_LENGTH = 4
        private const val PASSWORD_LENGTH = 24
        private const val ICE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

        /** Fresh credentials from [random] — the seam production wires to `CryptoRandom`, tests to a seed. */
        public fun random(random: Random): IceCredentials =
            IceCredentials(
                ufrag = Ufrag(randomIceString(random, UFRAG_LENGTH)),
                password = IcePassword(randomIceString(random, PASSWORD_LENGTH)),
            )

        private fun randomIceString(
            random: Random,
            length: Int,
        ): String = buildString(length) { repeat(length) { append(ICE_CHARS[random.nextInt(ICE_CHARS.length)]) } }
    }
}

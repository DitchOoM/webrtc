package com.ditchoom.webrtc.stun

/**
 * The outcome of [StunMessage.decode]. Parse failure is a **typed reject**, never a throw-through or
 * a crash (T0 discipline / DESIGN_PRINCIPLES §6): a caller `when`s over this exhaustively with no
 * `else`, and a hostile datagram can only ever produce a [Reject], never an exception.
 */
public sealed interface StunDecodeResult {
    public data class Success(
        public val message: StunMessage,
    ) : StunDecodeResult

    public data class Reject(
        public val reason: StunRejectReason,
    ) : StunDecodeResult
}

/**
 * Why a datagram is not a well-formed STUN message. A sealed, exhaustive vocabulary — the
 * discriminant is the type, never a string (directive #3); the diagnostic detail rides as data.
 * These map into the `SocketException` hierarchy at the session layer (W6).
 */
public sealed interface StunRejectReason {
    /** Fewer than the 20-byte header, or the header's own fixed fields ran off the end. */
    public data object ShorterThanHeader : StunRejectReason

    /** The two leading bits were not zero — not a STUN message (RFC 8489 §5). */
    public data object NotStunMethod : StunRejectReason

    /** Magic cookie was not 0x2112A442 (RFC 8489 §5): legacy RFC 3489 or non-STUN traffic. */
    public data class BadMagicCookie(
        public val actual: UInt,
    ) : StunRejectReason

    /** Message length was not a multiple of 4 (RFC 8489 §5). */
    public data class LengthNotAligned(
        public val messageLength: Int,
    ) : StunRejectReason

    /** The declared attribute region extends past the datagram. */
    public data class Truncated(
        public val needed: Int,
        public val available: Int,
    ) : StunRejectReason

    /** An attribute's TLV header or value ran past the message, or padding didn't align. */
    public data class MalformedAttribute(
        public val offset: Int,
    ) : StunRejectReason
}

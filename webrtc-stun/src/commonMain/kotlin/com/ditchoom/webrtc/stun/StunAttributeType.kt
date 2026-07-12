package com.ditchoom.webrtc.stun

import kotlin.jvm.JvmInline

/**
 * A STUN attribute type (RFC 8489 §14, §18.3; TURN adds RFC 8656 §14). A 16-bit registry point,
 * wrapped so it is never a bare `UShort`. The high bit of the range splits the two RFC 8489 §5
 * classes: **comprehension-required** (0x0000–0x7FFF) — an unknown one makes the message
 * unprocessable — versus **comprehension-optional** (0x8000–0xFFFF) — an unknown one is skipped.
 */
@JvmInline
public value class StunAttributeType(
    public val value: UShort,
) {
    /** RFC 8489 §5: 0x0000–0x7FFF must be understood; 0x8000–0xFFFF may be ignored if unknown. */
    public val isComprehensionRequired: Boolean
        get() = value < COMPREHENSION_OPTIONAL_BASE

    public companion object {
        private const val COMPREHENSION_OPTIONAL_BASE: UShort = 0x8000u

        // Core STUN (RFC 8489 §14).
        public val MappedAddress: StunAttributeType = StunAttributeType(0x0001u)
        public val Username: StunAttributeType = StunAttributeType(0x0006u)
        public val MessageIntegrity: StunAttributeType = StunAttributeType(0x0008u)
        public val ErrorCode: StunAttributeType = StunAttributeType(0x0009u)
        public val UnknownAttributes: StunAttributeType = StunAttributeType(0x000Au)
        public val Realm: StunAttributeType = StunAttributeType(0x0014u)
        public val Nonce: StunAttributeType = StunAttributeType(0x0015u)
        public val MessageIntegritySha256: StunAttributeType = StunAttributeType(0x001Cu)
        public val XorMappedAddress: StunAttributeType = StunAttributeType(0x0020u)
        public val Software: StunAttributeType = StunAttributeType(0x8022u)
        public val AlternateServer: StunAttributeType = StunAttributeType(0x8023u)
        public val Fingerprint: StunAttributeType = StunAttributeType(0x8028u)

        // TURN (RFC 8656 §14) — codec-only in W1.
        public val ChannelNumber: StunAttributeType = StunAttributeType(0x000Cu)
        public val Lifetime: StunAttributeType = StunAttributeType(0x000Du)
        public val XorPeerAddress: StunAttributeType = StunAttributeType(0x0012u)
        public val Data: StunAttributeType = StunAttributeType(0x0013u)
        public val XorRelayedAddress: StunAttributeType = StunAttributeType(0x0016u)
        public val RequestedAddressFamily: StunAttributeType = StunAttributeType(0x0017u)
        public val EvenPort: StunAttributeType = StunAttributeType(0x0018u)
        public val RequestedTransport: StunAttributeType = StunAttributeType(0x0019u)
        public val DontFragment: StunAttributeType = StunAttributeType(0x001Au)
        public val ReservationToken: StunAttributeType = StunAttributeType(0x0022u)
    }
}

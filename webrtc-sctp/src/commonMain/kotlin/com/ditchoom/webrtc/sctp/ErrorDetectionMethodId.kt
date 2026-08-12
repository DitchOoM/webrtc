package com.ditchoom.webrtc.sctp

import kotlin.jvm.JvmInline

/**
 * An RFC 9653 §8 Error Detection Method Identifier — what an endpoint proposes to use *instead of* the
 * CRC32c in RFC 4960 §6.8.
 *
 * A value class over the wire's 32-bit identifier rather than an enum, because the registry is IANA's and
 * an endpoint may legitimately advertise a method this library has never heard of. An unknown identifier
 * is data to be compared and declined, not a parse failure — modelling it as an enum would make a
 * conforming peer's advertisement into a decode error.
 *
 * [Reserved] doubles as "nothing was advertised", which is sound rather than convenient: RFC 9653 §8
 * reserves 0 and forbids its use as a real method, so a zeroed field cannot collide with a method some
 * future peer actually proposes. That is what lets the State Cookie carry this field with no companion
 * "was it present" Boolean.
 */
@JvmInline
public value class ErrorDetectionMethodId(
    public val value: UInt,
) {
    public companion object {
        /** Reserved by RFC 9653 §8, and therefore this library's encoding of "the peer advertised none". */
        public val Reserved: ErrorDetectionMethodId = ErrorDetectionMethodId(0u)

        /**
         * The Zero Checksum Method (RFC 9653 §4): the sender writes 0 in the checksum field and the
         * receiver accepts it on the transport's own integrity guarantee — for WebRTC, DTLS's AEAD.
         */
        public val ZeroChecksum: ErrorDetectionMethodId = ErrorDetectionMethodId(1u)
    }
}

package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.codec.annotations.Endianness
import com.ditchoom.buffer.codec.annotations.ProtocolMessage
import kotlin.jvm.JvmInline

// The identifier value classes of SCTP (RFC 4960) and the WebRTC data-channel binding (RFC 8831).
// Every identifier is a `@JvmInline value class` around its exact on-wire scalar (directive: make
// illegal states unrepresentable; ids are never a bare Int/UInt/UShort at an API boundary). The
// compiler refuses to pass a Tsn where a VerificationTag is expected even though both wrap UInt, and
// none of them carries a runtime cost.

/**
 * An SCTP Transmission Sequence Number (RFC 4960 §3.3.1) — a 32-bit sequence value that wraps, so it
 * is compared with serial-number arithmetic ([sackPrecedes]), never as a plain unsigned `<`. Distinct
 * in the type system from a [VerificationTag] or a raw `UInt`.
 */
@JvmInline
public value class Tsn(
    public val value: UInt,
) {
    /** The next TSN, wrapping modulo 2³² (RFC 4960 §1.6). */
    public fun next(): Tsn = Tsn(value + 1u)

    /**
     * RFC 1982 serial-number comparison: true when `this` is "before" [other] on the circular 2³² TSN
     * space (the signed 32-bit difference is negative). Used to fold a cumulative-ack point forward
     * without treating the wrap boundary as a discontinuity.
     */
    public fun sackPrecedes(other: Tsn): Boolean = (value - other.value).toInt() < 0
}

/**
 * An SCTP stream identifier (RFC 4960 §3.3.1) — an unsigned 16-bit stream number. Wrapped so it is
 * never confused with a [StreamSequenceNumber] or a raw `Int`; the range is validated on construction.
 */
@JvmInline
public value class StreamId(
    public val value: Int,
) {
    init {
        require(value in 0..U16_MAX) { "SCTP stream id is a u16, got $value" }
    }

    public companion object {
        private const val U16_MAX = 0xFFFF
    }
}

/**
 * An SCTP Stream Sequence Number (RFC 4960 §3.3.1) — the per-stream 16-bit ordering counter carried
 * by ordered DATA and FORWARD-TSN. Wrapping, but the codec floor treats it as an opaque `UShort`.
 */
@JvmInline
public value class StreamSequenceNumber(
    public val value: UShort,
)

/**
 * The SCTP Verification Tag (RFC 4960 §3.1) — the 32-bit anti-blind-injection tag in the common
 * header, and the `Initiate Tag` an INIT/INIT-ACK advertises. A distinct type from a [Tsn].
 *
 * `@ProtocolMessage` over a scalar makes this a 4-byte FixedSize field the generated
 * [SctpCommonHeaderCodec] reads and writes directly (mirrors STUN's `StunMessageType`).
 */
@JvmInline
@ProtocolMessage(wireOrder = Endianness.Big)
public value class VerificationTag(
    public val value: UInt,
)

/**
 * The SCTP Payload Protocol Identifier (RFC 4960 §3.3.1) carried by every DATA chunk. In WebRTC it
 * discriminates the data-channel payload kind (RFC 8831 §8): DCEP control vs. UTF-8 string vs. binary,
 * with the empty-payload variants that disambiguate a zero-length application message from a
 * fragment. Opaque to the codec; the constants are the IANA "WebRTC" allocations.
 */
@JvmInline
public value class PayloadProtocolId(
    public val value: UInt,
) {
    public companion object {
        /** WebRTC DCEP control messages (RFC 8832) — [com.ditchoom.webrtc.sctp.dcep.DataChannelMessage]. */
        public val WebRtcDcep: PayloadProtocolId = PayloadProtocolId(50u)

        /** WebRTC UTF-8 string data (RFC 8831 §6.6). */
        public val WebRtcString: PayloadProtocolId = PayloadProtocolId(51u)

        /** WebRTC binary data, deprecated partial-fragment marker (RFC 8831 §6.6). */
        public val WebRtcBinaryPartial: PayloadProtocolId = PayloadProtocolId(52u)

        /** WebRTC binary data (RFC 8831 §6.6). */
        public val WebRtcBinary: PayloadProtocolId = PayloadProtocolId(53u)

        /** WebRTC UTF-8 string, deprecated partial-fragment marker (RFC 8831 §6.6). */
        public val WebRtcStringPartial: PayloadProtocolId = PayloadProtocolId(54u)

        /** WebRTC empty UTF-8 string (RFC 8831 §6.6 — an empty message that is still a string). */
        public val WebRtcStringEmpty: PayloadProtocolId = PayloadProtocolId(56u)

        /** WebRTC empty binary message (RFC 8831 §6.6). */
        public val WebRtcBinaryEmpty: PayloadProtocolId = PayloadProtocolId(57u)
    }
}

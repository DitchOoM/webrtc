package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.codec.annotations.Endianness
import com.ditchoom.buffer.codec.annotations.ProtocolMessage

/**
 * The fixed 20-byte STUN message header (RFC 8489 §5):
 *
 * ```
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |0 0|     STUN Message Type     |         Message Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Magic Cookie                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Transaction ID (96 bits)                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ```
 *
 * All four fields are FixedSize, so KSP generates a straight-line `StunHeaderCodec` (network byte
 * order). [messageLength] is the byte count of the attributes that follow — always a multiple of 4
 * (RFC 8489 §5) — and is owned/validated by the message layer ([StunMessage]), which knows the true
 * attribute extent; the header alone cannot enforce it.
 */
@ProtocolMessage(wireOrder = Endianness.Big)
public data class StunHeader(
    public val messageType: StunMessageType,
    public val messageLength: UShort,
    public val magicCookie: UInt,
    public val transactionId: TransactionId,
) {
    public companion object {
        /** Wire size of the header in bytes (RFC 8489 §5). */
        public const val SIZE_BYTES: Int = 20
    }
}

package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.codec.annotations.Endianness
import com.ditchoom.buffer.codec.annotations.ProtocolMessage

/**
 * The fixed 12-byte SCTP common header (RFC 4960 §3.1):
 *
 * ```
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Source Port Number        |     Destination Port Number   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Verification Tag                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Checksum                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ```
 *
 * All four fields are FixedSize, so KSP generates a straight-line `SctpCommonHeaderCodec` in network
 * byte order. [checksum] is the **raw 4-byte word as it sits on the wire** (network order): SCTP's
 * CRC32c (RFC 4960 §6.8 / Appendix B) is stored little-endian relative to the [Crc32c.of] value, so
 * this big-endian-read word equals the *byte-reversed* CRC32c. The reversal, the "checksum region is
 * zeroed while computing" rule, and verify/compute all live in [SctpPacket] — the header struct only
 * carries the bytes.
 */
@ProtocolMessage(wireOrder = Endianness.Big)
public data class SctpCommonHeader(
    public val sourcePort: UShort,
    public val destinationPort: UShort,
    public val verificationTag: VerificationTag,
    public val checksum: UInt,
) {
    public companion object {
        /** Wire size of the common header in bytes (RFC 4960 §3.1). */
        public const val SIZE_BYTES: Int = 12
    }
}

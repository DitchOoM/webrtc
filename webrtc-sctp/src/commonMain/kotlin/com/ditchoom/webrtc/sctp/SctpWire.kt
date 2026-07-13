package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer

// Shared wire helpers for the hand-written SCTP TLV layers (chunks, INIT/INIT-ACK parameters, ERROR
// causes). SCTP's framing — a length field that counts the 4-byte TLV header + value but NOT the
// trailing pad to a 4-byte boundary (RFC 4960 §3.2, §3.2.1) — is the same shape STUN attributes have,
// so these mirror StunMessage's helpers: absolute big-endian reads that never disturb position, and a
// zero-copy slice view.

/** SCTP's alignment boundary — every chunk, parameter, and cause is padded up to a 4-byte multiple. */
internal const val SCTP_ALIGNMENT: Int = 4

/** Bytes of the TLV header shared by chunks (type+flags+length), parameters, and causes (type+length). */
internal const val TLV_HEADER_BYTES: Int = 4

/** On-wire padded length of a [len]-byte value (RFC 4960 §3.2: pad to a 4-byte boundary). */
internal fun paddedLength(len: Int): Int = len + ((SCTP_ALIGNMENT - (len % SCTP_ALIGNMENT)) % SCTP_ALIGNMENT)

/** Big-endian absolute 8-bit read. */
internal fun ReadBuffer.u8(index: Int): Int = get(index).toInt() and 0xFF

/** Big-endian absolute 16-bit read — byte-order-independent, for the TLV walks. */
internal fun ReadBuffer.u16(index: Int): Int = (u8(index) shl Byte.SIZE_BITS) or u8(index + 1)

/** Big-endian absolute 32-bit read. */
internal fun ReadBuffer.u32(index: Int): UInt = ((u16(index).toLong() shl Short.SIZE_BITS) or u16(index + 2).toLong()).toUInt()

/**
 * A zero-copy big-endian slice view of `[start, endExclusive)` that does **not** disturb this buffer's
 * position/limit. The slice shares storage (the slice-lifetime contract applies).
 */
internal fun ReadBuffer.sliceOf(
    start: Int,
    endExclusive: Int,
): ReadBuffer {
    val savedPos = position()
    val savedLimit = limit()
    position(0)
    setLimit(endExclusive)
    position(start)
    val view = slice(ByteOrder.BIG_ENDIAN)
    position(0)
    setLimit(savedLimit)
    position(savedPos)
    return view
}

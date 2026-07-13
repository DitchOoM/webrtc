package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed

// Shared test helpers for the SCTP codec tests — buffer construction and a reference CRC32c.

/** A read-ready big-endian buffer holding the given unsigned byte values. */
internal fun bufferOf(vararg bytes: Int): PlatformBuffer {
    val buf = BufferFactory.managed().allocate(maxOf(1, bytes.size), ByteOrder.BIG_ENDIAN)
    for (b in bytes) buf.writeByte(b.toByte())
    buf.resetForRead()
    buf.setLimit(bytes.size)
    return buf
}

/** A read-ready big-endian buffer holding the bytes of a lowercase hex string. */
internal fun bufferOfHex(hex: String): PlatformBuffer {
    val clean = hex.filterNot { it == ' ' || it == '\n' }
    val n = clean.length / 2
    val buf = BufferFactory.managed().allocate(maxOf(1, n), ByteOrder.BIG_ENDIAN)
    for (i in 0 until n) buf.writeByte(clean.substring(i * 2, i * 2 + 2).toInt(16).toByte())
    buf.resetForRead()
    buf.setLimit(n)
    return buf
}

/** A read-ready buffer holding the given bytes, exposed only as a non-zero-offset slice view. */
internal fun sliceWithOffset(
    bytes: List<Int>,
    leadingPad: Int,
): ReadBuffer {
    val backing = BufferFactory.managed().allocate(leadingPad + bytes.size, ByteOrder.BIG_ENDIAN)
    repeat(leadingPad) { backing.writeByte(0x7F) }
    for (b in bytes) backing.writeByte(b.toByte())
    backing.resetForRead()
    backing.position(leadingPad)
    return backing.slice()
}

/** A read-only ByteArray-free copy of a buffer's remaining bytes as an Int list (for equality checks). */
internal fun ReadBuffer.toIntList(): List<Int> {
    val out = ArrayList<Int>(remaining())
    for (i in position() until limit()) out += get(i).toInt() and 0xFF
    return out
}

/**
 * A reference CRC32c computed the naive bitwise way (reflected, poly 0x82F63B78, init/xorout
 * 0xFFFFFFFF) — an independent second implementation the table-driven [Crc32c] is cross-checked
 * against. Deliberately allocation-tolerant and slow; it only runs in tests.
 */
internal fun referenceCrc32c(bytes: List<Int>): UInt {
    var crc = -1
    for (b in bytes) {
        crc = crc xor (b and 0xFF)
        repeat(8) {
            crc = if (crc and 1 != 0) (crc ushr 1) xor 0x82F63B78.toInt() else crc ushr 1
        }
    }
    return crc.inv().toUInt()
}

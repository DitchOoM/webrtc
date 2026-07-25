package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
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
 * A buffer's remaining bytes as a lowercase hex string — the inverse of [bufferOfHex], and the readable
 * form for pinning a wire layout: an expected-byte assertion written as hex stays one line per logical
 * field instead of one line per byte (which is what an `Int` list degrades into under ktlint's
 * argument-list wrapping). Does not disturb this buffer's position.
 *
 * Uses buffer's own `ReadBuffer.encodeHexInto` rather than a per-byte format loop: that is the bulk
 * path (word-at-a-time in common, a single C transform over raw pointers on the native backends), and
 * a per-byte loop here is the pattern this library exists to avoid — test helpers get copied.
 *
 * The destination buffer is buffer's API shape, not an accident: `encodeHexInto` writes ASCII hex
 * *into a WriteBuffer* and buffer exposes no `ReadBuffer` → hex-`String` form, so a `String` result has
 * to be read back out of one. Worth a small upstream addition; until then this is the honest cost.
 */
internal fun ReadBuffer.toHex(): String {
    val n = remaining()
    if (n == 0) return ""
    val hex = BufferFactory.managed().allocate(n * 2, ByteOrder.BIG_ENDIAN)
    encodeHexInto(hex, position(), n)
    hex.resetForRead()
    hex.setLimit(n * 2)
    return hex.readString(n * 2, Charset.UTF8)
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

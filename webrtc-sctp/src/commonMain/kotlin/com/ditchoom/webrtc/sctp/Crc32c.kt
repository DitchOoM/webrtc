package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed

/**
 * CRC32c (Castagnoli) — the SCTP packet checksum (RFC 4960 §6.8, defined by RFC 3309).
 *
 * This is **not** the CRC-32 that `ReadBuffer.crc32` (buffer core, used by STUN FINGERPRINT) computes:
 * SCTP uses the Castagnoli polynomial `0x1EDC6F41` (reversed `0x82F63B78`), reflected input and
 * output, init/xorout `0xFFFFFFFF`. Its check value over the ASCII string "123456789" is `0xE3069283`
 * (the iSCSI/RFC 3720 known answer). [Crc32c.of] returns that final value directly.
 *
 * The 256-entry lookup table is built once into a **shared read-only managed [ReadBuffer]** (one
 * 32-bit word per entry), exactly as buffer's own `CRC32_TABLE` does — a primitive `IntArray` table is
 * forbidden in production sources (directive #1). The covered spans here are small (an SCTP datagram
 * is ≤ the DTLS record size), so a common per-byte table walk keeps every buffer implementation on one
 * path; a native-accelerated bulk CRC32c belongs upstream in buffer core (the `crc32` precedent) if a
 * hot path ever demands it — see PERFORMANCE.md.
 *
 * The SCTP checksum is placed in the packet as the little-endian encoding of this value (RFC 4960
 * Appendix B): [SctpPacket] owns that field placement and the "checksum region is zeroed while
 * computing" rule; this file owns only the arithmetic.
 */
public object Crc32c {
    /** Castagnoli polynomial in reversed (LSB-first) bit order — the reflected form the table walk uses. */
    private const val REVERSED_POLYNOMIAL: Int = 0x82F63B78.toInt()

    private const val TABLE_BITS = 8
    private const val ENTRY_BYTES = 4
    private const val TABLE_ENTRIES = 1 shl TABLE_BITS
    private const val BYTE_MASK = 0xFF
    private const val BYTE_BITS = 8

    /** Shift landing the most-significant byte of a big-endian word (byte at the lowest address). */
    private const val WORD_HIGH_BYTE_SHIFT = 56

    /**
     * 256-entry table, entry `i` at absolute byte offset `i * ENTRY_BYTES` — a managed buffer, not an
     * `IntArray` (directive #1). Mirrors buffer's `CRC32_TABLE`, only the polynomial differs.
     */
    private val table: ReadBuffer =
        BufferFactory.managed().allocate(TABLE_ENTRIES * ENTRY_BYTES, ByteOrder.BIG_ENDIAN).apply {
            for (n in 0 until TABLE_ENTRIES) {
                var c = n
                repeat(TABLE_BITS) {
                    c = if (c and 1 != 0) REVERSED_POLYNOMIAL xor (c ushr 1) else c ushr 1
                }
                set(n * ENTRY_BYTES, c)
            }
        }

    /** Folds one input byte [b] into the running [crc]. */
    private fun step(
        crc: Int,
        b: Int,
    ): Int = table.getInt(((crc xor b) and BYTE_MASK) * ENTRY_BYTES) xor (crc ushr TABLE_BITS)

    /** The CRC32c initial register value (`0xFFFFFFFF`). Seed an incremental fold with this. */
    public const val INIT: Int = -1

    /**
     * CRC32c over the absolute byte range `[offset, offset + length)` of [source]. Does not change
     * [source]'s position. The caller is responsible for `[offset, offset + length)` lying within the
     * buffer. Equivalent to `finalize(update(INIT, source, offset, length))`.
     */
    public fun of(
        source: ReadBuffer,
        offset: Int,
        length: Int,
    ): UInt = finalize(update(INIT, source, offset, length))

    /**
     * Folds `[offset, offset + length)` of [source] into the running register [crc] and returns the
     * new **un-finalized** register — for CRCs that span several discontiguous spans (SCTP feeds the
     * bytes before the checksum field, four zero bytes, then the bytes after, so the datagram is never
     * mutated). Seed the first call with [INIT] and pass the result to [finalize].
     *
     * The input is consumed in bulk 8-byte words (one [getLong][ReadBuffer.getLong] per 8 bytes, byte
     * tail last) — the same shape as buffer's own `ReadBuffer.crc32`, so the per-byte `get()` virtual
     * call and bounds check happen once per word instead of once per byte. The *table fold* stays
     * per-byte: intrinsic to a 256-entry-table CRC, not an extra pass. The value is byte-order-
     * independent (a per-byte checksum) even though the bulk read is not — the word is decomposed into
     * its bytes in ascending address order, which depends on [byteOrder].
     */
    public fun update(
        crc: Int,
        source: ReadBuffer,
        offset: Int,
        length: Int,
    ): Int {
        var c = crc
        var i = 0
        val bulkEnd = length - Long.SIZE_BYTES
        if (source.byteOrder == ByteOrder.BIG_ENDIAN) {
            while (i <= bulkEnd) {
                val w = source.getLong(offset + i)
                var shift = WORD_HIGH_BYTE_SHIFT
                while (shift >= 0) {
                    c = step(c, (w ushr shift).toInt() and BYTE_MASK)
                    shift -= BYTE_BITS
                }
                i += Long.SIZE_BYTES
            }
        } else {
            while (i <= bulkEnd) {
                val w = source.getLong(offset + i)
                var shift = 0
                while (shift <= WORD_HIGH_BYTE_SHIFT) {
                    c = step(c, (w ushr shift).toInt() and BYTE_MASK)
                    shift += BYTE_BITS
                }
                i += Long.SIZE_BYTES
            }
        }
        while (i < length) {
            c = step(c, source.get(offset + i).toInt() and BYTE_MASK)
            i++
        }
        return c
    }

    /** Applies the CRC32c output reflection/complement (`xorout 0xFFFFFFFF`) to a running register. */
    public fun finalize(crc: Int): UInt = crc.inv().toUInt()
}

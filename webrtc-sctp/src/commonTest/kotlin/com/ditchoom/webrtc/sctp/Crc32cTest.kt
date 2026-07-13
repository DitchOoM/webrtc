package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.managed
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * CRC32c (Castagnoli) conformance — the SCTP checksum arithmetic (RFC 4960 §6.8 / RFC 3309).
 *
 * Two independent anchors: the published check value `0xE3069283` for the ASCII string "123456789"
 * (the iSCSI/RFC 3720 known answer), and a cross-check against [referenceCrc32c] — a naive bitwise
 * implementation in the test — over 5000 random buffers of random length. If the table-driven
 * production [Crc32c] and the bitwise reference agree on thousands of random inputs, the table and the
 * word-batched bulk read are almost certainly correct.
 */
class Crc32cTest {
    @Test
    fun knownAnswerForCheckString() {
        val data = "123456789"
        val buf = BufferFactory.managed().allocate(data.length, ByteOrder.BIG_ENDIAN)
        buf.writeString(data)
        buf.resetForRead()
        assertEquals(0xE3069283u, Crc32c.of(buf, 0, data.length))
    }

    @Test
    fun emptyInputIsZero() {
        // init 0xFFFFFFFF, no bytes folded, xorout 0xFFFFFFFF → 0.
        assertEquals(0u, Crc32c.of(bufferOf(), 0, 0))
    }

    @Test
    fun matchesBitwiseReferenceOverRandomBuffers() {
        val random = Random(0x5C7C_C12Cu.toInt())
        repeat(5000) {
            val n = random.nextInt(0, 300)
            val bytes = List(n) { random.nextInt(0, 256) }
            val buf = BufferFactory.managed().allocate(maxOf(1, n), ByteOrder.BIG_ENDIAN)
            for (b in bytes) buf.writeByte(b.toByte())
            buf.resetForRead()
            buf.setLimit(n)
            assertEquals(referenceCrc32c(bytes), Crc32c.of(buf, 0, n), "mismatch at length $n")
        }
    }

    @Test
    fun bulkAndTailPathsAgreeAcrossEveryLengthTo64() {
        // Lengths straddling the 8-byte bulk boundary exercise the word loop + byte tail split.
        val random = Random(99)
        for (n in 0..64) {
            val bytes = List(n) { random.nextInt(0, 256) }
            val buf = BufferFactory.managed().allocate(maxOf(1, n), ByteOrder.BIG_ENDIAN)
            for (b in bytes) buf.writeByte(b.toByte())
            buf.resetForRead()
            buf.setLimit(n)
            assertEquals(referenceCrc32c(bytes), Crc32c.of(buf, 0, n), "mismatch at length $n")
        }
    }

    @Test
    fun offsetRegionIsChecksummedIndependentlyOfSurroundingBytes() {
        // The same 5-byte region at offset 3 must checksum identically regardless of neighbor bytes.
        val region = listOf(0x11, 0x22, 0x33, 0x44, 0x55)
        val a = BufferFactory.managed().allocate(16, ByteOrder.BIG_ENDIAN)
        repeat(3) { a.writeByte(0x00) }
        for (b in region) a.writeByte(b.toByte())
        repeat(8) { a.writeByte(0xAB.toByte()) }
        a.resetForRead()
        assertEquals(referenceCrc32c(region), Crc32c.of(a, 3, region.size))
    }
}

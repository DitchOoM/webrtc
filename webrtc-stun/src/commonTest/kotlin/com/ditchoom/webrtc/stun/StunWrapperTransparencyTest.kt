package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.pool.BufferPool
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Wrapper-transparency (RFC §7 / TESTING.md §4): the codec must work when handed a buffer wrapper —
 * a pooled buffer, or a slice view over a larger datagram at a non-zero offset — not only a raw
 * `PlatformBuffer` at offset 0. This guards the absolute-offset arithmetic in the TLV walk and the
 * in-place integrity checks against a hidden "position 0 == storage 0" assumption.
 */
class StunWrapperTransparencyTest {
    private val password = ascii("VOkJxbRl1RmTxUk/WvJxBt")
    private val request =
        "000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74" +
            "002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020000800149a" +
            "eaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf"

    @Test
    fun decodesAndVerifiesFromAPooledBuffer() {
        val n = request.length / 2
        val pool = BufferPool(factory = BufferFactory.Default)
        val buf = pool.allocate(n, ByteOrder.BIG_ENDIAN)
        writeHex(buf, request)
        buf.resetForRead()
        buf.setLimit(n)
        verify(buf)
    }

    @Test
    fun decodesAndVerifiesFromASliceAtNonZeroOffset() {
        val n = request.length / 2
        val prefix = 8 // pretend the datagram sits after an 8-byte demux/header region
        val backing = BufferFactory.Default.allocate(prefix + n, ByteOrder.BIG_ENDIAN)
        repeat(prefix) { backing.writeByte(0x55) }
        writeHex(backing, request)
        backing.resetForRead()
        backing.position(prefix)
        val view = backing.slice(ByteOrder.BIG_ENDIAN) // position 0 of the view == storage offset `prefix`
        verify(view)
    }

    private fun verify(buf: ReadBuffer) {
        val r = StunMessage.decode(buf)
        assertTrue(r is StunDecodeResult.Success, "expected Success from a wrapped buffer, got $r")
        assertTrue(r.message.verifyFingerprint(), "FINGERPRINT must verify through the wrapper")
        assertTrue(r.message.verifyMessageIntegrity(password), "MESSAGE-INTEGRITY must verify through the wrapper")
    }

    private fun writeHex(
        buf: com.ditchoom.buffer.WriteBuffer,
        hex: String,
    ) {
        for (i in 0 until hex.length / 2) buf.writeByte(hex.substring(i * 2, i * 2 + 2).toInt(16).toByte())
    }

    private fun ascii(text: String): ReadBuffer {
        val b = BufferFactory.Default.allocate(text.length, ByteOrder.BIG_ENDIAN)
        b.writeString(text, Charset.UTF8)
        b.resetForRead()
        return b
    }
}

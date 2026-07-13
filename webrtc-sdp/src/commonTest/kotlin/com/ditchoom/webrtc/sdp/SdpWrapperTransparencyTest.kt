package com.ditchoom.webrtc.sdp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.pool.BufferPool
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * Wrapper-transparency (RFC §7 / TESTING.md §4): the parser must work when handed a buffer wrapper —
 * a pooled buffer, or a slice view over a larger datagram at a non-zero offset — not only a raw
 * `PlatformBuffer` at offset 0. SDP reads from `position()` to `limit()`, so this guards that the
 * single UTF-8 decode honors a non-zero start and a wrapper's own remaining-length accounting.
 */
class SdpWrapperTransparencyTest {
    private val vector = SdpTestVectors.chromeDataChannelOffer

    @Test
    fun parsesFromAPooledBuffer() {
        val bytes = vector.encodeToByteArray()
        val pool = BufferPool(factory = BufferFactory.Default)
        val buf = pool.allocate(bytes.size, ByteOrder.BIG_ENDIAN)
        buf.writeString(vector, Charset.UTF8)
        buf.resetForRead()
        buf.setLimit(bytes.size)
        assertRoundTrips(buf)
    }

    @Test
    fun parsesFromASliceAtNonZeroOffset() {
        val bytes = vector.encodeToByteArray()
        val prefix = 8 // pretend the SDP sits after an 8-byte framing region
        val backing = BufferFactory.Default.allocate(prefix + bytes.size, ByteOrder.BIG_ENDIAN)
        repeat(prefix) { backing.writeByte(0x55) }
        backing.writeString(vector, Charset.UTF8)
        backing.resetForRead()
        backing.position(prefix)
        val view = backing.slice(ByteOrder.BIG_ENDIAN) // position 0 of the view == storage offset `prefix`
        assertRoundTrips(view)
    }

    private fun assertRoundTrips(buf: ReadBuffer) {
        val r = SessionDescription.parse(buf)
        assertIs<SdpParseResult.Success>(r, "expected Success from a wrapped buffer, got $r")
        assertEquals(vector, r.description.toText(), "round-trip must hold through the wrapper")
        assertEquals(
            Mid("0"),
            r.description.mediaDescriptions
                .single()
                .mid(),
        )
    }
}

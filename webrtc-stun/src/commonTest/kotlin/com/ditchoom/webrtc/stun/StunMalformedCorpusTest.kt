package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * T0 floor (RFC §7): a hostile or truncated datagram must yield a **typed** [StunDecodeResult.Reject],
 * never a throw-through or a crash. The committed cases pin specific reject reasons; the seeded
 * property loop asserts the stronger invariant — decode is total (Success or Reject) over arbitrary
 * bytes, on every platform.
 */
class StunMalformedCorpusTest {
    @Test
    fun emptyIsRejected() {
        assertIs<StunRejectReason.ShorterThanHeader>(reject(fill(bytes())))
    }

    @Test
    fun shorterThanHeaderIsRejected() {
        assertIs<StunRejectReason.ShorterThanHeader>(reject(fill(bytes(0x00, 0x01, 0x00, 0x00))))
    }

    @Test
    fun leadingBitsSetIsNotStun() {
        // First byte 0xC0 → the two leading type bits are set (RFC 8489 §5): not a STUN message.
        val b = bytes(0xC0, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42) + zeros(12)
        assertIs<StunRejectReason.NotStunMethod>(reject(fill(b)))
    }

    @Test
    fun badMagicCookieIsRejected() {
        val b = bytes(0x00, 0x01, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF) + zeros(12)
        assertIs<StunRejectReason.BadMagicCookie>(reject(fill(b)))
    }

    @Test
    fun unalignedLengthIsRejected() {
        val b = bytes(0x00, 0x01, 0x00, 0x03, 0x21, 0x12, 0xA4, 0x42) + zeros(12) + bytes(0, 0, 0)
        assertIs<StunRejectReason.LengthNotAligned>(reject(fill(b)))
    }

    @Test
    fun lengthBeyondDatagramIsTruncated() {
        // Claims 8 attribute bytes but supplies none.
        val b = bytes(0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xA4, 0x42) + zeros(12)
        assertIs<StunRejectReason.Truncated>(reject(fill(b)))
    }

    @Test
    fun attributeLengthOverflowIsMalformed() {
        // One attribute claiming length 0xFFFF inside a 8-byte attribute region.
        val b =
            bytes(0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xA4, 0x42) + zeros(12) +
                bytes(0x00, 0x06, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00)
        assertIs<StunRejectReason.MalformedAttribute>(reject(fill(b)))
    }

    @Test
    fun decodeIsTotalOverArbitraryBytes() {
        // The core T0 invariant: no input makes decode throw. Seeded, so a failure reproduces.
        val random = Random(0xC0FFEE)
        repeat(20_000) {
            val n = random.nextInt(0, 256)
            val buf = BufferFactory.Default.allocate(maxOf(1, n), ByteOrder.BIG_ENDIAN)
            repeat(n) { buf.writeByte(random.nextInt().toByte()) }
            buf.resetForRead()
            buf.setLimit(n)
            // Must return a value (never throw); we only assert totality here.
            val result = StunMessage.decode(buf)
            assertTrue(result is StunDecodeResult.Success || result is StunDecodeResult.Reject)
        }
    }

    @Test
    fun everySingleByteMutationOfAValidMessageStaysTotal() {
        // Flip each byte of the RFC 5769 request through several values; decode must never throw and
        // any Success must still re-encode without error.
        val valid = requestBytes()
        for (i in 0 until valid.size) {
            for (delta in intArrayOf(1, 0x40, 0x80, 0xFF)) {
                val mutated = valid.copyOf()
                mutated[i] = (mutated[i].toInt() xor delta).toByte()
                val buf = fill(mutated.toList())
                when (val r = StunMessage.decode(buf)) {
                    is StunDecodeResult.Success -> r.message.encode() // must not throw
                    is StunDecodeResult.Reject -> {} // typed reject is fine
                }
            }
        }
    }

    private fun reject(buf: PlatformBuffer): StunRejectReason {
        val r = StunMessage.decode(buf)
        assertIs<StunDecodeResult.Reject>(r)
        return r.reason
    }

    private fun bytes(vararg b: Int): List<Byte> = b.map { it.toByte() }

    private fun zeros(n: Int): List<Byte> = List(n) { 0 }

    private fun fill(b: List<Byte>): PlatformBuffer {
        val buf = BufferFactory.Default.allocate(maxOf(1, b.size), ByteOrder.BIG_ENDIAN)
        for (x in b) buf.writeByte(x)
        buf.resetForRead()
        buf.setLimit(b.size)
        return buf
    }

    private fun requestBytes(): ByteArray {
        val hex =
            "000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74" +
                "002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020000800149a" +
                "eaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf"
        return ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    @Test
    fun nonUtf8TextAttributeReturnsNullNeverThrows() {
        // Jazzer regression (seed regression-nonutf8-software.bin): a SOFTWARE attribute whose bytes
        // are not valid UTF-8 must make asText() a typed miss (null), not throw MalformedInputException.
        val software = RawAttribute.ofValue(StunAttributeType.Software, fill(bytes(0xFF, 0xFE, 0x00, 0x80)))
        assertEquals(null, software.asText())
        // And a valid one still decodes.
        assertEquals("ok", RawAttribute.ofText(StunAttributeType.Software, "ok").asText())
    }

    @Test
    fun integrityAttributesWithNonConformingLengthVerifyFalseNeverThrow() {
        // Jazzer regression (seed regression-short-integrity-len.bin): a MESSAGE-INTEGRITY declared
        // shorter than 20 bytes (or FINGERPRINT shorter than 4) must make verification return false,
        // not read past the datagram.
        val cookie = listOf(0x21, 0x12, 0xA4, 0x42).map { it.toByte() }
        val txId = zeros(12)

        // MESSAGE-INTEGRITY (0x0008) with declared length 4 (not 20), at the end of the message.
        val shortMi = bytes(0x01, 0x01, 0x00, 0x08) + cookie + txId + bytes(0x00, 0x08, 0x00, 0x04, 0, 0, 0, 0)
        val miMsg = (StunMessage.decode(fill(shortMi)) as StunDecodeResult.Success).message
        assertTrue(!miMsg.verifyMessageIntegrity(emptyKey()))

        // FINGERPRINT (0x8028) with declared length 0 (not 4), at the end of the message.
        val shortFp = bytes(0x01, 0x01, 0x00, 0x04) + cookie + txId + bytes(0x80, 0x28, 0x00, 0x00)
        val fpMsg = (StunMessage.decode(fill(shortFp)) as StunDecodeResult.Success).message
        assertTrue(!fpMsg.verifyFingerprint())
    }

    private fun emptyKey() = fill(bytes(0x6B, 0x65, 0x79)) // "key"

    @Test
    fun sanityRejectReasonEqualityIsTyped() {
        // Reasons are values (typed discriminants), not strings.
        assertEquals(StunRejectReason.ShorterThanHeader, StunRejectReason.ShorterThanHeader)
    }
}

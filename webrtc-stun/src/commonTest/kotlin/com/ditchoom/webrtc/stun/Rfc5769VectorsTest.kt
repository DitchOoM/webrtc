package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * RFC 5769 sample vectors — the interop-grade T0 corpus (TESTING.md §3). Each is decoded, its
 * MESSAGE-INTEGRITY (HMAC-SHA1) and FINGERPRINT (CRC-32) recomputed in place and checked against the
 * wire, its XOR-MAPPED-ADDRESS un-XOR'd, and the message re-encoded byte-for-byte. The long-term
 * §2.4 vector is out of scope in W1 (its key is MD5(username:realm:password); buffer-crypto has no
 * MD5 yet — tracked for a follow-up).
 */
class Rfc5769VectorsTest {
    private val password = "VOkJxbRl1RmTxUk/WvJxBt"

    // b7e7a701 bc34d686 fa87dfae — shared by all three vectors.
    private val txId = TransactionId(0xB7E7A701u, 0xBC34D686u, 0xFA87DFAEu)

    private val request =
        "000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74" +
            "002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020000800149a" +
            "eaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf"

    private val ipv4Response =
        "0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000080001a1" +
            "47e112a643000800142b91f599fd9e90c38c7489f92af9ba53f06be7d780280004c07d4c96"

    private val ipv6Response =
        "010100482112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000140002a1" +
            "470113a9faa5d3f179bc25f4b5bed2b9d900080014a382954e4be67bf11784c97c8292c275bfe3ed4180" +
            "280004c8fb0b4c"

    @Test
    fun sampleRequest() {
        val msg = decoded(request)
        assertEquals(StunClass.Request, msg.messageType.stunClass)
        assertEquals(StunMethod.Binding, msg.messageType.method)
        assertEquals(txId, msg.transactionId)
        assertEquals(Stun.MAGIC_COOKIE, msg.header.magicCookie)
        assertEquals("STUN test client", msg.firstOrNull(StunAttributeType.Software)?.asText())
        assertEquals("evtj:h6vY", msg.firstOrNull(StunAttributeType.Username)?.asText())
        assertTrue(msg.verifyFingerprint(), "FINGERPRINT (CRC-32) must verify")
        assertTrue(msg.verifyMessageIntegrity(ascii(password)), "MESSAGE-INTEGRITY (HMAC-SHA1) must verify")
        assertRoundTrips(request, msg)
    }

    @Test
    fun sampleIpv4Response() {
        val msg = decoded(ipv4Response)
        assertEquals(StunClass.SuccessResponse, msg.messageType.stunClass)
        assertEquals("test vector", msg.firstOrNull(StunAttributeType.Software)?.asText())
        assertTrue(msg.verifyFingerprint())
        assertTrue(msg.verifyMessageIntegrity(ascii(password)))

        val mapped = msg.firstOrNull(StunAttributeType.XorMappedAddress)?.asXorMappedAddress(msg.transactionId)
        assertNotNull(mapped)
        assertEquals("192.0.2.1", (mapped.ip as IpAddress.V4).toString())
        assertEquals(32853u.toUShort(), mapped.port)
        assertRoundTrips(ipv4Response, msg)
    }

    @Test
    fun sampleIpv6Response() {
        val msg = decoded(ipv6Response)
        assertEquals(StunClass.SuccessResponse, msg.messageType.stunClass)
        assertTrue(msg.verifyFingerprint())
        assertTrue(msg.verifyMessageIntegrity(ascii(password)))

        val mapped = msg.firstOrNull(StunAttributeType.XorMappedAddress)?.asXorMappedAddress(msg.transactionId)
        assertNotNull(mapped)
        val v6 = mapped.ip as IpAddress.V6
        // 2001:0db8:1234:5678:0011:2233:4455:6677
        assertEquals(0x20010db812345678uL, v6.hi)
        assertEquals(0x0011223344556677uL, v6.lo)
        assertEquals(32853u.toUShort(), mapped.port)
        assertRoundTrips(ipv6Response, msg)
    }

    @Test
    fun tamperedMessageIntegrityFailsClosed() {
        // Flip one byte inside the MESSAGE-INTEGRITY value: verification must fail, never throw.
        val bytes = bufferOfHex(ipv4Response)
        val miValueStart = ipv4Response.length / 2 - 4 - 20 // FINGERPRINT(8) precedes; MI value before it
        bytes.set(miValueStart, (bytes.get(miValueStart) + 1).toByte())
        val decoded = StunMessage.decode(bytes)
        assertTrue(decoded is StunDecodeResult.Success)
        assertTrue(!decoded.message.verifyMessageIntegrity(ascii(password)))
    }

    private fun decoded(hex: String): StunMessage {
        val result = StunMessage.decode(bufferOfHex(hex))
        assertTrue(result is StunDecodeResult.Success, "expected Success, got $result")
        return result.message
    }

    private fun assertRoundTrips(
        hex: String,
        msg: StunMessage,
    ) {
        val encoded = msg.encode()
        val original = bufferOfHex(hex)
        assertTrue(original.contentEquals(encoded), "re-encoded message must be byte-identical to the wire form")
    }

    private fun ascii(text: String): ReadBuffer {
        val buf = BufferFactory.Default.allocate(text.length, ByteOrder.BIG_ENDIAN)
        buf.writeString(text, Charset.UTF8)
        buf.resetForRead()
        return buf
    }

    private fun bufferOfHex(hex: String): PlatformBuffer {
        val n = hex.length / 2
        val buf = BufferFactory.Default.allocate(n, ByteOrder.BIG_ENDIAN)
        for (i in 0 until n) {
            buf.writeByte(hex.substring(i * 2, i * 2 + 2).toInt(HEX_RADIX).toByte())
        }
        buf.resetForRead()
        return buf
    }

    private companion object {
        const val HEX_RADIX = 16
    }
}

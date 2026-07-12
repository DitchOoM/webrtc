package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Builds messages with [StunMessageBuilder], encodes, decodes, and checks the values survive. */
class StunEncodeRoundTripTest {
    private val key = ascii("a-short-term-credential")

    @Test
    fun bindingRequestWithIntegrityAndFingerprintVerifies() {
        val txId = TransactionId(0x01020304u, 0x05060708u, 0x090A0B0Cu)
        val encoded =
            StunMessageBuilder
                .of(StunClass.Request, StunMethod.Binding, txId)
                .add(RawAttribute.ofText(StunAttributeType.Software, "webrtc-stun/0.0"))
                .add(RawAttribute.ofText(StunAttributeType.Username, "alice:bob"))
                .addMessageIntegrity(key)
                .addFingerprint()
                .encode()

        val msg = success(encoded)
        assertEquals(txId, msg.transactionId)
        assertEquals(StunMethod.Binding, msg.messageType.method)
        assertTrue(msg.verifyFingerprint())
        assertTrue(msg.verifyMessageIntegrity(key))
        assertTrue(!msg.verifyMessageIntegrity(ascii("wrong-key")))
    }

    @Test
    fun messageIntegritySha256Verifies() {
        val txId = TransactionId(0xFEEDu, 0xF00Du, 0xCAFEu)
        val encoded =
            StunMessageBuilder
                .of(StunClass.Request, StunMethod.Binding, txId)
                .add(RawAttribute.ofText(StunAttributeType.Username, "alice"))
                .addMessageIntegritySha256(key)
                .addFingerprint()
                .encode()
        val msg = success(encoded)
        assertTrue(msg.verifyMessageIntegritySha256(key))
        assertTrue(!msg.verifyMessageIntegritySha256(ascii("wrong-key")))
        assertTrue(msg.verifyFingerprint())
    }

    @Test
    fun messageIntegritySha256TruncatedVerifies() {
        // RFC 8489 §14.6 truncation: a 16-byte tag must verify (exercises the truncated length-rewrite).
        val txId = TransactionId(7u, 8u, 9u)
        val encoded =
            StunMessageBuilder
                .of(StunClass.Request, StunMethod.Binding, txId)
                .add(RawAttribute.ofText(StunAttributeType.Username, "carol"))
                .addMessageIntegritySha256(key, tagLengthBytes = 16)
                .encode()
        val msg = success(encoded)
        assertEquals(16, msg.firstOrNull(StunAttributeType.MessageIntegritySha256)?.length)
        assertTrue(msg.verifyMessageIntegritySha256(key))
        assertTrue(!msg.verifyMessageIntegritySha256(ascii("wrong-key")))
    }

    @Test
    fun builderRejectsIntegrityAfterFingerprint() {
        val b = StunMessageBuilder.of(StunClass.Request, StunMethod.Binding, TransactionId(1u, 2u, 3u)).addFingerprint()
        assertFailsWith<IllegalArgumentException> { b.addMessageIntegrity(key) }
        assertFailsWith<IllegalArgumentException> { b.addMessageIntegritySha256(key) }
    }

    @Test
    fun builderRejectsOutOfRangeSha256TagLength() {
        val b = StunMessageBuilder.of(StunClass.Request, StunMethod.Binding, TransactionId(1u, 2u, 3u))
        assertFailsWith<IllegalArgumentException> { b.addMessageIntegritySha256(key, tagLengthBytes = 18) } // not %4
        assertFailsWith<IllegalArgumentException> { b.addMessageIntegritySha256(key, tagLengthBytes = 12) } // < 16
        assertFailsWith<IllegalArgumentException> { b.addMessageIntegritySha256(key, tagLengthBytes = 36) } // > 32
    }

    @Test
    fun bothMessageIntegritiesVerifyTogether() {
        // RFC 8489: MESSAGE-INTEGRITY then MESSAGE-INTEGRITY-SHA256 then FINGERPRINT — all must verify.
        val txId = TransactionId(1u, 2u, 3u)
        val encoded =
            StunMessageBuilder
                .of(StunClass.Request, StunMethod.Binding, txId)
                .add(RawAttribute.ofText(StunAttributeType.Username, "bob"))
                .addMessageIntegrity(key)
                .addMessageIntegritySha256(key)
                .addFingerprint()
                .encode()
        val msg = success(encoded)
        assertTrue(msg.verifyMessageIntegrity(key), "HMAC-SHA1 MI must verify")
        assertTrue(msg.verifyMessageIntegritySha256(key), "HMAC-SHA256 MI must verify")
        assertTrue(msg.verifyFingerprint(), "FINGERPRINT must verify")
    }

    @Test
    fun ipv4XorMappedAddressRoundTrips() {
        val txId = TransactionId(0xAABBCCDDu, 0x11223344u, 0x55667788u)
        val address = TransportAddress(IpAddress.V4(0xC0A80101u), 40000u) // 192.168.1.1:40000
        val encoded =
            StunMessageBuilder
                .of(StunClass.SuccessResponse, StunMethod.Binding, txId)
                .add(RawAttribute.ofXorMappedAddress(address, txId))
                .addFingerprint()
                .encode()

        val decoded = success(encoded).firstOrNull(StunAttributeType.XorMappedAddress)?.asXorMappedAddress(txId)
        assertEquals(address, decoded)
    }

    @Test
    fun ipv6XorMappedAddressRoundTrips() {
        val txId = TransactionId(0xB7E7A701u, 0xBC34D686u, 0xFA87DFAEu)
        val address = TransportAddress(IpAddress.V6(0x20010DB812345678uL, 0x0011223344556677uL), 0x9112u)
        val encoded =
            StunMessageBuilder
                .of(StunClass.SuccessResponse, StunMethod.Binding, txId)
                .add(RawAttribute.ofXorMappedAddress(address, txId))
                .encode()
        assertEquals(address, success(encoded).firstOrNull(StunAttributeType.XorMappedAddress)?.asXorMappedAddress(txId))
    }

    @Test
    fun errorCodeRoundTrips() {
        val txId = TransactionId(1u, 2u, 3u)
        val encoded =
            StunMessageBuilder
                .of(StunClass.ErrorResponse, StunMethod.Binding, txId)
                .add(RawAttribute.ofErrorCode(StunErrorCode(401, "Unauthorized")))
                .encode()
        val error = success(encoded).firstOrNull(StunAttributeType.ErrorCode)?.asErrorCode()
        assertNotNull(error)
        assertEquals(401, error.code)
        assertEquals("Unauthorized", error.reason)
    }

    @Test
    fun mappedAddressPlaintextRoundTrips() {
        val txId = TransactionId(9u, 9u, 9u)
        val address = TransportAddress(IpAddress.V4(0x08080808u), 53u) // 8.8.8.8:53
        val encoded =
            StunMessageBuilder
                .of(StunClass.SuccessResponse, StunMethod.Binding, txId)
                .add(RawAttribute.ofMappedAddress(address))
                .encode()
        assertEquals(address, success(encoded).firstOrNull(StunAttributeType.MappedAddress)?.asTransportAddress())
    }

    @Test
    fun propertyRandomMessagesRoundTripAndVerify() {
        val random = Random(0x5EED)
        repeat(500) {
            val txId = TransactionId(random.nextInt().toUInt(), random.nextInt().toUInt(), random.nextInt().toUInt())
            val builder = StunMessageBuilder.of(StunClass.entries.random(random), StunMethod.Binding, txId)
            // A random spread of text attributes of varied lengths (exercises padding: 0..3).
            repeat(random.nextInt(0, 4)) {
                builder.add(RawAttribute.ofText(StunAttributeType.Software, "x".repeat(random.nextInt(0, 17))))
            }
            builder.addMessageIntegrity(key).addFingerprint()
            val msg = success(builder.encode())
            assertTrue(msg.verifyFingerprint())
            assertTrue(msg.verifyMessageIntegrity(key))
            assertEquals(txId, msg.transactionId)
        }
    }

    private fun success(encoded: ReadBuffer): StunMessage {
        val r = StunMessage.decode(encoded)
        assertTrue(r is StunDecodeResult.Success, "expected Success, got $r")
        return r.message
    }

    private fun ascii(text: String): ReadBuffer {
        val b = BufferFactory.Default.allocate(text.length, ByteOrder.BIG_ENDIAN)
        b.writeString(text, Charset.UTF8)
        b.resetForRead()
        return b
    }
}

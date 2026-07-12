package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Codec-only TURN (RFC 8656) attributes, UNKNOWN-ATTRIBUTES, and the 420 helper. */
class StunTurnAndExtrasTest {
    private val txId = TransactionId(0x11u, 0x22u, 0x33u)

    @Test
    fun lifetimeRoundTrips() {
        val a = RawAttribute.ofLifetime(600u)
        assertEquals(StunAttributeType.Lifetime, a.type)
        assertEquals(600u, roundTrip(a).asLifetimeSeconds())
    }

    @Test
    fun requestedTransportRoundTrips() {
        assertEquals(TURN_TRANSPORT_UDP, roundTrip(RawAttribute.ofRequestedTransport()).asRequestedTransport())
    }

    @Test
    fun channelNumberRoundTrips() {
        assertEquals(0x4001u.toUShort(), roundTrip(RawAttribute.ofChannelNumber(0x4001u)).asChannelNumber())
    }

    @Test
    fun xorPeerAndRelayedReuseXorMappedAddressWireForm() {
        val peer = TransportAddress(IpAddress.V4(0x0A000001u), 3478u) // 10.0.0.1:3478
        // Built as XOR-MAPPED-ADDRESS but the wire form is shared; decode it as a peer address.
        val encoded =
            StunMessageBuilder
                .of(StunClass.Indication, StunMethod.Send, txId)
                .add(RawAttribute.ofXorMappedAddress(peer, txId))
                .encode()
        val msg = (StunMessage.decode(encoded) as StunDecodeResult.Success).message
        assertEquals(peer, msg.attributes.first().asXorMappedAddress(txId))
    }

    @Test
    fun unknownAttributesRoundTrips() {
        val types = listOf(StunAttributeType.Username, StunAttributeType.Realm, StunAttributeType(0x7FFFu))
        val decoded = roundTrip(RawAttribute.ofUnknownAttributes(types)).asUnknownAttributes()
        assertEquals(types, decoded)
    }

    @Test
    fun malformedTypedReadsReturnNull() {
        // A LIFETIME-typed attribute whose value isn't 4 bytes → typed miss, not a throw.
        assertNull(RawAttribute.ofText(StunAttributeType.Lifetime, "xy").asLifetimeSeconds())
    }

    @Test
    fun unknownComprehensionRequiredDrives420() {
        val recognized = setOf(StunAttributeType.Software, StunAttributeType.MessageIntegrity)
        val msg =
            StunMessageBuilder
                .of(StunClass.Request, StunMethod.Binding, txId)
                .add(RawAttribute.ofText(StunAttributeType.Software, "peer")) // comprehension-optional (0x8022)
                .add(RawAttribute.ofText(StunAttributeType.Username, "u")) // comprehension-required, unrecognized
                .add(RawAttribute.ofText(StunAttributeType(0x0003u), "x")) // comprehension-required, unrecognized
                .build()
        val unknown = msg.unknownComprehensionRequired(recognized)
        assertEquals(listOf(StunAttributeType.Username, StunAttributeType(0x0003u)), unknown)
    }

    @Test
    fun attributesCoveredByMessageIntegrityExcludesTheTail() {
        val key = keyOf()
        // SOFTWARE, USERNAME are covered; MESSAGE-INTEGRITY and the trailing FINGERPRINT are not.
        val encoded =
            StunMessageBuilder
                .of(StunClass.Request, StunMethod.Binding, txId)
                .add(RawAttribute.ofText(StunAttributeType.Software, "s"))
                .add(RawAttribute.ofText(StunAttributeType.Username, "u"))
                .addMessageIntegrity(key)
                .addFingerprint()
                .encode()
        val msg = (StunMessage.decode(encoded) as StunDecodeResult.Success).message
        val covered = msg.attributesCoveredByMessageIntegrity()
        assertEquals(listOf(StunAttributeType.Software, StunAttributeType.Username), covered?.map { it.type })
    }

    @Test
    fun attributesCoveredByMessageIntegrityIsNullWhenAbsent() {
        val encoded =
            StunMessageBuilder
                .of(StunClass.Request, StunMethod.Binding, txId)
                .add(RawAttribute.ofText(StunAttributeType.Software, "s"))
                .encode()
        val msg = (StunMessage.decode(encoded) as StunDecodeResult.Success).message
        assertNull(msg.attributesCoveredByMessageIntegrity())
    }

    @Test
    fun constantTimeMessageIntegrityStillVerifies() {
        val key = keyOf()
        val encoded =
            StunMessageBuilder
                .of(StunClass.Request, StunMethod.Binding, txId)
                .add(RawAttribute.ofText(StunAttributeType.Username, "alice"))
                .addMessageIntegrity(key)
                .encode()
        val msg = (StunMessage.decode(encoded) as StunDecodeResult.Success).message
        assertTrue(msg.verifyMessageIntegrity(key))
        assertTrue(!msg.verifyMessageIntegrity(keyOf("other-key-value!")))
    }

    private fun roundTrip(attr: RawAttribute): RawAttribute {
        val encoded = StunMessageBuilder.of(StunClass.Request, StunMethod.Binding, txId).add(attr).encode()
        return (StunMessage.decode(encoded) as StunDecodeResult.Success).message.attributes.first()
    }

    private fun keyOf(text: String = "the-secret-key-x"): ReadBuffer {
        val b = BufferFactory.Default.allocate(text.length, ByteOrder.BIG_ENDIAN)
        b.writeString(text)
        b.resetForRead()
        return b
    }
}

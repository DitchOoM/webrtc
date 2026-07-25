package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A [BufferFactory] decorator that counts allocations (the directive-#6 accounting seam; mirrors the
 * SCTP and ICE `CountingBufferFactory`).
 */
private class CountingBufferFactory(
    private val delegate: BufferFactory = BufferFactory.Default,
) : BufferFactory by delegate {
    var allocations: Int = 0
        private set

    override fun allocate(
        size: Int,
        byteOrder: ByteOrder,
    ): PlatformBuffer {
        allocations++
        return delegate.allocate(size, byteOrder)
    }
}

private fun keyBuffer(text: String): ReadBuffer {
    val bytes = text.encodeToByteArray()

    @Suppress("NoByteArrayInProd") // test-only: building a fixture key for the HMAC seam
    val buf = BufferFactory.Default.allocate(maxOf(1, bytes.size), ByteOrder.BIG_ENDIAN)
    for (b in bytes) buf.writeByte(b)
    buf.resetForRead()
    buf.setLimit(bytes.size)
    return buf
}

/**
 * Standing directive #6 says buffers are factory-injected. `webrtc-stun` said so in its signatures but
 * did not mean it: every attribute builder, the message builder's integrity/fingerprint scratch, and the
 * integrity *verification* scratch allocated from the global `BufferFactory.Default`, so a consumer
 * handing the stack a pooled or accounting factory had it silently bypassed here — and any leak or
 * allocation-bound invariant was unprovable for exactly these allocations.
 *
 * These tests fail on the old code by construction: they assert the injected factory is the one that
 * runs, so a hardwired `BufferFactory.Default.allocate` shows up as a zero count.
 */
class StunBufferFactoryInjectionTest {
    private val transactionId = TransactionId.random(kotlin.random.Random(1))

    @Test
    fun the_message_builder_allocates_from_its_injected_factory() {
        val factory = CountingBufferFactory()
        StunMessageBuilder
            .of(StunClass.Request, StunMethod.Binding, transactionId, factory)
            .add(RawAttribute.ofText(StunAttributeType.Username, "alice:bob", factory))
            .addMessageIntegrity(keyBuffer("secret"))
            .addFingerprint()
            .encode(factory)

        assertTrue(
            factory.allocations > 0,
            "the injected factory must be the one that allocates — a hardwired BufferFactory.Default " +
                "would leave this at 0",
        )
    }

    @Test
    fun every_turn_attribute_builder_honors_its_factory() {
        // One factory per builder so a single shared counter cannot mask one that ignored its argument.
        val cases: List<Pair<String, (BufferFactory) -> RawAttribute>> =
            listOf(
                "ofRequestedAddressFamily" to { f -> RawAttribute.ofRequestedAddressFamily(TURN_FAMILY_IPV6, f) },
                "ofLifetime" to { f -> RawAttribute.ofLifetime(600u, f) },
                "ofRequestedTransport" to { f -> RawAttribute.ofRequestedTransport(factory = f) },
                "ofChannelNumber" to { f -> RawAttribute.ofChannelNumber(0x4000u, f) },
                "ofUnknownAttributes" to { f -> RawAttribute.ofUnknownAttributes(listOf(StunAttributeType.Username), f) },
                "ofText" to { f -> RawAttribute.ofText(StunAttributeType.Realm, "example.org", f) },
                "ofErrorCode" to { f -> RawAttribute.ofErrorCode(StunErrorCode(401, "Unauthorized"), f) },
                "ofMappedAddress" to { f -> RawAttribute.ofMappedAddress(loopback(), f) },
                "ofXorMappedAddress" to { f -> RawAttribute.ofXorMappedAddress(loopback(), transactionId, f) },
            )

        val ignored =
            cases.filter { (_, build) ->
                CountingBufferFactory().let {
                    build(it)
                    it.allocations == 0
                }
            }
        assertEquals(emptyList(), ignored.map { it.first }, "these builders ignored their injected factory")
    }

    @Test
    fun integrity_verification_allocates_from_its_injected_factory() {
        val key = keyBuffer("secret")
        val encoded =
            StunMessageBuilder
                .of(StunClass.Request, StunMethod.Binding, transactionId)
                .addMessageIntegrity(key)
                .encode()
        val decoded = StunMessage.decode(encoded)
        assertTrue(decoded is StunDecodeResult.Success, "the fixture message must decode")

        val factory = CountingBufferFactory()
        assertTrue(
            decoded.message.verifyMessageIntegrity(key, factory),
            "the fixture's own MESSAGE-INTEGRITY must verify",
        )
        assertTrue(
            factory.allocations > 0,
            "verification's MAC + length-patch scratch must come from the injected factory",
        )
    }

    private fun loopback(): TransportAddress = TransportAddress(IpAddress.V4(0x7F000001u), 3478u)
}

package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.codec.DecodeContext
import com.ditchoom.buffer.codec.EncodeContext
import kotlin.test.Test
import kotlin.test.assertEquals

/** Round-trips the KSP-generated [StunHeader] codec and pins the RFC 8489 §5 type bit-interleaving. */
class StunHeaderTest {
    @Test
    fun bindingRequestTypeIsWellKnownValue() {
        assertEquals(0x0001u.toUShort(), StunMessageType.of(StunClass.Request, StunMethod.Binding).raw)
        assertEquals(0x0101u.toUShort(), StunMessageType.of(StunClass.SuccessResponse, StunMethod.Binding).raw)
        assertEquals(0x0111u.toUShort(), StunMessageType.of(StunClass.ErrorResponse, StunMethod.Binding).raw)
    }

    @Test
    fun typeClassAndMethodDeinterleaveRoundTrip() {
        for (cls in StunClass.entries) {
            for (m in listOf(0x001, 0x003, 0x009, 0x0ABC, 0x0FFF)) {
                val t = StunMessageType.of(cls, StunMethod(m.toUShort()))
                assertEquals(cls, t.stunClass)
                assertEquals(m.toUShort(), t.method.value)
            }
        }
    }

    @Test
    fun headerCodecRoundTrips() {
        val header =
            StunHeader(
                messageType = StunMessageType.of(StunClass.Request, StunMethod.Binding),
                messageLength = 0u,
                magicCookie = Stun.MAGIC_COOKIE,
                transactionId = TransactionId(0x11223344u, 0x55667788u, 0x99AABBCCu),
            )
        val buf = BufferFactory.Default.allocate(StunHeader.SIZE_BYTES, ByteOrder.BIG_ENDIAN)
        StunHeaderCodec.encode(buf, header, EncodeContext.Empty)
        buf.resetForRead()
        assertEquals(StunHeader.SIZE_BYTES, buf.remaining())
        assertEquals(header, StunHeaderCodec.decode(buf, DecodeContext.Empty))
    }
}

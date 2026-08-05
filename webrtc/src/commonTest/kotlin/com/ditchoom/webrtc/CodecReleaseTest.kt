package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.ParameterType
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.SctpDecodeResult
import com.ditchoom.webrtc.sctp.SctpPacket
import com.ditchoom.webrtc.sctp.SctpPacketBuilder
import com.ditchoom.webrtc.sctp.SctpParameter
import com.ditchoom.webrtc.sctp.Tsn
import com.ditchoom.webrtc.sctp.VerificationTag
import com.ditchoom.webrtc.stun.RawAttribute
import com.ditchoom.webrtc.stun.StunAttributeType
import com.ditchoom.webrtc.stun.StunClass
import com.ditchoom.webrtc.stun.StunDecodeResult
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.StunMessageBuilder
import com.ditchoom.webrtc.stun.StunMethod
import com.ditchoom.webrtc.stun.TransactionId
import kotlin.random.Random
import kotlin.test.Test

/**
 * **Each codec, alone, on a pooled datagram: decode it, release it, and the chunk must come home.**
 *
 * `PooledReceiveChunkTest` asks the same question of a whole session, which is the invariant that
 * matters — but a whole session is a poor place to *find* a pin, because every layer is a candidate.
 * These isolate one codec each, so a failure names its own culprit.
 *
 * The datagram is copied into a tracked pooled buffer first, exactly as the receive path does
 * (`TestNet.copyOf` / socket-udp's receive factory), because that copy is the thing whose refcount the
 * decode moves.
 */
class CodecReleaseTest {
    @Test
    fun decoding_and_releasing_a_stun_message_returns_the_chunk() {
        val factory = LeakTrackingFactory()
        val wire = stunBindingRequest()
        val datagram = factory.intoPool(wire)

        val decoded = StunMessage.decode(datagram)
        check(decoded is StunDecodeResult.Success) { "fixture must decode: $decoded" }
        decoded.message.release()
        datagram.freeIfNeeded()

        factory.assertPoolDrained("a decoded STUN message")
    }

    @Test
    fun a_rejected_stun_message_returns_the_chunk_too() {
        val factory = LeakTrackingFactory()
        // A valid header whose attribute walk runs off the end — the peer-controlled reject path, which
        // hands the caller no object to release the part-built attributes through.
        val wire = stunBindingRequest()
        wire.position(2)
        wire.writeUShort(0xFFFFu.toUShort()) // message length far beyond the datagram
        wire.resetForRead()
        val datagram = factory.intoPool(wire)

        StunMessage.decode(datagram) // Reject; nothing for the caller to release
        datagram.freeIfNeeded()

        factory.assertPoolDrained("a rejected STUN message")
    }

    @Test
    fun decoding_and_releasing_an_sctp_packet_returns_the_chunk() {
        val factory = LeakTrackingFactory()
        val wire = sctpInitPacket()
        val datagram = factory.intoPool(wire)

        val decoded = SctpPacket.decode(datagram)
        check(decoded is SctpDecodeResult.Success) { "fixture must decode: $decoded" }
        decoded.packet.release()
        datagram.freeIfNeeded()

        factory.assertPoolDrained("a decoded SCTP packet")
    }

    // Built from `BufferFactory.managed()` (GC-heap on every target) so the fixture's own scaffolding
    // never lands in the tracked pool and cannot be mistaken for a production pin.
    private fun stunBindingRequest(): PlatformBuffer =
        StunMessageBuilder
            .of(
                StunClass.Request,
                StunMethod.Binding,
                TransactionId.random(Random(7)),
                BufferFactory.managed(),
            ).add(RawAttribute.ofText(StunAttributeType.Username, "alice:bob", BufferFactory.managed()))
            .add(RawAttribute.ofText(StunAttributeType.Software, "webrtc-kt", BufferFactory.managed()))
            .addFingerprint()
            .encode(BufferFactory.managed())

    private fun sctpInitPacket(): PlatformBuffer =
        SctpPacketBuilder(SOURCE_PORT, DESTINATION_PORT, VerificationTag(0u))
            .add(
                SctpChunk.Init(
                    initiateTag = VerificationTag(INITIATE_TAG),
                    advertisedReceiverWindow = RWND,
                    outboundStreams = STREAMS,
                    inboundStreams = STREAMS,
                    initialTsn = Tsn(1u),
                    parameters = listOf(SctpParameter.ofValue(ParameterType.ForwardTsnSupported, ReadBuffer.EMPTY_BUFFER)),
                ),
            ).encode(BufferFactory.managed())

    /** Copy [wire] into a pooled buffer from this factory — the shape a receive path produces. */
    private fun LeakTrackingFactory.intoPool(wire: ReadBuffer): PlatformBuffer {
        val len = wire.remaining()
        val copy = allocate(len, ByteOrder.BIG_ENDIAN)
        copy.write(wire)
        copy.resetForRead()
        copy.setLimit(len)
        return copy
    }

    private companion object {
        const val SOURCE_PORT: UShort = 5000u
        const val DESTINATION_PORT: UShort = 5000u
        const val INITIATE_TAG: UInt = 0x12345678u
        const val RWND: UInt = 65535u
        const val STREAMS: UShort = 10u
    }
}

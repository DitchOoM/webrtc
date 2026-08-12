package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.managed
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The RFC 4820 PAD chunk, which exists here for exactly one purpose: inflating an RFC 8899 path-MTU probe
 * to a chosen size without carrying anything.
 *
 * The load-bearing property is not the encoding — it is what a receiver that has **never heard of RFC
 * 4820** does with it. Chunk type 132's two high bits are `10`, which RFC 4960 §3.2 defines as *skip this
 * chunk and keep processing the rest of the packet*, so a peer discards the padding and answers the
 * HEARTBEAT bundled beside it. That is what makes a probe confirmable by dcSCTP, usrsctp, Pion and werift
 * without a negotiation, a capability bit, or anything to gate a fixture on — and a capability-gated
 * probe that silently degenerates on peers that lack it is the failure mode this repository keeps
 * recording.
 */
class PadChunkTest {
    private val factory = BufferFactory.managed()

    private fun packetOf(vararg chunks: SctpChunk) =
        SctpPacketBuilder(5000u, 5000u, VerificationTag(0x11223344u))
            .also { builder -> chunks.forEach { builder.add(it) } }
            .encode(factory)

    @Test
    fun the_high_bits_say_skip_and_continue() {
        assertEquals(
            UnrecognizedAction.SkipAndContinue,
            SctpChunkType.Pad.unrecognizedAction,
            "a peer that cannot parse a PAD chunk must still process the HEARTBEAT bundled with it",
        )
        assertEquals(132u.toUByte(), SctpChunkType.Pad.value)
    }

    @Test
    fun a_pad_chunk_costs_its_own_header_plus_its_padding() {
        val encoded = packetOf(SctpChunk.Pad(PadBytes(64)))
        assertEquals(
            SctpCommonHeader.SIZE_BYTES + TLV_HEADER_BYTES + 64,
            encoded.limit(),
            "the whole point is exact sizing: a probe that is not the size it claims measures nothing",
        )
    }

    /**
     * Deliberately **not** decoded into [SctpChunk.Pad]. The chunk carries no information by definition, so
     * a typed variant would be an empty value every inbound `when` then has to handle for no purpose — and
     * discarding it while continuing to read the packet is what RFC 4960 §3.2 prescribes anyway.
     */
    @Test
    fun an_inbound_pad_chunk_stays_unrecognized() {
        val encoded = packetOf(SctpChunk.Pad(PadBytes(32)))
        val decoded = assertIs<SctpDecodeResult.Success>(SctpPacket.decode(encoded)).packet
        val chunk = assertIs<SctpChunk.Unrecognized>(decoded.chunks.single())
        assertEquals(SctpChunkType.Pad, chunk.type)
        assertEquals(32, chunk.value.remaining())
        decoded.release()
    }

    /** The probe's real shape, decoded as a peer would: the HEARTBEAT survives the padding beside it. */
    @Test
    fun a_probe_decodes_as_a_heartbeat_followed_by_skippable_padding() {
        val nonce = factory.allocate(4, com.ditchoom.buffer.ByteOrder.BIG_ENDIAN)
        nonce.writeUInt(0xDEADBEEFu)
        nonce.resetForRead()
        nonce.setLimit(4)
        val info = SctpParameter.ofValue(ParameterType.HeartbeatInfo, nonce)
        val encoded = packetOf(SctpChunk.Heartbeat(info), SctpChunk.Pad(PadBytes(1024)))

        val decoded = assertIs<SctpDecodeResult.Success>(SctpPacket.decode(encoded)).packet
        assertEquals(2, decoded.chunks.size)
        assertIs<SctpChunk.Heartbeat>(decoded.chunks[0])
        assertIs<SctpChunk.Unrecognized>(decoded.chunks[1])
        assertTrue(
            encoded.limit() > 1024,
            "the probe is the size of its padding plus its framing, which is what makes it a probe",
        )
        decoded.release()
    }

    @Test
    fun a_pad_length_that_is_not_four_byte_aligned_is_unconstructible() {
        assertFailsWith<IllegalArgumentException> { PadBytes(3) }
        assertFailsWith<IllegalArgumentException> { PadBytes(-4) }
        assertFailsWith<IllegalArgumentException> { PadBytes(65532) }
    }

    @Test
    fun zero_padding_is_legal_and_is_a_bare_chunk_header() {
        val encoded = packetOf(SctpChunk.Pad(PadBytes(0)))
        assertEquals(SctpCommonHeader.SIZE_BYTES + TLV_HEADER_BYTES, encoded.limit())
    }

    private companion object {
        private const val TLV_HEADER_BYTES = 4
    }
}

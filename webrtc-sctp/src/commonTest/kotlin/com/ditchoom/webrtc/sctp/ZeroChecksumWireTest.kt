package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.managed
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The two wire seams RFC 9653 touches — what the encoder puts in the checksum field, and what the
 * verifier does with what it finds there.
 *
 * The permission and the chunk vocabulary are **two independent gates**, and every interesting failure
 * here is one of them being mistaken for the other. A packet is emitted with a zero only when the peer
 * permitted it *and* nothing in the packet is on RFC 9653 §5.2's list; a packet is accepted with a zero
 * only when *we* advertised, which is a fact about a completely different direction.
 */
class ZeroChecksumWireTest {
    private val dtls = OutboundChecksum.ZeroWherePermitted(ErrorDetectionMethodId.ZeroChecksum)
    private val accepting = ZeroChecksumAcceptance.Advertised(ErrorDetectionMethodId.ZeroChecksum)

    private fun packetOf(vararg chunks: SctpChunk): SctpPacketBuilder =
        SctpPacketBuilder(5000u, 5000u, VerificationTag(0xDEADBEEFu)).apply { chunks.forEach { add(it) } }

    /** The four checksum bytes as they sit on the wire (RFC 4960 §3.1, header offset 8). */
    private fun checksumOf(
        chunk: SctpChunk,
        outbound: OutboundChecksum,
    ): UInt = packetOf(chunk).encode(BufferFactory.managed(), outbound).u32(SctpPacket.CHECKSUM_OFFSET)

    private fun decodedWith(
        outbound: OutboundChecksum,
        vararg chunks: SctpChunk,
    ): SctpPacket {
        val encoded = packetOf(*chunks).encode(BufferFactory.managed(), outbound)
        return (SctpPacket.decode(encoded) as SctpDecodeResult.Success).packet
    }

    private val cookie get() = bufferOf(0xD1, 0xC4, 0x0C, 0x1E)

    private val init
        get() =
            SctpChunk.Init(VerificationTag(1u), 65536u, 16u, 16u, Tsn(1u), listOf(SctpParameter.forwardTsnSupported()))

    private val data
        get() =
            SctpChunk.Data(
                flags = DataChunkFlags.of(beginning = true, ending = true, unordered = false),
                tsn = Tsn(7u),
                streamId = StreamId(0),
                streamSequenceNumber = StreamSequenceNumber(0u),
                payloadProtocolId = PayloadProtocolId(53u),
                userData = bufferOf(1, 2, 3, 4),
            )

    /**
     * The whole of RFC 9653 §5.2's per-packet half, as a table. The permissive default is the dangerous
     * one — a chunk that should force a CRC32c but does not puts an unchecksummed packet somewhere the RFC
     * says it may not go, and nothing on a working link would ever notice.
     */
    @Test
    fun the_chunks_rfc_9653_exempts_from_the_permission_are_exactly_these() {
        val required =
            listOf<SctpChunk>(
                init,
                SctpChunk.CookieEcho(cookie),
                SctpChunk.Abort(verificationTagReflected = true, causes = emptyList()),
                SctpChunk.ShutdownComplete(verificationTagReflected = true),
                SctpChunk.Unrecognized(SctpChunkType(0xC1u.toUByte()), 0u, bufferOf(0)),
            )
        val permitted =
            listOf(
                data,
                SctpChunk.InitAck(VerificationTag(1u), 65536u, 16u, 16u, Tsn(1u), listOf(SctpParameter.forwardTsnSupported())),
                SctpChunk.Sack(Tsn(1u), 65536u, emptyList(), emptyList()),
                SctpChunk.Heartbeat(SctpParameter.ofValue(ParameterType.HeartbeatInfo, bufferOf(9))),
                SctpChunk.HeartbeatAck(SctpParameter.ofValue(ParameterType.HeartbeatInfo, bufferOf(9))),
                SctpChunk.Abort(verificationTagReflected = false, causes = emptyList()),
                SctpChunk.Shutdown(Tsn(1u)),
                SctpChunk.ShutdownAck,
                SctpChunk.Error(listOf(SctpErrorCause.empty(ErrorCauseCode.UnrecognizedChunkType))),
                SctpChunk.CookieAck,
                SctpChunk.ShutdownComplete(verificationTagReflected = false),
                SctpChunk.ReConfig(listOf(SctpParameter.ofValue(ParameterType.ReConfigResponse, bufferOf(0, 0, 0, 1, 0, 0, 0, 0)))),
                SctpChunk.ForwardTsn(Tsn(1u), emptyList()),
            )

        for (chunk in required) {
            assertEquals(
                ChunkChecksumRequirement.Crc32cRequired,
                chunk.checksumRequirement,
                "RFC 9653 §5.2 requires a correct CRC32c on a packet carrying ${chunk.type}",
            )
        }
        for (chunk in permitted) {
            assertEquals(
                ChunkChecksumRequirement.EitherPermitted,
                chunk.checksumRequirement,
                "${chunk.type} imposes no checksum constraint of its own",
            )
        }
        // ABORT and SHUTDOWN COMPLETE appear in both lists, once per T-bit polarity — they are the two
        // variants whose answer is not a property of the type alone. Counting distinct classes rather than
        // entries is what makes this a coverage claim: every `SctpChunk` variant is named above, so a
        // variant added later fails here as well as at the exhaustive `when` it must join.
        assertEquals(
            16,
            (required + permitted).distinctBy { it::class }.size,
            "every SctpChunk variant must appear in this table",
        )
    }

    /**
     * The T bit is the RFC 4960 §8.4 out-of-the-blue discriminant, and RFC 9653 §5.2 restriction 1b hangs
     * off it: a reflected ABORT is an answer to an endpoint that holds no association with us and has
     * therefore permitted us nothing. The same chunk without the bit is ordinary traffic of a live
     * association. One bit, two entirely different packets.
     */
    @Test
    fun the_t_bit_alone_decides_whether_an_abort_may_carry_a_zero() {
        assertEquals(0u, checksumOf(SctpChunk.Abort(verificationTagReflected = false, causes = emptyList()), dtls))
        assertNotEquals(
            0u,
            checksumOf(SctpChunk.Abort(verificationTagReflected = true, causes = emptyList()), dtls),
            "a reflected ABORT answers an out-of-the-blue packet and must be checksummed",
        )
    }

    @Test
    fun a_permitted_packet_is_emitted_with_a_zero_checksum() {
        assertEquals(0u, checksumOf(data, dtls), "a DATA chunk under permission carries no CRC32c")
        assertNotEquals(0u, checksumOf(data, OutboundChecksum.Crc32c), "the same chunk without permission must be checksummed")
    }

    @Test
    fun an_init_and_a_cookie_echo_are_checksummed_even_under_permission() {
        assertNotEquals(0u, checksumOf(init, dtls), "RFC 9653 §5.2 restriction 1a")
        assertNotEquals(0u, checksumOf(SctpChunk.CookieEcho(cookie), dtls), "RFC 9653 §5.2 restriction 2")
    }

    /**
     * Bundling: the checksum covers every chunk in the packet, so one demanding chunk decides for all of
     * them. Without the join, a DATA chunk bundled behind a COOKIE ECHO would carry the permission's zero
     * onto a packet the RFC requires be checksummed — and the bundling site would have to remember why.
     */
    @Test
    fun one_demanding_chunk_checksums_the_whole_packet() {
        val bundled = packetOf(SctpChunk.CookieEcho(cookie), data).encode(BufferFactory.managed(), dtls)

        assertNotEquals(0u, bundled.u32(SctpPacket.CHECKSUM_OFFSET))
    }

    /** The permission changes nothing about a packet whose chunks were already going to be checksummed. */
    @Test
    fun a_checksummed_packet_is_byte_identical_with_and_without_the_permission() {
        assertEquals(
            packetOf(init).encode(BufferFactory.managed(), OutboundChecksum.Crc32c).toIntList(),
            packetOf(init).encode(BufferFactory.managed(), dtls).toIntList(),
        )
    }

    @Test
    fun a_zero_checksum_packet_is_accepted_when_we_advertised() {
        val verdict = decodedWith(dtls, data).validateChecksum(accepting)

        assertEquals(ChecksumVerdict.AcceptedZero, verdict)
        assertTrue(verdict.accepted, "RFC 9653 §5.3 obliges an endpoint that advertised to accept this")
    }

    /**
     * The one that matters most: a peer we made no promise to does not get to skip its checksum. RFC 9653
     * §5.3 is explicit — "Otherwise, the endpoint MUST drop all SCTP packets with an incorrect CRC32c
     * checksum" — and this is the packet an attacker or a confused peer would send to find out whether we
     * check.
     */
    @Test
    fun a_zero_checksum_packet_is_rejected_when_we_advertised_nothing() {
        val verdict = decodedWith(dtls, data).validateChecksum(ZeroChecksumAcceptance.RequireCrc32c)

        assertEquals(ChecksumVerdict.Mismatch, verdict)
        assertFalse(verdict.accepted, "a zero checksum is an incorrect one unless we said we would accept it")
    }

    /**
     * Accepting a zero does not mean accepting anything. A packet carrying a genuinely wrong non-zero
     * checksum is still a [ChecksumVerdict.Mismatch] under an advertised acceptance — RFC 9653 §5.3 widens
     * the rule to admit exactly one value, not to switch the check off.
     */
    @Test
    fun an_advertised_acceptance_still_rejects_a_wrong_non_zero_checksum() {
        val encoded = packetOf(data).encode(BufferFactory.managed(), OutboundChecksum.Crc32c)
        encoded.set(SctpPacket.CHECKSUM_OFFSET, encoded.u32(SctpPacket.CHECKSUM_OFFSET).toInt() xor 0x00FF0000)
        val packet = (SctpPacket.decode(encoded) as SctpDecodeResult.Success).packet

        assertEquals(ChecksumVerdict.Mismatch, packet.validateChecksum(accepting))
    }

    /** A correctly checksummed packet is [ChecksumVerdict.Verified] under either acceptance. */
    @Test
    fun a_correctly_checksummed_packet_verifies_under_either_acceptance() {
        assertEquals(ChecksumVerdict.Verified, decodedWith(OutboundChecksum.Crc32c, data).validateChecksum(accepting))
        assertEquals(
            ChecksumVerdict.Verified,
            decodedWith(OutboundChecksum.Crc32c, data).validateChecksum(ZeroChecksumAcceptance.RequireCrc32c),
        )
    }

    /**
     * A packet that was never on a wire stays [ChecksumVerdict.NotFromWire] whatever was negotiated. It is
     * a caller mistake rather than a peer's, and RFC 9653 has nothing to say about it — the arm exists so
     * that adding an acceptance did not quietly give the category error a second meaning.
     */
    @Test
    fun a_built_packet_is_still_not_from_the_wire_under_an_advertised_acceptance() {
        assertEquals(ChecksumVerdict.NotFromWire, packetOf(data).build().validateChecksum(accepting))
    }
}

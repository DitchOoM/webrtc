package com.ditchoom.webrtc.sctp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * T0 round-trip floor: every modeled chunk type builds → encodes → decodes with its typed fields
 * intact, re-encodes byte-for-byte, and carries a CRC32c that [SctpPacket.verifyChecksum] accepts. The
 * checksum's little-endian field placement (RFC 4960 Appendix B) is pinned independently against
 * [referenceCrc32c] so a byte-order regression can't hide behind a self-consistent encode.
 */
class SctpPacketRoundTripTest {
    private val srcPort: UShort = 5000u
    private val dstPort: UShort = 5000u
    private val vtag = VerificationTag(0xDEADBEEFu)

    private fun packetOf(vararg chunks: SctpChunk): SctpPacket {
        val b = SctpPacketBuilder(srcPort, dstPort, vtag)
        for (c in chunks) b.add(c)
        return b.build()
    }

    // Encodes, decodes, asserts checksum + byte-exact re-encode, returns the decoded packet.
    private fun roundTrip(packet: SctpPacket): SctpPacket {
        val enc = packet.encode()
        val original = enc.toIntList()
        enc.position(0)
        val decoded = assertIs<SctpDecodeResult.Success>(SctpPacket.decode(enc)).packet
        assertTrue(decoded.verifyChecksum(), "checksum must verify")

        // Independent checksum placement check: recompute CRC32c over the bytes with the field zeroed,
        // and confirm the stored field is its little-endian encoding.
        val zeroed = original.toMutableList().also { for (i in 8..11) it[i] = 0 }
        val expected = referenceCrc32c(zeroed)
        val storedLe =
            (original[8].toLong() or (original[9].toLong() shl 8) or (original[10].toLong() shl 16) or (original[11].toLong() shl 24))
                .toUInt()
        assertEquals(expected, storedLe, "checksum field must be the little-endian CRC32c")

        val reenc = decoded.encode()
        assertEquals(original, reenc.toIntList(), "decode→encode must be byte-exact")
        return decoded
    }

    @Test
    fun dataChunkRoundTrips() {
        val payload = bufferOf(0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // 8 bytes (DCEP-shaped)
        val data =
            SctpChunk.Data(
                flags = DataChunkFlags.of(beginning = true, ending = true),
                tsn = Tsn(0x01020304u),
                streamId = StreamId(7),
                streamSequenceNumber = StreamSequenceNumber(9u),
                payloadProtocolId = PayloadProtocolId.WebRtcDcep,
                userData = payload,
            )
        val decoded = roundTrip(packetOf(data)).firstOrNull(SctpChunkType.Data)
        val d = assertIs<SctpChunk.Data>(decoded)
        assertEquals(Tsn(0x01020304u), d.tsn)
        assertEquals(StreamId(7), d.streamId)
        assertEquals(StreamSequenceNumber(9u), d.streamSequenceNumber)
        assertEquals(PayloadProtocolId.WebRtcDcep, d.payloadProtocolId)
        assertTrue(d.flags.unfragmented)
        assertTrue(!d.flags.unordered)
        assertEquals(8, d.userData.remaining())
    }

    @Test
    fun dataChunkWithOddLengthPayloadPadsAndRoundTrips() {
        // 3-byte user data forces one pad byte — exercises chunk padding.
        val data =
            SctpChunk.Data(
                DataChunkFlags.of(beginning = true, ending = false, unordered = true),
                Tsn(1u),
                StreamId(0),
                StreamSequenceNumber(0u),
                PayloadProtocolId.WebRtcString,
                bufferOf(0x41, 0x42, 0x43),
            )
        val d = assertIs<SctpChunk.Data>(roundTrip(packetOf(data)).firstOrNull(SctpChunkType.Data))
        assertTrue(d.flags.unordered)
        assertEquals(listOf(0x41, 0x42, 0x43), d.userData.toIntList())
    }

    @Test
    fun initChunkWithParametersRoundTrips() {
        val init =
            SctpChunk.Init(
                initiateTag = VerificationTag(0x11223344u),
                advertisedReceiverWindow = 0x0001_0000u,
                outboundStreams = 1024u,
                inboundStreams = 1024u,
                initialTsn = Tsn(0xAABBCCDDu),
                parameters =
                    listOf(
                        SctpParameter.forwardTsnSupported(),
                        SctpParameter.supportedExtensions(listOf(SctpChunkType.ForwardTsn, SctpChunkType.ShutdownComplete)),
                    ),
            )
        val decoded = assertIs<SctpChunk.Init>(roundTrip(packetOf(init)).firstOrNull(SctpChunkType.Init))
        assertEquals(VerificationTag(0x11223344u), decoded.initiateTag)
        assertEquals(1024u.toUShort(), decoded.outboundStreams)
        assertTrue(decoded.supportsForwardTsn())
        val ext = decoded.parameters.firstNotNullOf { it.asSupportedExtensions() }
        assertEquals(listOf(SctpChunkType.ForwardTsn, SctpChunkType.ShutdownComplete), ext)
    }

    @Test
    fun initAckWithStateCookieRoundTrips() {
        val cookie = bufferOf(0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02) // 6 bytes → padded to 8
        val initAck =
            SctpChunk.InitAck(
                VerificationTag(1u),
                0x8000u,
                10u,
                10u,
                Tsn(100u),
                listOf(SctpParameter.ofValue(ParameterType.StateCookie, cookie)),
            )
        val decoded = assertIs<SctpChunk.InitAck>(roundTrip(packetOf(initAck)).firstOrNull(SctpChunkType.InitAck))
        val sc = assertIs<SctpParameter>(decoded.stateCookie())
        assertEquals(listOf(0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02), sc.value.toIntList())
    }

    @Test
    fun sackWithGapsAndDuplicatesRoundTrips() {
        val sack =
            SctpChunk.Sack(
                cumulativeTsnAck = Tsn(0x1000u),
                advertisedReceiverWindow = 0x2000u,
                gapAckBlocks = listOf(GapAckBlock(2u, 3u), GapAckBlock(5u, 7u)),
                duplicateTsns = listOf(Tsn(0x0FFFu)),
            )
        val decoded = assertIs<SctpChunk.Sack>(roundTrip(packetOf(sack)).firstOrNull(SctpChunkType.Sack))
        assertEquals(listOf(GapAckBlock(2u, 3u), GapAckBlock(5u, 7u)), decoded.gapAckBlocks)
        assertEquals(listOf(Tsn(0x0FFFu)), decoded.duplicateTsns)
    }

    @Test
    fun heartbeatRoundTrips() {
        val hb = SctpChunk.Heartbeat(SctpParameter.ofValue(ParameterType.HeartbeatInfo, bufferOf(1, 2, 3, 4, 5)))
        val decoded = assertIs<SctpChunk.Heartbeat>(roundTrip(packetOf(hb)).firstOrNull(SctpChunkType.Heartbeat))
        assertEquals(ParameterType.HeartbeatInfo, decoded.info.type)
        assertEquals(listOf(1, 2, 3, 4, 5), decoded.info.value.toIntList())
    }

    @Test
    fun abortWithCauseRoundTrips() {
        val abort =
            SctpChunk.Abort(
                verificationTagReflected = true,
                causes = listOf(SctpErrorCause.empty(ErrorCauseCode.UserInitiatedAbort)),
            )
        val decoded = assertIs<SctpChunk.Abort>(roundTrip(packetOf(abort)).firstOrNull(SctpChunkType.Abort))
        assertTrue(decoded.verificationTagReflected)
        assertEquals(ErrorCauseCode.UserInitiatedAbort, decoded.causes.single().code)
    }

    @Test
    fun errorWithCauseValueRoundTrips() {
        val error = SctpChunk.Error(listOf(SctpErrorCause.ofValue(ErrorCauseCode.ProtocolViolation, bufferOf(0x41, 0x42))))
        val decoded = assertIs<SctpChunk.Error>(roundTrip(packetOf(error)).firstOrNull(SctpChunkType.Error))
        assertEquals(
            listOf(0x41, 0x42),
            decoded.causes
                .single()
                .value
                .toIntList(),
        )
    }

    @Test
    fun shutdownFamilyRoundTrips() {
        assertIs<SctpChunk.Shutdown>(roundTrip(packetOf(SctpChunk.Shutdown(Tsn(42u)))).firstOrNull(SctpChunkType.Shutdown))
        assertIs<SctpChunk.ShutdownAck>(roundTrip(packetOf(SctpChunk.ShutdownAck)).firstOrNull(SctpChunkType.ShutdownAck))
        val sc =
            assertIs<SctpChunk.ShutdownComplete>(
                roundTrip(packetOf(SctpChunk.ShutdownComplete(true))).firstOrNull(SctpChunkType.ShutdownComplete),
            )
        assertTrue(sc.verificationTagReflected)
    }

    @Test
    fun cookieEchoAndAckRoundTrip() {
        val echo = SctpChunk.CookieEcho(bufferOf(0xDE, 0xAD, 0xBE, 0xEF, 0x00))
        val decoded = assertIs<SctpChunk.CookieEcho>(roundTrip(packetOf(echo)).firstOrNull(SctpChunkType.CookieEcho))
        assertEquals(listOf(0xDE, 0xAD, 0xBE, 0xEF, 0x00), decoded.cookie.toIntList())
        assertIs<SctpChunk.CookieAck>(roundTrip(packetOf(SctpChunk.CookieAck)).firstOrNull(SctpChunkType.CookieAck))
    }

    @Test
    fun forwardTsnRoundTrips() {
        val fwd =
            SctpChunk.ForwardTsn(
                newCumulativeTsn = Tsn(0x1234u),
                streams =
                    listOf(
                        ForwardTsnStream(StreamId(1), StreamSequenceNumber(2u)),
                        ForwardTsnStream(StreamId(3), StreamSequenceNumber(4u)),
                    ),
            )
        val decoded = assertIs<SctpChunk.ForwardTsn>(roundTrip(packetOf(fwd)).firstOrNull(SctpChunkType.ForwardTsn))
        assertEquals(Tsn(0x1234u), decoded.newCumulativeTsn)
        assertEquals(2, decoded.streams.size)
        assertEquals(StreamId(3), decoded.streams[1].streamId)
    }

    @Test
    fun unrecognizedChunkIsPreservedVerbatim() {
        // Type 0x81 = 0b10_000001 → high bits 10 → "skip and continue" (RFC 4960 §3.2 forward-compat).
        val unknown = SctpChunk.Unrecognized(SctpChunkType(0x81u), flags = 0x05u, value = bufferOf(0x01, 0x02, 0x03))
        val decoded = assertIs<SctpChunk.Unrecognized>(roundTrip(packetOf(unknown)).chunks.single())
        assertEquals(SctpChunkType(0x81u), decoded.type)
        assertEquals(0x05u.toUByte(), decoded.flags)
        assertEquals(listOf(0x01, 0x02, 0x03), decoded.value.toIntList())
        assertEquals(UnrecognizedAction.SkipAndContinue, decoded.type.unrecognizedAction)
    }

    @Test
    fun multiChunkBundleRoundTrips() {
        // COOKIE-ECHO + DATA in one packet (RFC 4960 §6.10 bundling): the second chunk must start
        // 4-aligned after the first, which the walk enforces.
        val packet =
            packetOf(
                SctpChunk.CookieEcho(bufferOf(0x01, 0x02, 0x03, 0x04, 0x05)), // 5-byte cookie → 3 pad bytes
                SctpChunk.Data(
                    DataChunkFlags.of(beginning = true, ending = true),
                    Tsn(1u),
                    StreamId(0),
                    StreamSequenceNumber(0u),
                    PayloadProtocolId.WebRtcDcep,
                    bufferOf(0x02),
                ),
            )
        val decoded = roundTrip(packet)
        assertEquals(2, decoded.chunks.size)
        assertIs<SctpChunk.CookieEcho>(decoded.chunks[0])
        assertIs<SctpChunk.Data>(decoded.chunks[1])
    }
}

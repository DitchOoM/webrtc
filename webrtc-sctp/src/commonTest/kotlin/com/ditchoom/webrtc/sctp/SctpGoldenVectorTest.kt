package com.ditchoom.webrtc.sctp

import com.ditchoom.webrtc.sctp.dcep.ChannelType
import com.ditchoom.webrtc.sctp.dcep.DataChannelDecodeResult
import com.ditchoom.webrtc.sctp.dcep.DataChannelMessage
import com.ditchoom.webrtc.sctp.dcep.Reliability
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Frozen wire vectors — the codec's regression anchor. Each hex string is a byte-exact SCTP packet or
 * DCEP message whose layout matches the RFC diagrams (RFC 4960 §3.3.2/§3.3.4, RFC 8832 §5.1); freezing
 * them means any change that perturbs the wire format — field order, padding, the CRC32c placement —
 * fails here loudly instead of silently breaking interop. Decode + typed fields + checksum + byte-exact
 * re-encode are all asserted, so the vectors pin the whole pipeline, not just the parser.
 */
class SctpGoldenVectorTest {
    // INIT (vtag 0) advertising Forward-TSN-Supported + Supported-Extensions=[FORWARD-TSN]. RFC 4960 §3.3.2.
    private val initHex =
        "13881388000000001d7a606e" +
            "01000020" + "11223344" + "00100000" + "04000400" + "aabbccdd" +
            "c0000004" + "80080005c0000000"

    // SACK: cum-ack 0x1000, a_rwnd 0x2000, one gap block [2,3], one duplicate TSN 0x0FFF. RFC 4960 §3.3.4.
    private val sackHex =
        "138813881122334470680b96" +
            "03000018" + "00001000" + "00002000" + "00010001" + "00020003" + "00000fff"

    // A DATA chunk (PPID 50 = DCEP) whose user data is a DATA_CHANNEL_OPEN for label "chat". RFC 8831/8832.
    private val dcepDataHex =
        "13881388112233440729cb15" +
            "00030020" + "00000001" + "00000000" + "00000032" +
            "03000000" + "00000000" + "00040000" + "63686174"

    // Bare DCEP DATA_CHANNEL_OPEN payload (label "chat", empty protocol). RFC 8832 §5.1. 16 bytes.
    private val dcepOpenHex = "03000000000000000004000063686174"

    @Test
    fun initVectorDecodesWithExpectedFields() {
        val packet = decode(initHex)
        assertTrue(packet.verifyChecksum())
        val init = assertIs<SctpChunk.Init>(packet.chunks.single())
        assertEquals(VerificationTag(0x11223344u), init.initiateTag)
        assertEquals(0x00100000u, init.advertisedReceiverWindow)
        assertEquals(1024u.toUShort(), init.outboundStreams)
        assertEquals(Tsn(0xAABBCCDDu), init.initialTsn)
        assertTrue(init.supportsForwardTsn())
        assertEquals(listOf(SctpChunkType.ForwardTsn), init.parameters.firstNotNullOf { it.asSupportedExtensions() })
        assertReencodes(initHex, packet)
    }

    @Test
    fun sackVectorDecodesWithExpectedFields() {
        val packet = decode(sackHex)
        assertTrue(packet.verifyChecksum())
        val sack = assertIs<SctpChunk.Sack>(packet.chunks.single())
        assertEquals(Tsn(0x1000u), sack.cumulativeTsnAck)
        assertEquals(0x2000u, sack.advertisedReceiverWindow)
        assertEquals(listOf(GapAckBlock(2u, 3u)), sack.gapAckBlocks)
        assertEquals(listOf(Tsn(0x0FFFu)), sack.duplicateTsns)
        assertReencodes(sackHex, packet)
    }

    @Test
    fun dcepOverDataVectorDecodesEndToEnd() {
        val packet = decode(dcepDataHex)
        assertTrue(packet.verifyChecksum())
        val data = assertIs<SctpChunk.Data>(packet.chunks.single())
        assertEquals(PayloadProtocolId.WebRtcDcep, data.payloadProtocolId)
        // The DATA payload is a DCEP OPEN — decode it too (the layer the association will hand up).
        val dcep = assertIs<DataChannelDecodeResult.Success>(DataChannelMessage.decode(data.userData)).message
        val open = assertIs<DataChannelMessage.Open>(dcep)
        assertEquals("chat", open.label)
        assertTrue(open.channelType.ordered)
        assertEquals(Reliability.Reliable, open.channelType.reliability)
        assertReencodes(dcepDataHex, packet)
    }

    @Test
    fun bareDcepOpenVectorDecodes() {
        val open =
            assertIs<DataChannelMessage.Open>(
                assertIs<DataChannelDecodeResult.Success>(DataChannelMessage.decode(bufferOfHex(dcepOpenHex))).message,
            )
        assertEquals("chat", open.label)
        assertEquals("", open.protocol)
        assertEquals(ChannelType.of(true, Reliability.Reliable).raw, open.channelType.raw)
        assertEquals(bufferOfHex(dcepOpenHex).toIntList(), open.encode().toIntList())
    }

    private fun decode(hex: String): SctpPacket = assertIs<SctpDecodeResult.Success>(SctpPacket.decode(bufferOfHex(hex))).packet

    private fun assertReencodes(
        hex: String,
        packet: SctpPacket,
    ) {
        assertEquals(bufferOfHex(hex).toIntList(), packet.encode().toIntList(), "golden vector must re-encode byte-exact")
    }
}

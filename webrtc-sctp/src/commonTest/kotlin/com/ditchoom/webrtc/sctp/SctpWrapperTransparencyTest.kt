package com.ditchoom.webrtc.sctp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Wrapper-transparency (TESTING.md §4): the decoder must work when handed a slice view over a larger
 * backing buffer at a non-zero offset — the shape a pooled datagram or an SCTP-over-DTLS record slice
 * takes — not only a fresh zero-offset [com.ditchoom.buffer.PlatformBuffer]. Absolute reads, the CRC32c
 * span, and the zero-copy chunk views must all be offset-correct.
 */
class SctpWrapperTransparencyTest {
    @Test
    fun decodesAndVerifiesOverANonZeroOffsetSlice() {
        val packetBytes =
            SctpPacketBuilder(9u, 9u, VerificationTag(0x01020304u))
                .add(
                    SctpChunk.Data(
                        DataChunkFlags.of(beginning = true, ending = true),
                        Tsn(0xAABBCCDDu),
                        StreamId(5),
                        StreamSequenceNumber(1u),
                        PayloadProtocolId.WebRtcBinary,
                        bufferOf(0xDE, 0xAD, 0xBE, 0xEF, 0x11),
                    ),
                ).encode()
                .toIntList()

        // Present the same bytes only through a slice that starts 7 bytes into a backing buffer.
        val slice = sliceWithOffset(packetBytes, leadingPad = 7)
        val decoded = assertIs<SctpDecodeResult.Success>(SctpPacket.decode(slice)).packet

        assertTrue(decoded.verifyChecksum(), "checksum must verify through an offset slice")
        val data = assertIs<SctpChunk.Data>(decoded.chunks.single())
        assertEquals(Tsn(0xAABBCCDDu), data.tsn)
        assertEquals(StreamId(5), data.streamId)
        assertEquals(listOf(0xDE, 0xAD, 0xBE, 0xEF, 0x11), data.userData.toIntList())
        // Re-encoding the offset-decoded packet reproduces the original bytes.
        assertEquals(packetBytes, decoded.encode().toIntList())
    }

    @Test
    fun dcepDecodesOverANonZeroOffsetSlice() {
        val openBytes =
            com.ditchoom.webrtc.sctp.dcep.DataChannelMessage
                .Open(
                    com.ditchoom.webrtc.sctp.dcep.ChannelType
                        .of(true, com.ditchoom.webrtc.sctp.dcep.Reliability.Reliable),
                    0u,
                    0u,
                    "label",
                    "proto",
                ).encode()
                .toIntList()
        val slice = sliceWithOffset(openBytes, leadingPad = 3)
        val decoded =
            assertIs<com.ditchoom.webrtc.sctp.dcep.DataChannelDecodeResult.Success>(
                com.ditchoom.webrtc.sctp.dcep.DataChannelMessage
                    .decode(slice),
            ).message
        val open = assertIs<com.ditchoom.webrtc.sctp.dcep.DataChannelMessage.Open>(decoded)
        assertEquals("label", open.label)
        assertEquals("proto", open.protocol)
    }
}

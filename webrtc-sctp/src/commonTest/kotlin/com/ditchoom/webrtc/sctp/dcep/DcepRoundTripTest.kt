package com.ditchoom.webrtc.sctp.dcep

import com.ditchoom.webrtc.sctp.bufferOf
import com.ditchoom.webrtc.sctp.bufferOfHex
import com.ditchoom.webrtc.sctp.toIntList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * T0 floor for DCEP (RFC 8832): DATA_CHANNEL_OPEN / DATA_CHANNEL_ACK round-trip with typed fields, the
 * [ChannelType] projection is exhaustive and reversible, and every malformed payload is a typed reject.
 */
class DcepRoundTripTest {
    private fun decode(bytes: com.ditchoom.buffer.ReadBuffer) = DataChannelMessage.decode(bytes)

    @Test
    fun openRoundTripsWithLabelAndProtocol() {
        val open =
            DataChannelMessage.Open(
                channelType = ChannelType.of(ordered = true, reliability = Reliability.Reliable),
                priority = 256u,
                reliabilityParameter = 0u,
                label = "chat",
                protocol = "myproto",
            )
        val enc = open.encode()
        val original = enc.toIntList()
        enc.position(0)
        val decoded = assertIs<DataChannelDecodeResult.Success>(decode(enc)).message
        val d = assertIs<DataChannelMessage.Open>(decoded)
        assertEquals("chat", d.label)
        assertEquals("myproto", d.protocol)
        assertEquals(256u.toUShort(), d.priority)
        assertTrue(d.channelType.ordered)
        assertEquals(Reliability.Reliable, d.channelType.reliability)
        assertEquals(original, d.encode().toIntList())
    }

    @Test
    fun openWithUnorderedPartialReliableTimedRoundTrips() {
        val ct = ChannelType.of(ordered = false, reliability = Reliability.PartialReliableTimed)
        val open = DataChannelMessage.Open(ct, priority = 0u, reliabilityParameter = 3000u, label = "", protocol = "")
        val enc = open.encode()
        enc.position(0)
        val d = assertIs<DataChannelMessage.Open>(assertIs<DataChannelDecodeResult.Success>(decode(enc)).message)
        assertTrue(!d.channelType.ordered)
        assertEquals(Reliability.PartialReliableTimed, d.channelType.reliability)
        assertEquals(3000u, d.reliabilityParameter)
        assertEquals("", d.label)
        assertEquals("", d.protocol)
    }

    @Test
    fun openWithSupplementaryPlaneLabelRoundTrips() {
        // Regression (wire-correctness review): a label with a non-BMP code point (an emoji is a
        // UTF-16 surrogate pair → 4 UTF-8 bytes, not the 6 a per-char count would give). The Label
        // Length field must match the bytes writeString emits, or the receiver mis-slices.
        val open =
            DataChannelMessage.Open(
                channelType = ChannelType.of(true, Reliability.Reliable),
                priority = 0u,
                reliabilityParameter = 0u,
                label = "chat-😀", // "chat-😀"
                protocol = "x🚀", // "x🚀"
            )
        val enc = open.encode()
        enc.position(0)
        val decoded = assertIs<DataChannelMessage.Open>(assertIs<DataChannelDecodeResult.Success>(decode(enc)).message)
        assertEquals("chat-😀", decoded.label)
        assertEquals("x🚀", decoded.protocol)
    }

    @Test
    fun ackRoundTrips() {
        val enc = DataChannelMessage.Ack.encode()
        assertEquals(listOf(0x02), enc.toIntList())
        enc.position(0)
        assertIs<DataChannelMessage.Ack>(assertIs<DataChannelDecodeResult.Success>(decode(enc)).message)
    }

    @Test
    fun channelTypeProjectionIsExhaustiveAndReversible() {
        for (raw in 0..0xFF) {
            val ct = ChannelType(raw.toUByte())
            // of(ordered, reliability) must reproduce the raw byte for the four known encodings; for an
            // unknown low value it reproduces via Reliability.Unknown(lowBits).
            val rebuilt = ChannelType.of(ct.ordered, ct.reliability)
            assertEquals(ct.raw, rebuilt.raw, "channel type 0x${raw.toString(16)} did not round-trip through its projection")
        }
        assertEquals(Reliability.Reliable, ChannelType(0x00u).reliability)
        assertEquals(Reliability.PartialReliableRetransmit, ChannelType(0x01u).reliability)
        assertEquals(Reliability.PartialReliableTimed, ChannelType(0x82u).reliability)
        assertIs<Reliability.Unknown>(ChannelType(0x7Fu).reliability)
    }

    @Test
    fun emptyPayloadIsRejected() {
        assertReject<DataChannelRejectReason.Empty>(bufferOf())
    }

    @Test
    fun unknownMessageTypeIsRejected() {
        assertReject<DataChannelRejectReason.UnknownMessageType>(bufferOf(0x99))
    }

    @Test
    fun openTooShortIsRejected() {
        assertReject<DataChannelRejectReason.OpenTooShort>(bufferOf(0x03, 0x00, 0x00, 0x00))
    }

    @Test
    fun labelProtocolBeyondMessageIsRejected() {
        // OPEN header claims a 100-byte label but the payload ends at the header.
        val bytes = bufferOfHex("03000000" + "00000000" + "0064" + "0000")
        assertReject<DataChannelRejectReason.LabelProtocolBeyondMessage>(bytes)
    }

    @Test
    fun invalidUtf8LabelIsRejected() {
        // label length 2, bytes 0xFF 0xFE — not valid UTF-8.
        val bytes = bufferOfHex("03000000" + "00000000" + "0002" + "0000" + "fffe")
        assertReject<DataChannelRejectReason.InvalidUtf8>(bytes)
    }

    private inline fun <reified R : DataChannelRejectReason> assertReject(bytes: com.ditchoom.buffer.ReadBuffer) {
        val r = assertIs<DataChannelDecodeResult.Reject>(decode(bytes))
        assertIs<R>(r.reason)
    }
}

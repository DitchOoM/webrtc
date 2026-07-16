package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.sctp.DataChunkFlags
import com.ditchoom.webrtc.sctp.ForwardTsnStream
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.StreamSequenceNumber
import com.ditchoom.webrtc.sctp.Tsn
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Regression fixtures for the [ReassemblyQueue] defects the W5 adversarial-review gate found (directive
 * #5 — every fix ships its deterministic fixture). Each test fails against the pre-fix code.
 */
class ReassemblyQueueTest {
    private val stream0 = StreamId(0)

    private fun data(
        tsn: Int,
        ssn: Int = 0,
        streamId: StreamId = stream0,
        beginning: Boolean = true,
        ending: Boolean = true,
        unordered: Boolean = false,
        immediate: Boolean = false,
        payload: ReadBuffer = payload(4, seed = tsn),
    ): SctpChunk.Data =
        SctpChunk.Data(
            flags = DataChunkFlags.of(beginning = beginning, ending = ending, unordered = unordered, immediate = immediate),
            tsn = Tsn(tsn.toUInt()),
            streamId = streamId,
            streamSequenceNumber = StreamSequenceNumber(ssn.toUShort()),
            payloadProtocolId = PayloadProtocolId.WebRtcBinary,
            userData = payload,
        )

    // R3-F1: a received TSN more than 65535 above the (stalled) cumulative point must NOT produce a
    // malformed gap block (offset wraps to a u16 with end < start) — it is simply omitted.
    @Test
    fun gap_block_beyond_u16_offset_is_omitted_not_malformed() {
        val q = ReassemblyQueue(peerInitialTsn = Tsn(100u), config = SctpConfig())
        // TSN 100 is missing, so the cumulative point stays at 99 forever.
        q.receive(data(tsn = 200)) // offset 101 — a representable gap block
        q.receive(data(tsn = 100_000)) // offset 99901 — beyond a u16, must be dropped from the SACK

        val sack = q.buildSack()
        assertEquals(Tsn(99u), sack.cumulativeTsnAck)
        assertTrue(sack.gapAckBlocks.all { it.end >= it.start }, "no malformed (end < start) gap block")
        assertTrue(
            sack.gapAckBlocks.all { (it.start.toInt() and 0xFFFF) <= 0xFFFF && (it.end.toInt() and 0xFFFF) <= 0xFFFF },
            "all offsets fit u16",
        )
        // The representable near gap is reported; the far one is not.
        assertEquals(1, sack.gapAckBlocks.size, "only the in-range gap block is emitted")
        assertEquals(
            101,
            sack.gapAckBlocks
                .first()
                .start
                .toInt(),
            "offset of TSN 200 above cum 99",
        )
    }

    // R3-F3: RFC 7053 SACK-IMMEDIATELY 'I' bit forces a prompt SACK even for perfectly in-order data.
    @Test
    fun i_bit_requests_immediate_sack() {
        val q = ReassemblyQueue(peerInitialTsn = Tsn(1u), config = SctpConfig())
        q.receive(data(tsn = 1, immediate = false))
        // In-order, no I-bit → delayed SACK is fine.
        assertTrue(!q.sackImmediatelyRequested, "in-order non-immediate data does not force a SACK")
        q.buildSack()
        q.receive(data(tsn = 2, immediate = true))
        assertTrue(q.sackImmediatelyRequested, "the I bit forces an immediate SACK (RFC 7053)")
    }

    // R3-F5: a B..E run whose fragments claim different streams must not be spliced into one message.
    @Test
    fun fragments_from_different_streams_are_not_spliced() {
        val q = ReassemblyQueue(peerInitialTsn = Tsn(1u), config = SctpConfig())
        val begin = data(tsn = 1, streamId = StreamId(1), beginning = true, ending = false, unordered = true)
        val end = data(tsn = 2, streamId = StreamId(2), beginning = false, ending = true, unordered = true)
        val delivered = q.receive(begin) + q.receive(end)
        assertEquals(0, delivered.size, "a stream-discontinuous B..E run is not assembled")
    }

    // R3-F6: a FORWARD-TSN that skips past an already-reassembled-but-held ordered message drops it,
    // rather than leaving it stuck in the ordered-ready map, and delivery resumes at the new SSN.
    @Test
    fun forward_tsn_drops_held_ordered_message_it_skips() {
        val q = ReassemblyQueue(peerInitialTsn = Tsn(1u), config = SctpConfig())
        // Deliver ordered ssn=1 first (held: we still expect ssn=0).
        val held = q.receive(data(tsn = 2, ssn = 1))
        assertEquals(0, held.size, "ssn=1 is held while ssn=0 is missing")
        // Peer abandons ssn=0 and ssn=1: FORWARD-TSN to cum TSN 2, stream0 skip to ssn 1.
        val afterForward = q.onForwardTsn(Tsn(2u), listOf(ForwardTsnStream(stream0, StreamSequenceNumber(1u))))
        assertEquals(0, afterForward.size, "the skipped-over held message is dropped, not delivered")
        // A subsequent ssn=2 delivers immediately (expected advanced past the skip).
        val next = q.receive(data(tsn = 3, ssn = 2))
        assertEquals(1, next.size, "delivery resumes at the SSN after the skip")
    }
}

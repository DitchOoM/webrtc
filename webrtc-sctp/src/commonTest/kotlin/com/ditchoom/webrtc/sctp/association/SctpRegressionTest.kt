@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.ForwardTsnStream
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.SctpDecodeResult
import com.ditchoom.webrtc.sctp.SctpPacket
import com.ditchoom.webrtc.sctp.SctpPacketBuilder
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.StreamSequenceNumber
import com.ditchoom.webrtc.sctp.Tsn
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Association-level regression fixtures for the W5 adversarial-review finds (directive #5). Each drives
 * a real established association with a crafted packet and asserts the fixed behavior.
 */
class SctpRegressionTest {
    private val now = Instant.fromEpochSeconds(10)

    private fun established(): SctpSim {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        check(sim.a.state == SctpAssociationState.Established)
        return sim
    }

    private fun outputsToPackets(outputs: List<SctpOutput>): List<SctpPacket> =
        outputs.filterIsInstance<SctpOutput.Transmit>().mapNotNull {
            it.packet.position(0)
            (SctpPacket.decode(it.packet.slice()) as? SctpDecodeResult.Success)?.packet
        }

    // R2-F5: a peer that lost its TCB reflects OUR verification tag (peerVerificationTag) in a T-bit
    // ABORT; the tag gate must accept it and tear the association down, not silently drop it.
    @Test
    fun reflected_t_bit_abort_tears_down() {
        val sim = established()
        val reflected =
            SctpPacketBuilder(
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                sim.a.peerVerificationTag, // the tag the restarted peer saw on our packets
            ).add(SctpChunk.Abort(verificationTagReflected = true, causes = emptyList())).encode()

        reflected.position(0)
        val outputs = sim.a.handle(SctpEvent.DatagramReceived(reflected.slice()), now)

        assertTrue(outputs.any { it is SctpOutput.Aborted && it.reason == SctpFailureReason.AbortReceived }, "reflected ABORT accepted")
        assertEquals(SctpAssociationState.Closed, sim.a.state)
    }

    // R2-F5 negative: a T-bit ABORT carrying neither of our tags is still rejected (no teardown).
    @Test
    fun abort_with_wrong_tag_is_ignored() {
        val sim = established()
        val bogusTag =
            com.ditchoom.webrtc.sctp
                .VerificationTag(0xDEADBEEFu)
        val abort =
            SctpPacketBuilder(SctpAssociation.SCTP_DATA_CHANNEL_PORT, SctpAssociation.SCTP_DATA_CHANNEL_PORT, bogusTag)
                .add(SctpChunk.Abort(verificationTagReflected = true, causes = emptyList()))
                .encode()
        abort.position(0)
        val outputs = sim.a.handle(SctpEvent.DatagramReceived(abort.slice()), now)
        assertTrue(outputs.none { it is SctpOutput.Aborted }, "an ABORT with an unknown tag is dropped")
        assertEquals(SctpAssociationState.Established, sim.a.state)
    }

    // R2-F1: a packet carrying ONLY a FORWARD-TSN (no bundled DATA) must still elicit an immediate SACK
    // (RFC 3758 §3.6) — before the fix, a SACK was emitted only when the packet also carried DATA, so the
    // peer's advanced-ack point was never confirmed and partial-reliability progress stalled.
    @Test
    fun lone_forward_tsn_elicits_a_sack() {
        val sim = established()
        val forward =
            SctpPacketBuilder(
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                sim.a.localVerificationTag, // packets TO a carry a's local tag
            ).add(
                SctpChunk.ForwardTsn(Tsn(1u), listOf(ForwardTsnStream(StreamId(0), StreamSequenceNumber(0u)))),
            ).encode()

        forward.position(0)
        val outputs = sim.a.handle(SctpEvent.DatagramReceived(forward.slice()), now)
        val sacks = outputsToPackets(outputs).flatMap { it.chunks }.filterIsInstance<SctpChunk.Sack>()
        assertEquals(1, sacks.size, "a lone FORWARD-TSN is answered with a SACK")
    }
}

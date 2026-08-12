@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.ErrorCauseCode
import com.ditchoom.webrtc.sctp.ParameterType
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.SctpDecodeResult
import com.ditchoom.webrtc.sctp.SctpErrorCause
import com.ditchoom.webrtc.sctp.SctpPacket
import com.ditchoom.webrtc.sctp.SctpPacketBuilder
import com.ditchoom.webrtc.sctp.SctpParameter
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.Tsn
import com.ditchoom.webrtc.sctp.VerificationTag
import com.ditchoom.webrtc.sctp.bufferOf
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The RFC 4960 §5.1.1 stream negotiation, now that both of its minima are settled and the inbound one is
 * enforced.
 *
 * The two minima are `min(our MIS, the peer's OS)` for what may arrive and `min(our OS, the peer's MIS)`
 * for what may leave, and every fixture in this module before this one ran a **symmetric** configuration,
 * where the two coincide. That is the whole reason the outbound half went unnoticed: an implementation
 * that computed one number and used it for both directions passes the entire corpus.
 */
class StreamCapacityTest {
    private val now = Instant.fromEpochSeconds(10)
    private val port = SctpAssociation.SCTP_DATA_CHANNEL_PORT

    // ── the two minima ──

    /**
     * Asymmetric on purpose, and asymmetric in a way that makes the two minima *swap* rather than merely
     * differ: A may send on 100 streams and receive on 50, B the mirror image. A single number used for
     * both directions reports one side's inbound count as its outbound one, which this catches; equal
     * numbers would not.
     */
    @Test
    fun each_endpoint_settles_its_outgoing_capacity_from_the_peers_maximum_inbound() {
        val sim =
            SctpSim(
                config = SctpConfig(outboundStreams = 300u, inboundStreams = 700u),
                configB = SctpConfig(outboundStreams = 50u, inboundStreams = 100u),
            )
        sim.associateA()
        sim.run()

        assertEquals(SctpAssociationState.Established, sim.a.state)
        assertEquals(SctpAssociationState.Established, sim.b.state)

        assertEquals(
            OutgoingStreamCapacity.Negotiated(StreamCount(100u)),
            sim.a.outgoingCapacity,
            "A may use min(its OS 300, B's MIS 100) outgoing streams",
        )
        assertEquals(
            OutgoingStreamCapacity.Negotiated(StreamCount(50u)),
            sim.b.outgoingCapacity,
            "B — a responder that kept no TCB across the handshake — may use min(its OS 50, A's MIS 700)",
        )
        assertEquals(50u.toUShort(), sim.a.negotiatedInboundStreams, "A receives on min(its MIS 700, B's OS 50)")
        assertEquals(100u.toUShort(), sim.b.negotiatedInboundStreams, "B receives on min(its MIS 100, A's OS 300)")

        // The property that makes the pair meaningful: one side's outgoing count IS the other's incoming
        // count. Disagreement here is a channel that opens and never delivers.
        assertEquals(
            (sim.a.outgoingCapacity as OutgoingStreamCapacity.Negotiated).streams.value,
            sim.b.negotiatedInboundStreams,
            "what A may send on must be what B will accept",
        )
        assertEquals(
            (sim.b.outgoingCapacity as OutgoingStreamCapacity.Negotiated).streams.value,
            sim.a.negotiatedInboundStreams,
            "and the reverse",
        )
    }

    @Test
    fun the_capacity_is_announced_once_the_handshake_settles_it() {
        val sim = SctpSim(config = SctpConfig(outboundStreams = 12u, inboundStreams = 12u))
        assertEquals(OutgoingStreamCapacity.NotNegotiated, sim.a.outgoingCapacity, "nothing is negotiated before the handshake")
        sim.associateA()
        sim.run()

        assertEquals(
            listOf(OutgoingStreamCapacity.Negotiated(StreamCount(12u))),
            sim.capacitiesA,
            "the allocator above this layer is told the ceiling, exactly once, when it comes into existence",
        )
        assertEquals(listOf(OutgoingStreamCapacity.Negotiated(StreamCount(12u))), sim.capacitiesB)
    }

    @Test
    fun a_teardown_takes_the_negotiated_capacity_with_it() {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        assertTrue(sim.a.outgoingCapacity is OutgoingStreamCapacity.Negotiated, "the fixture needs a settled capacity")

        sim.a.close()
        assertEquals(
            OutgoingStreamCapacity.NotNegotiated,
            sim.a.outgoingCapacity,
            "a capacity believed of a departed peer must not survive into the next association",
        )
        assertEquals(PeerExtensions.None, sim.a.peerExtensions, "nor may its advertised extensions")
    }

    // ── the zero-stream abort, on both chunks ──

    /**
     * RFC 4960 §3.3.2 forbids zero in either stream field, and until now only the INIT arm was checked —
     * so the *initiator* was the one role that could not see the violation. Both fields, both roles: four
     * cases, each of which would otherwise establish an association that can carry nothing.
     */
    @Test
    fun an_init_ack_advertising_zero_streams_aborts_the_association() {
        for (outbound in listOf(0u.toUShort(), 8u.toUShort())) {
            for (inbound in listOf(0u.toUShort(), 8u.toUShort())) {
                val zero = outbound == 0u.toUShort() || inbound == 0u.toUShort()
                val association = SctpAssociation(SctpConfig(), Random(7))
                association.handle(SctpEvent.Associate, now)
                val outputs = association.handle(SctpEvent.DatagramReceived(initAck(association, outbound, inbound)), now)

                val aborted = outputs.filterIsInstance<SctpOutput.Aborted>().map { it.reason }
                if (zero) {
                    assertEquals(
                        listOf(SctpFailureReason.ProtocolViolation(ProtocolViolationKind.ZeroStreams)),
                        aborted,
                        "an INIT ACK advertising OS=$outbound MIS=$inbound is a §3.3.2 violation",
                    )
                    assertTrue(
                        chunksOf(outputs).any { it is SctpChunk.Abort },
                        "the peer is told, rather than left waiting on a handshake we abandoned",
                    )
                } else {
                    // The discriminating half. Without it this test passes just as green on an association
                    // that aborts on every INIT ACK it is ever shown.
                    assertTrue(aborted.isEmpty(), "a well-formed INIT ACK is not a violation")
                    assertEquals(SctpAssociationState.CookieEchoed, association.state, "…it advances the handshake")
                }
            }
        }
    }

    // ── the inbound guard ──

    /**
     * A DATA chunk on a stream the association never negotiated is refused with an RFC 4960 §3.3.10.1
     * ERROR and delivers nothing. The stream count was settled and then read by nothing at all until now,
     * so a peer could open reassembly state on any of 65536 ids whatever it agreed to.
     *
     * The in-range arm is what gives the out-of-range one its meaning: id 3 is the highest the negotiated
     * count of 4 admits, so "refused" here is a statement about the boundary rather than about the
     * association having stopped delivering.
     */
    @Test
    fun a_data_chunk_above_the_negotiated_stream_count_is_refused_with_an_error() {
        val sim = established(streams = 4u)

        val admitted = handToB(sim, StreamId(3))
        assertEquals(1, admitted.outputs.filterIsInstance<SctpOutput.MessageReceived>().size, "id 3 is inside a count of 4")
        assertTrue(causesIn(admitted.outputs).isEmpty(), "…and draws no ERROR")

        val refused = handToB(sim, StreamId(4))
        assertTrue(
            refused.outputs.filterIsInstance<SctpOutput.MessageReceived>().isEmpty(),
            "id 4 is outside a count of 4 and must not be delivered",
        )
        val cause = causesIn(refused.outputs).single()
        assertEquals(ErrorCauseCode.InvalidStreamIdentifier, cause.code, "RFC 4960 §3.3.10.1")
        assertEquals(
            listOf(0, 4, 0, 0),
            cause.value.let { view -> (view.position() until view.limit()).map { view[it].toInt() and 0xFF } },
            "the cause names the offending stream id, then two reserved bytes",
        )
    }

    /**
     * The refused chunk's TSN is still acknowledged. Without this the receiver's cumulative point sits
     * below a chunk the sender will now retransmit forever — so one out-of-range stream costs the
     * association's whole error budget, and with it every other data channel on it.
     */
    @Test
    fun a_refused_data_chunk_is_still_acknowledged() {
        val sim = established(streams = 4u)
        val refused = handToB(sim, StreamId(4))

        // The SACK is delayed (RFC 4960 §6.2) rather than immediate for a chunk that arrived in order, so
        // the timer is what puts it on the wire. Observable state plus a fired timer — never a budget.
        val sacked = sim.b.handle(SctpEvent.TimerFired, sim.now + 1.seconds)
        val sack = chunksOf(sacked).filterIsInstance<SctpChunk.Sack>().single()
        assertEquals(
            refused.tsn,
            sack.cumulativeTsnAck,
            "the cumulative point advanced over the refused TSN; leaving it behind invites an endless retransmit",
        )
        assertTrue(sack.gapAckBlocks.isEmpty(), "and it left no gap for the sender to fill")
    }

    // ── helpers ──

    private fun established(streams: UShort): SctpSim {
        val sim = SctpSim(config = SctpConfig(outboundStreams = streams, inboundStreams = streams))
        sim.associateA()
        sim.run()
        check(sim.a.state == SctpAssociationState.Established)
        check(sim.b.state == SctpAssociationState.Established)
        return sim
    }

    private class Handoff(
        val tsn: Tsn,
        val outputs: List<SctpOutput>,
    )

    /**
     * One user message from A, handed to B directly rather than through the sim's routing, so B's *own*
     * outputs — the ERROR it answers with — are visible. The sim's copy of the same datagram is suppressed
     * while the send runs, or B would see the same TSN twice and the second one as a duplicate.
     */
    private fun handToB(
        sim: SctpSim,
        streamId: StreamId,
    ): Handoff {
        sim.dropFilter = { toA -> !toA }
        val sent = sim.post(toA = true, SctpEvent.SendMessage(SctpSendOptions(streamId, PayloadProtocolId.WebRtcBinary), payload(8)))
        sim.dropFilter = null
        val tsn = chunksOf(sent).filterIsInstance<SctpChunk.Data>().single().tsn
        val received =
            sent.filterIsInstance<SctpOutput.Transmit>().flatMap {
                it.packet.position(0)
                sim.b.handle(SctpEvent.DatagramReceived(it.packet.slice()), sim.now)
            }
        return Handoff(tsn, received)
    }

    private fun chunksOf(outputs: List<SctpOutput>): List<SctpChunk> =
        outputs
            .filterIsInstance<SctpOutput.Transmit>()
            .mapNotNull {
                it.packet.position(0)
                (SctpPacket.decode(it.packet.slice()) as? SctpDecodeResult.Success)?.packet
            }.flatMap { it.chunks }

    private fun causesIn(outputs: List<SctpOutput>): List<SctpErrorCause> =
        chunksOf(outputs).filterIsInstance<SctpChunk.Error>().flatMap { it.causes }

    // An INIT ACK addressed to [association], carrying a State Cookie it will echo verbatim. The cookie's
    // contents are irrelevant to the initiator, which only ever copies the bytes back.
    private fun initAck(
        association: SctpAssociation,
        outboundStreams: UShort,
        inboundStreams: UShort,
    ) = SctpPacketBuilder(port, port, association.localVerificationTag)
        .add(
            SctpChunk.InitAck(
                initiateTag = VerificationTag(0xABCDEF01u),
                advertisedReceiverWindow = 65536u,
                outboundStreams = outboundStreams,
                inboundStreams = inboundStreams,
                initialTsn = Tsn(1000u),
                parameters = listOf(SctpParameter.ofValue(ParameterType.StateCookie, bufferOf(1, 2, 3, 4))),
            ),
        ).encode()
        .also { it.position(0) }
        .slice()
}

@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.DeliveryOrder
import com.ditchoom.webrtc.sctp.ParameterType
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.ReConfigParameter
import com.ditchoom.webrtc.sctp.ReConfigParameterDecode
import com.ditchoom.webrtc.sctp.ReConfigRequestSequenceNumber
import com.ditchoom.webrtc.sctp.ReConfigResult
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.SctpDecodeResult
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
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * RFC 6525 §4.5 / §4.6 stream-count growth, in both directions.
 *
 * Two of the four requests this subset used to refuse outright are now honoured, and the reason they
 * could be is C1's: the association finally *has* stream counts, so "add four" has something to add to.
 * The requester was generalized to carry either kind of request because §5.1.2 gives a reset and an
 * increase one outstanding-request slot between them — modelling them as two state machines would put
 * both on the wire at once and have the peer answer the second with `ErrorRequestAlreadyInProgress`.
 */
class StreamGrowthTest {
    private val now = Instant.fromEpochSeconds(10)

    private fun established(streams: UShort = 8u): SctpSim {
        val sim = SctpSim(config = SctpConfig(outboundStreams = streams, inboundStreams = streams))
        sim.associateA()
        sim.run()
        check(sim.a.state == SctpAssociationState.Established)
        check(sim.b.state == SctpAssociationState.Established)
        return sim
    }

    // ── originating (RFC 6525 §4.5) ──

    @Test
    fun a_granted_increase_raises_the_outgoing_capacity_on_the_asking_side_only() {
        val sim = established()
        sim.post(toA = true, SctpEvent.RequestMoreOutgoingStreams(StreamCount(4u)))
        sim.run()

        assertEquals(
            listOf(SctpOutput.OutgoingStreamsAdded(StreamCount(4u), StreamAddOutcome.Performed)),
            sim.streamsAddedA,
            "A asked and the peer performed it",
        )
        assertEquals(
            OutgoingStreamCapacity.Negotiated(StreamCount(12u)),
            sim.a.outgoingCapacity,
            "A may now send on 8 + 4 streams",
        )
        assertEquals(
            listOf(OutgoingStreamCapacity.Negotiated(StreamCount(8u)), OutgoingStreamCapacity.Negotiated(StreamCount(12u))),
            sim.capacitiesA,
            "…and the allocator above it was told, once per change",
        )

        // The other half of the same agreement: B raised what it will ACCEPT, not what it may send.
        assertEquals(12u.toUShort(), sim.b.negotiatedInboundStreams, "B accepts on the streams A gained")
        assertEquals(
            OutgoingStreamCapacity.Negotiated(StreamCount(8u)),
            sim.b.outgoingCapacity,
            "B's own outgoing count is untouched — growth is one-directional",
        )
        assertEquals(
            listOf(OutgoingStreamCapacity.Negotiated(StreamCount(8u))),
            sim.capacitiesB,
            "so B announces nothing beyond the handshake settlement it already made",
        )
    }

    /**
     * The increase reaches the guard, not just the counter. Stream 8 is outside the handshake's count of 8
     * and refused; after the increase the same id is delivered. Both halves are needed — the first proves
     * the boundary was real, the second that the growth moved it.
     */
    @Test
    fun a_stream_id_the_handshake_refused_is_delivered_after_the_increase() {
        val sim = established()
        val beyond = StreamId(8)

        sim.post(
            toA = true,
            SctpEvent.SendMessage(SctpSendOptions(beyond, PayloadProtocolId.WebRtcBinary, DeliveryOrder.Unordered), payload(8)),
        )
        sim.run()
        assertTrue(sim.inboxB.isEmpty(), "stream 8 is outside a negotiated count of 8")

        sim.post(toA = true, SctpEvent.RequestMoreOutgoingStreams(StreamCount(4u)))
        sim.run()
        sim.post(
            toA = true,
            SctpEvent.SendMessage(SctpSendOptions(beyond, PayloadProtocolId.WebRtcBinary, DeliveryOrder.Unordered), payload(8)),
        )
        sim.run()
        assertEquals(listOf(beyond), sim.inboxB.map { it.streamId }, "…and inside a count of 12 it is delivered")
    }

    /**
     * A peer that never advertised RE-CONFIG is never sent one (RFC 6525 §5.1), and the caller is still
     * answered — the same rule a stream reset already followed, for the same reason: a request nobody can
     * put on the wire still has to complete, or the open waiting on it waits forever.
     */
    @Test
    fun a_peer_that_never_advertised_reconfig_is_never_asked_and_the_caller_is_still_answered() {
        val association = withoutReConfig()
        val outputs = association.handle(SctpEvent.RequestMoreOutgoingStreams(StreamCount(4u)), now)

        assertEquals(
            listOf(SctpOutput.OutgoingStreamsAdded(StreamCount(4u), StreamAddOutcome.NotAdded.Unsupported)),
            outputs.filterIsInstance<SctpOutput.OutgoingStreamsAdded>(),
        )
        assertTrue(reConfigChunks(outputs).isEmpty(), "…and nothing was put in front of a peer that cannot read it")
    }

    @Test
    fun asking_for_zero_streams_is_a_no_op_rather_than_a_request() {
        val sim = established()
        sim.post(toA = true, SctpEvent.RequestMoreOutgoingStreams(StreamCount.None))
        sim.run()
        assertTrue(sim.streamsAddedA.isEmpty(), "RFC 6525 §4.5 cannot express a zero count, so there is nothing to ask")
        assertEquals(OutgoingStreamCapacity.Negotiated(StreamCount(8u)), sim.a.outgoingCapacity)
    }

    @Test
    fun an_increase_past_the_sixteen_bit_ceiling_is_refused_before_it_reaches_the_wire() {
        val sim = established(streams = 0xFFFFu)
        sim.post(toA = true, SctpEvent.RequestMoreOutgoingStreams(StreamCount(1u)))
        sim.run()

        assertEquals(
            listOf(SctpOutput.OutgoingStreamsAdded(StreamCount(1u), StreamAddOutcome.NotAdded.WouldOverflow)),
            sim.streamsAddedA,
            "the negotiated total is a u16 and there is nothing truthful to ask for",
        )
        assertEquals(
            OutgoingStreamCapacity.Negotiated(StreamCount.Max),
            sim.a.outgoingCapacity,
            "refused, not clamped — a clamp would report success for an increase the caller did not get",
        )
    }

    /**
     * A reset and an increase asked for together share RFC 6525 §5.1.2's single outstanding-request slot,
     * and both complete. The one-at-a-time rule is what the generalized requester exists for; without it
     * the second request either overwrites the first or races it onto the wire.
     */
    @Test
    fun a_reset_and_an_increase_asked_for_together_both_complete_one_at_a_time() {
        val sim = established()
        val stream = StreamId(1)
        val requests =
            sim.post(toA = true, SctpEvent.ResetStreams(StreamResetScope.Streams(setOf(stream)))) +
                sim.post(toA = true, SctpEvent.RequestMoreOutgoingStreams(StreamCount(4u)))
        // Exactly one RE-CONFIG chunk left the association for the two asks (§5.1.2).
        assertEquals(1, reConfigChunks(requests).size, "only one request may be outstanding at a time")

        sim.run()
        assertEquals(
            listOf(StreamResetOutcome.Performed),
            sim.outgoingResetsA.map { it.outcome },
            "the reset completed",
        )
        assertEquals(
            listOf(StreamAddOutcome.Performed),
            sim.streamsAddedA.map { it.outcome },
            "…and so did the increase queued behind it",
        )
        assertEquals(OutgoingStreamCapacity.Negotiated(StreamCount(12u)), sim.a.outgoingCapacity)
    }

    // ── honouring (RFC 6525 §4.5 / §4.6) ──

    @Test
    fun a_peers_add_outgoing_request_raises_what_this_endpoint_accepts() {
        val sim = established()
        val sequence = ReConfigRequestSequenceNumber(500u)
        val outputs = deliverToA(sim, ReConfigParameter.AddOutgoingStreams(sequence, 4u))

        assertEquals(ReConfigResult.SuccessPerformed, responsesIn(outputs).single().result)
        assertEquals(12u.toUShort(), sim.a.negotiatedInboundStreams, "the peer may now send on 4 more streams")
        assertEquals(
            OutgoingStreamCapacity.Negotiated(StreamCount(8u)),
            sim.a.outgoingCapacity,
            "and asking to send on more does not grant us more to send on",
        )
        assertTrue(
            outputs.filterIsInstance<SctpOutput.OutgoingCapacityChanged>().isEmpty(),
            "nothing above this layer needs to hear about an inbound-only change",
        )
    }

    @Test
    fun a_peers_add_incoming_request_raises_what_this_endpoint_may_send_on() {
        val sim = established()
        val sequence = ReConfigRequestSequenceNumber(500u)
        val outputs = deliverToA(sim, ReConfigParameter.AddIncomingStreams(sequence, 4u))

        assertEquals(ReConfigResult.SuccessPerformed, responsesIn(outputs).single().result)
        assertEquals(
            OutgoingStreamCapacity.Negotiated(StreamCount(12u)),
            sim.a.outgoingCapacity,
            "the peer asked to receive on more, which is us sending on more",
        )
        assertEquals(
            listOf(OutgoingStreamCapacity.Negotiated(StreamCount(12u))),
            outputs.filterIsInstance<SctpOutput.OutgoingCapacityChanged>().map { it.capacity },
            "…and the allocator above must hear about it, or the new ids are never used",
        )
        assertEquals(8u.toUShort(), sim.a.negotiatedInboundStreams, "what we accept is unchanged")
    }

    /**
     * The load-bearing one. A retransmitted add request is answered from the §5.2.1 response cache rather
     * than performed again — and a second increase would be **silent**, because both answers are Success.
     * The two endpoints would simply disagree about how many streams exist, which is the disagreement the
     * repeat rule exists to prevent and the reason these requests go through `admit` at all.
     */
    @Test
    fun a_retransmitted_add_request_is_answered_again_but_not_applied_again() {
        val sim = established()
        val sequence = ReConfigRequestSequenceNumber(500u)
        val request = ReConfigParameter.AddOutgoingStreams(sequence, 4u)

        assertEquals(ReConfigResult.SuccessPerformed, responsesIn(deliverToA(sim, request)).single().result)
        assertEquals(12u.toUShort(), sim.a.negotiatedInboundStreams)

        val repeat = deliverToA(sim, request)
        assertEquals(
            ReConfigResult.SuccessPerformed,
            responsesIn(repeat).single().result,
            "§5.2.1: the same answer is repeated, so the peer stops retransmitting",
        )
        assertEquals(12u.toUShort(), sim.a.negotiatedInboundStreams, "…and the count is not raised a second time")
    }

    @Test
    fun a_request_for_zero_streams_or_one_that_would_overflow_is_denied() {
        for ((count, streams) in listOf(0u.toUShort() to 8u.toUShort(), 1u.toUShort() to 0xFFFFu.toUShort())) {
            val sim = established(streams = streams)
            val outputs = deliverToA(sim, ReConfigParameter.AddOutgoingStreams(ReConfigRequestSequenceNumber(500u), count))
            assertEquals(
                ReConfigResult.Denied,
                responsesIn(outputs).single().result,
                "count=$count against $streams streams is not something we can perform",
            )
            assertEquals(streams, sim.a.negotiatedInboundStreams, "and nothing changed")
        }
    }

    // ── growth policy at the data-channel layer is covered by StreamGrowthPolicyTest ──

    private fun packetsOf(outputs: List<SctpOutput>): List<SctpPacket> =
        outputs.filterIsInstance<SctpOutput.Transmit>().mapNotNull {
            it.packet.position(0)
            (SctpPacket.decode(it.packet.slice()) as? SctpDecodeResult.Success)?.packet
        }

    private fun reConfigChunks(outputs: List<SctpOutput>): List<SctpChunk.ReConfig> =
        packetsOf(outputs).flatMap { it.chunks }.filterIsInstance<SctpChunk.ReConfig>()

    private fun responsesIn(outputs: List<SctpOutput>): List<ReConfigParameter.Response> =
        reConfigChunks(outputs)
            .flatMap { it.reConfigParameters() }
            .filterIsInstance<ReConfigParameterDecode.Interpreted>()
            .map { it.parameter }
            .filterIsInstance<ReConfigParameter.Response>()

    // A RE-CONFIG chunk delivered to endpoint A as if from its peer, stamped with A's own Verification Tag.
    private fun deliverToA(
        sim: SctpSim,
        vararg parameters: ReConfigParameter,
    ): List<SctpOutput> {
        val packet =
            SctpPacketBuilder(
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                sim.a.localVerificationTag,
            ).add(SctpChunk.ReConfig.of(*parameters)).encode()
        packet.position(0)
        return sim.a.handle(SctpEvent.DatagramReceived(packet.slice()), now)
    }

    /**
     * An established association whose peer advertised **no** Supported Extensions — driven through the
     * real handshake with hand-made chunks, because both endpoints of `SctpSim` run this same code and
     * therefore both always advertise. Everything about it is ordinary except what the INIT ACK omits.
     */
    private fun withoutReConfig(): SctpAssociation {
        val port = SctpAssociation.SCTP_DATA_CHANNEL_PORT
        val association = SctpAssociation(SctpConfig(outboundStreams = 8u, inboundStreams = 8u), Random(9))
        association.handle(SctpEvent.Associate, now)
        val initAck =
            SctpPacketBuilder(port, port, association.localVerificationTag)
                .add(
                    SctpChunk.InitAck(
                        initiateTag = VerificationTag(0x0BADF00Du),
                        advertisedReceiverWindow = 65536u,
                        outboundStreams = 8u,
                        inboundStreams = 8u,
                        initialTsn = Tsn(1000u),
                        parameters = listOf(SctpParameter.ofValue(ParameterType.StateCookie, bufferOf(1, 2, 3, 4))),
                    ),
                ).encode()
        initAck.position(0)
        association.handle(SctpEvent.DatagramReceived(initAck.slice()), now)
        val cookieAck = SctpPacketBuilder(port, port, association.localVerificationTag).add(SctpChunk.CookieAck).encode()
        cookieAck.position(0)
        association.handle(SctpEvent.DatagramReceived(cookieAck.slice()), now)
        check(association.state == SctpAssociationState.Established) { "fixture needs an established association" }
        check(!association.peerExtensions.reConfig) { "fixture needs a peer that advertised no RE-CONFIG" }
        return association
    }
}

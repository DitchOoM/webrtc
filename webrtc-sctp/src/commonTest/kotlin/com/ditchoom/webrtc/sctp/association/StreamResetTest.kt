@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.ParameterType
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.ReConfigParameter
import com.ditchoom.webrtc.sctp.ReConfigParameterDecode
import com.ditchoom.webrtc.sctp.ReConfigRequestSequenceNumber
import com.ditchoom.webrtc.sctp.ReConfigResult
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.SctpChunkType
import com.ditchoom.webrtc.sctp.SctpDecodeResult
import com.ditchoom.webrtc.sctp.SctpPacket
import com.ditchoom.webrtc.sctp.SctpPacketBuilder
import com.ditchoom.webrtc.sctp.SctpParameter
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.Tsn
import com.ditchoom.webrtc.sctp.VerificationTag
import com.ditchoom.webrtc.sctp.asSupportedExtensions
import com.ditchoom.webrtc.sctp.bufferOf
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * RFC 6525 stream reconfiguration end to end: the negotiation that invites it, the request/response
 * exchange, §5.2.2 deferred processing, the §5.2/§5.2.1 sequence rules, the refusals this subset
 * answers with, and the retransmit budget.
 *
 * The observable-state discipline (directive #4) matters here more than usual: a stream reset is
 * *invisible* on a healthy association unless you look at what happens to the Stream Sequence Numbers
 * either side of it, so the load-bearing assertion is message delivery after a reset, not a chunk count.
 */
class StreamResetTest {
    private val now = Instant.fromEpochSeconds(10)
    private val stream = StreamId(1)
    private val scope = StreamResetScope.Streams(setOf(stream))

    private fun established(): SctpSim {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        check(sim.a.state == SctpAssociationState.Established)
        check(sim.b.state == SctpAssociationState.Established)
        return sim
    }

    private fun sendOn(
        sim: SctpSim,
        streamId: StreamId,
        seed: Int,
    ) = sim.post(
        toA = true,
        SctpEvent.SendMessage(SctpSendOptions(streamId, PayloadProtocolId.WebRtcBinary), payload(16, seed)),
    )

    private fun packetsOf(outputs: List<SctpOutput>): List<SctpPacket> =
        outputs.filterIsInstance<SctpOutput.Transmit>().mapNotNull {
            it.packet.position(0)
            (SctpPacket.decode(it.packet.slice()) as? SctpDecodeResult.Success)?.packet
        }

    private fun reConfigChunks(outputs: List<SctpOutput>): List<SctpChunk.ReConfig> =
        packetsOf(outputs).flatMap { it.chunks }.filterIsInstance<SctpChunk.ReConfig>()

    private fun interpreted(outputs: List<SctpOutput>): List<ReConfigParameter> =
        reConfigChunks(outputs)
            .flatMap { it.reConfigParameters() }
            .filterIsInstance<ReConfigParameterDecode.Interpreted>()
            .map { it.parameter }

    // A RE-CONFIG chunk delivered to endpoint A as if from its peer: stamped with A's own Verification
    // Tag, which is what RFC 4960 §8.5 requires of every packet addressed to it.
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

    private fun responsesIn(outputs: List<SctpOutput>): List<ReConfigParameter.Response> =
        interpreted(outputs).filterIsInstance<ReConfigParameter.Response>()

    // ── negotiation (RFC 6525 §5.1) ──

    @Test
    fun init_advertises_reconfig_in_its_supported_extensions() {
        val sim = SctpSim()
        val outputs = sim.post(toA = true, SctpEvent.Associate)
        val init = packetsOf(outputs).flatMap { it.chunks }.filterIsInstance<SctpChunk.Init>().single()
        val extensions = init.parameters.firstNotNullOf { it.asSupportedExtensions() }
        assertTrue(SctpChunkType.ReConfig in extensions, "INIT invites RE-CONFIG (RFC 6525 §5.1)")
        assertTrue(SctpChunkType.ForwardTsn in extensions, "…without dropping the FORWARD-TSN advertisement")
    }

    @Test
    fun init_ack_advertises_reconfig_too() {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        // B answered the INIT; it must have advertised RE-CONFIG in its INIT ACK, or A would never send
        // one. Proven through behaviour: A's reset below reaches B and is performed.
        sim.post(toA = true, SctpEvent.ResetStreams(scope))
        sim.run()
        assertEquals(StreamResetOutcome.Performed, sim.outgoingResetsA.single().outcome)
    }

    // ── the reset itself ──

    /**
     * The load-bearing test. Two ordered messages leave stream 1 at SSN 0 and 1; after the reset, the
     * third leaves at SSN 0 again and must still be delivered.
     *
     * Non-vacuous in **both** directions, which is why it is one test and not two: drop the sender-side
     * reset and A sends SSN 2 to a receiver that now expects 0; drop the receiver-side reset and A's
     * SSN 0 arrives at a receiver still expecting 2. Either way the message is held forever and the
     * final assertion fails.
     */
    @Test
    fun a_reset_restarts_the_stream_sequence_on_both_sides() {
        val sim = established()
        sendOn(sim, stream, seed = 1)
        sendOn(sim, stream, seed = 2)
        sim.run()
        assertEquals(2, sim.inboxB.size, "both pre-reset messages delivered")

        sim.post(toA = true, SctpEvent.ResetStreams(scope))
        sim.run()

        sendOn(sim, stream, seed = 3)
        sim.run()
        assertEquals(3, sim.inboxB.size, "the post-reset message is delivered at SSN 0, not held")
        val last = sim.inboxB.last().payload
        assertEquals(payload(16, 3).bytes(), last.bytes())
    }

    @Test
    fun the_peer_is_notified_of_the_reset_and_the_requester_of_the_outcome() {
        val sim = established()
        sim.post(toA = true, SctpEvent.ResetStreams(scope))
        sim.run()

        assertEquals(listOf<StreamResetScope>(scope), sim.incomingResetsB, "B was told which streams the peer reset")
        val completed = sim.outgoingResetsA.single()
        assertEquals(scope, completed.scope, "the outcome names the scope that was asked for")
        assertEquals(StreamResetOutcome.Performed, completed.outcome)
        assertTrue(sim.incomingResetsA.isEmpty(), "a request is not an incoming reset for its own sender")
    }

    @Test
    fun an_empty_stream_set_is_a_no_op_not_an_all_streams_reset() {
        val sim = established()
        val outputs = sim.post(toA = true, SctpEvent.ResetStreams(StreamResetScope.Streams(emptySet())))
        sim.run()

        assertTrue(reConfigChunks(outputs).isEmpty(), "nothing on the wire for an empty request")
        assertTrue(sim.incomingResetsB.isEmpty(), "and above all, the peer did not reset every stream")
        assertTrue(sim.outgoingResetsA.isEmpty())
    }

    @Test
    fun all_streams_resets_every_stream_the_peer_was_sequencing() {
        val sim = established()
        sendOn(sim, StreamId(1), seed = 1)
        sendOn(sim, StreamId(3), seed = 2)
        sim.run()

        sim.post(toA = true, SctpEvent.ResetStreams(StreamResetScope.AllStreams))
        sim.run()
        assertEquals(listOf<StreamResetScope>(StreamResetScope.AllStreams), sim.incomingResetsB)

        // Both streams restart at SSN 0 and both messages still arrive.
        sendOn(sim, StreamId(1), seed = 3)
        sendOn(sim, StreamId(3), seed = 4)
        sim.run()
        assertEquals(4, sim.inboxB.size)
    }

    // ── RFC 6525 §5.1.2: one outstanding request at a time ──

    @Test
    fun a_second_request_waits_for_the_first_to_be_answered() {
        val sim = established()
        val first = sim.post(toA = true, SctpEvent.ResetStreams(StreamResetScope.Streams(setOf(StreamId(1)))))
        val second = sim.post(toA = true, SctpEvent.ResetStreams(StreamResetScope.Streams(setOf(StreamId(3)))))

        assertEquals(1, reConfigChunks(first).size, "the first request goes out immediately")
        assertTrue(reConfigChunks(second).isEmpty(), "the second is queued behind it (RFC 6525 §5.1.2)")

        sim.run()
        assertEquals(2, sim.outgoingResetsA.size, "both complete, in order")
        assertEquals(StreamResetScope.Streams(setOf(StreamId(1))), sim.outgoingResetsA[0].scope)
        assertEquals(StreamResetScope.Streams(setOf(StreamId(3))), sim.outgoingResetsA[1].scope)
        assertTrue(sim.outgoingResetsA.all { it.outcome == StreamResetOutcome.Performed })
        assertEquals(2, sim.incomingResetsB.size)
    }

    @Test
    fun requests_carry_consecutive_sequence_numbers_seeded_from_the_initial_tsn() {
        val sim = established()
        val first = interpreted(sim.post(toA = true, SctpEvent.ResetStreams(scope)))
        sim.run()
        val second = interpreted(sim.post(toA = true, SctpEvent.ResetStreams(StreamResetScope.Streams(setOf(StreamId(3))))))

        val one = first.filterIsInstance<ReConfigParameter.OutgoingSsnReset>().single()
        val two = second.filterIsInstance<ReConfigParameter.OutgoingSsnReset>().single()
        assertEquals(one.requestSequenceNumber.next(), two.requestSequenceNumber, "§5.1.1: sequence numbers increment")
        assertEquals(listOf(stream), one.streams, "the named stream rides in the request")
        assertFalse(one.resetsAllStreams)
    }

    // ── RFC 6525 §5.2.2: deferred processing ──

    /**
     * A reset whose Sender's Last Assigned TSN names data the receiver has not got yet must be HELD, not
     * performed: performing it would erase the SSN state the missing message is about to be reassembled
     * against. The fixture drops exactly one DATA chunk, then watches the reset wait for its retransmit.
     */
    @Test
    fun a_reset_is_deferred_until_the_missing_data_arrives() {
        val sim = established()
        var dropped = false
        sim.dropFilter = { toA -> if (!toA && !dropped) true.also { dropped = true } else false }
        sendOn(sim, stream, seed = 5)
        sim.post(toA = true, SctpEvent.ResetStreams(scope))
        sim.dropFilter = null

        // Long enough for the RE-CONFIG to arrive and be answered, but well short of the 3s initial RTO
        // that recovers the dropped DATA.
        sim.runUntil(sim.now + 1.seconds)
        assertTrue(sim.inboxB.isEmpty(), "the dropped message has not been recovered yet")
        assertTrue(sim.incomingResetsB.isEmpty(), "so the reset is deferred, not performed (RFC 6525 §5.2.2)")
        assertTrue(sim.outgoingResetsA.isEmpty(), "and the requester is still waiting: 'In progress' is not an answer")

        sim.run()
        assertEquals(1, sim.inboxB.size, "the retransmit filled the gap")
        assertEquals(listOf<StreamResetScope>(scope), sim.incomingResetsB, "…and only then was the reset performed")
        assertEquals(StreamResetOutcome.Performed, sim.outgoingResetsA.single().outcome)
    }

    // ── RFC 6525 §5.2 / §5.2.1: the sequence rules, driven with crafted requests ──

    private fun outgoingRequest(
        sequence: UInt,
        lastAssignedTsn: Tsn = Tsn(0u),
    ) = ReConfigParameter.OutgoingSsnReset(
        requestSequenceNumber = ReConfigRequestSequenceNumber(sequence),
        responseSequenceNumber = ReConfigRequestSequenceNumber(0u),
        // TSN 0 is at or below any cumulative point the fixture reaches, so nothing is deferred here.
        senderLastAssignedTsn = lastAssignedTsn,
        streams = listOf(stream),
    )

    @Test
    fun a_repeated_request_repeats_the_response_without_resetting_twice() {
        val sim = established()
        val first = deliverToA(sim, outgoingRequest(100u))
        val repeat = deliverToA(sim, outgoingRequest(100u))

        assertEquals(ReConfigResult.SuccessPerformed, responsesIn(first).single().result)
        assertEquals(
            ReConfigResult.SuccessPerformed,
            responsesIn(repeat).single().result,
            "§5.2.1: the same request gets the same response",
        )
        val performed = (first + repeat).filterIsInstance<SctpOutput.IncomingStreamsReset>()
        assertEquals(1, performed.size, "…but the reset itself was performed exactly once")
    }

    @Test
    fun an_out_of_sequence_request_is_rejected_and_the_expected_one_still_works() {
        val sim = established()
        deliverToA(sim, outgoingRequest(100u))

        val skipped = deliverToA(sim, outgoingRequest(102u))
        assertEquals(
            ReConfigResult.ErrorBadSequenceNumber,
            responsesIn(skipped).single().result,
            "§5.2: a gap in the request sequence is rejected as such",
        )
        assertTrue(skipped.filterIsInstance<SctpOutput.IncomingStreamsReset>().isEmpty(), "and nothing was reset")

        val next = deliverToA(sim, outgoingRequest(101u))
        assertEquals(ReConfigResult.SuccessPerformed, responsesIn(next).single().result, "the expected one is still accepted")
    }

    @Test
    fun the_first_request_is_accepted_whatever_sequence_number_it_carries() {
        val sim = established()
        // Deliberately nowhere near the peer's Initial TSN. RFC 6525 §5.1.1 says an endpoint seeds from
        // its Initial TSN and every peer we interoperate with does, but rejecting a peer that seeded
        // differently would break every channel close for the life of the association.
        val outputs = deliverToA(sim, outgoingRequest(7u))
        assertEquals(ReConfigResult.SuccessPerformed, responsesIn(outputs).single().result)
        assertEquals(1, outputs.filterIsInstance<SctpOutput.IncomingStreamsReset>().size)
    }

    @Test
    fun the_requests_this_subset_does_not_perform_are_denied_not_ignored() {
        val sim = established()
        val sequence = ReConfigRequestSequenceNumber(500u)
        // The two requests that remain unperformable. The Add Outgoing / Add Incoming pair used to sit
        // here too and is now honoured — see StreamGrowthTest, which asserts both the increase and the
        // §5.2.1 repeat rule that keeps a retransmitted one from applying twice.
        val refused =
            listOf(
                ReConfigParameter.IncomingSsnReset(sequence, listOf(stream)),
                ReConfigParameter.SsnTsnReset(sequence),
            )
        for (request in refused) {
            // Each runs on its own association: they all share one sequence number, and the point here is
            // the refusal, not the ordering rule (which has its own test).
            val outputs = deliverToA(established(), request)
            assertEquals(
                ReConfigResult.Denied,
                responsesIn(outputs).single().result,
                "${request.type} is answered, so the peer stops retransmitting it",
            )
        }
        assertTrue(sim.incomingResetsB.isEmpty())
    }

    @Test
    fun a_malformed_parameter_is_dropped_rather_than_answered_on_a_guessed_sequence_number() {
        val sim = established()
        // An Outgoing SSN Reset body one byte short of its 12-byte fixed prefix: the type is right, so the
        // codec reports Malformed rather than NotReConfig, and there is no trustworthy sequence number to
        // address a response to.
        val truncated = SctpParameter.ofValue(ParameterType.OutgoingSsnResetRequest, bufferOf(0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0))
        val packet =
            SctpPacketBuilder(
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                sim.a.localVerificationTag,
            ).add(SctpChunk.ReConfig(listOf(truncated))).encode()
        packet.position(0)
        val outputs = sim.a.handle(SctpEvent.DatagramReceived(packet.slice()), now)

        assertTrue(reConfigChunks(outputs).isEmpty(), "no response invented for an unaddressable request")
        assertTrue(outputs.filterIsInstance<SctpOutput.IncomingStreamsReset>().isEmpty())
        assertEquals(SctpAssociationState.Established, sim.a.state, "and the association survives it (T0)")
    }

    // ── the retransmit budget (RFC 6525 §5.1.1) ──

    @Test
    fun an_unanswered_request_retransmits_and_then_fails_the_association() {
        val sim = established()
        sim.dropFilter = { toA -> !toA } // the peer hears nothing from here on
        sim.post(toA = true, SctpEvent.ResetStreams(scope))
        sim.run()

        assertEquals(listOf<SctpFailureReason>(SctpFailureReason.RetransmissionLimitReached), sim.abortsA)
        assertEquals(SctpAssociationState.Closed, sim.a.state)
    }

    // ── a peer that never advertised RE-CONFIG ──

    /**
     * Hand-driven rather than run through [SctpSim], because both sim endpoints are ours and both
     * advertise the extension: the only way to model a peer that does not is to be that peer.
     */
    @Test
    fun a_peer_that_did_not_advertise_reconfig_is_never_sent_one() {
        val association = SctpAssociation(SctpConfig(), Random(9))
        association.handle(SctpEvent.Associate, now)

        val initAck =
            SctpChunk.InitAck(
                initiateTag = VerificationTag(0x5EEDu),
                advertisedReceiverWindow = 65_536u,
                outboundStreams = 16u,
                inboundStreams = 16u,
                initialTsn = Tsn(1_000u),
                // No Supported Extensions parameter at all — an RFC 4960 peer that knows nothing of RFC 6525.
                parameters = listOf(SctpParameter.ofValue(ParameterType.StateCookie, bufferOf(1, 2, 3, 4))),
            )
        feed(association, initAck)
        feed(association, SctpChunk.CookieAck)
        check(association.state == SctpAssociationState.Established)

        val outputs = association.handle(SctpEvent.ResetStreams(scope), now)

        assertTrue(reConfigChunks(outputs).isEmpty(), "RFC 6525 §5.1: a RE-CONFIG is only sent to a peer that invited it")
        val completed = outputs.filterIsInstance<SctpOutput.OutgoingStreamsReset>().single()
        assertEquals(StreamResetOutcome.Unsupported, completed.outcome, "…and the close still gets an answer")
        assertEquals(scope, completed.scope)
        // No retransmit timer was armed either: there is no request on the wire to retransmit, and an
        // armed reconfig timer would eventually abort a perfectly healthy association.
        assertEquals(null, association.nextDeadline(now))
    }

    private fun feed(
        association: SctpAssociation,
        chunk: SctpChunk,
    ) {
        val packet =
            SctpPacketBuilder(
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                association.localVerificationTag,
            ).add(chunk).encode()
        packet.position(0)
        association.handle(SctpEvent.DatagramReceived(packet.slice()), now)
    }
}

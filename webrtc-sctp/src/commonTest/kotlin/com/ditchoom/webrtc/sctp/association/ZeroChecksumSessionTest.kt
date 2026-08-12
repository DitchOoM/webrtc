@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.ErrorDetectionMethodId
import com.ditchoom.webrtc.sctp.OutboundChecksum
import com.ditchoom.webrtc.sctp.ParameterType
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.SctpPacket
import com.ditchoom.webrtc.sctp.SctpPacketBuilder
import com.ditchoom.webrtc.sctp.SctpParameter
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.TransportErrorDetection
import com.ditchoom.webrtc.sctp.ZeroChecksumPolicy
import com.ditchoom.webrtc.sctp.bufferOf
import com.ditchoom.webrtc.sctp.u32
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * RFC 9653 through a real association: what actually goes in the checksum field of packets a negotiated
 * session emits, and what happens to a zero that arrives without permission.
 *
 * Every assertion here reads the **wire bytes**, not the association's own belief about what it settled.
 * That distinction is the whole point of a second fixture at this altitude: `ZeroChecksumNegotiationTest`
 * proves the two endpoints agreed, and an implementation could agree perfectly while the encoder ignored
 * the agreement entirely — or, worse, while it applied it to the handshake chunks RFC 9653 §5.2 exempts.
 */
class ZeroChecksumSessionTest {
    private val dtls = TransportErrorDetection.Provided(ErrorDetectionMethodId.ZeroChecksum)
    private val epoch = Instant.fromEpochSeconds(0)

    private fun policy(policy: ZeroChecksumPolicy) = SctpConfig(zeroChecksum = policy)

    /** The checksum field of the first packet in [outputs] (RFC 4960 §3.1, header offset 8). */
    private fun checksumOf(outputs: List<SctpOutput>): UInt {
        val transmit = outputs.filterIsInstance<SctpOutput.Transmit>().first()
        transmit.packet.position(0)
        return transmit.packet.u32(SctpPacket.CHECKSUM_OFFSET)
    }

    /** The first packet in [outputs], as a view the peer can be fed. */
    private fun wire(outputs: List<SctpOutput>): ReadBuffer {
        val transmit = outputs.filterIsInstance<SctpOutput.Transmit>().first()
        transmit.packet.position(0)
        return transmit.packet.slice()
    }

    private fun send(
        sim: SctpSim,
        toA: Boolean,
    ): List<SctpOutput> =
        sim.post(
            toA,
            SctpEvent.SendMessage(
                SctpSendOptions(streamId = StreamId(0), payloadProtocolId = PayloadProtocolId(53u)),
                bufferOf(0xC0, 0xFF, 0xEE),
            ),
        )

    private fun establishedPair(
        aPolicy: ZeroChecksumPolicy,
        bPolicy: ZeroChecksumPolicy,
    ): SctpSim {
        val sim = SctpSim(config = policy(aPolicy), configB = policy(bPolicy), errorDetection = dtls)
        sim.associateA()
        sim.run()
        assertEquals(SctpAssociationState.Established, sim.a.state, "the fixture needs an established association")
        assertEquals(SctpAssociationState.Established, sim.b.state, "the fixture needs an established association")
        return sim
    }

    /**
     * The handshake's own checksum profile, driven packet by packet so every one of the four is
     * observable. Two of the four are exempt from a permission both peers have already granted:
     *
     * - the **INIT** carries the permission and so predates it (§5.2 restriction 1a);
     * - the **COOKIE ECHO** names no association a receiver can look up, which is the RFC's stated reason
     *   for restriction 2 — a reason belonging to the peer rather than to us, and therefore not one that
     *   can be reasoned away locally.
     *
     * The **INIT ACK** is the interesting permitted one: RFC 9653 §5.2 does not list it, because by the
     * time an endpoint answers an INIT it has read what that INIT advertised. The responder holds no TCB
     * at that moment (RFC 4960 §5.1.3), so its zero here is derived for that one emit from the INIT in
     * hand and then forgotten with everything else — and if it were derived from stored state instead, it
     * could only be the `Crc32c` the association has not yet left.
     */
    @Test
    fun the_handshake_checksums_exactly_the_two_packets_rfc_9653_exempts() {
        val config = policy(ZeroChecksumPolicy.AcceptAndEmit)
        val a = SctpAssociation(config, Random(1), errorDetection = dtls)
        val b = SctpAssociation(config, Random(2), errorDetection = dtls)

        val init = a.handle(SctpEvent.Associate, epoch)
        val initAck = b.handle(SctpEvent.DatagramReceived(wire(init)), epoch)
        val cookieEcho = a.handle(SctpEvent.DatagramReceived(wire(initAck)), epoch)
        val cookieAck = b.handle(SctpEvent.DatagramReceived(wire(cookieEcho)), epoch)
        a.handle(SctpEvent.DatagramReceived(wire(cookieAck)), epoch)

        assertNotEquals(0u, checksumOf(init), "RFC 9653 §5.2 restriction 1a: an INIT is always checksummed")
        assertEquals(0u, checksumOf(initAck), "the INIT ACK answers an INIT that already advertised")
        assertNotEquals(0u, checksumOf(cookieEcho), "RFC 9653 §5.2 restriction 2: a COOKIE ECHO is always checksummed")
        assertEquals(0u, checksumOf(cookieAck), "nothing exempts a COOKIE ACK")
        assertEquals(SctpAssociationState.Established, a.state)
        assertEquals(SctpAssociationState.Established, b.state)
    }

    /** The point of the whole extension: negotiated DATA rides with no CRC32c and is delivered anyway. */
    @Test
    fun negotiated_data_crosses_with_a_zero_checksum() {
        val sim = establishedPair(ZeroChecksumPolicy.AcceptAndEmit, ZeroChecksumPolicy.AcceptAndEmit)

        val sent = send(sim, toA = true)
        sim.run()

        assertEquals(0u, checksumOf(sent), "a negotiated DATA packet carries no CRC32c")
        assertEquals(1, sim.inboxB.size, "and the peer that advertised must accept it")
        assertEquals(PayloadProtocolId(53u), sim.inboxB.single().payloadProtocolId)
    }

    /**
     * The asymmetry on the wire, in one association: A emits zeros because B advertised, and B emits real
     * CRC32c checksums because B's own policy says so. Both messages arrive.
     *
     * This is the fixture a conflated "zero checksum negotiated" flag cannot make green in either
     * direction — whichever end it read, both peers would emit the same thing.
     */
    @Test
    fun each_direction_carries_what_that_direction_negotiated() {
        val sim = establishedPair(ZeroChecksumPolicy.AcceptAndEmit, ZeroChecksumPolicy.AcceptOnly)

        val fromA = send(sim, toA = true)
        val fromB = send(sim, toA = false)
        sim.run()

        assertEquals(0u, checksumOf(fromA), "B advertised, so A's DATA may carry a zero")
        assertNotEquals(0u, checksumOf(fromB), "B asked to accept only, so its own DATA is checksummed")
        assertEquals(1, sim.inboxA.size, "a checksummed message still arrives")
        assertEquals(1, sim.inboxB.size, "and so does a zero-checksum one")
    }

    /**
     * A zero checksum arriving from a peer we never made the promise to. RFC 9653 §5.3: "Otherwise, the
     * endpoint MUST drop all SCTP packets with an incorrect CRC32c checksum."
     *
     * Driven as a **discriminating pair** over one hand-built packet, because "nothing came back" passes
     * just as green on an association that had stopped answering anything. The same zero-checksum
     * HEARTBEAT is delivered to two endpoints that differ only in what they advertised: the one that
     * advertised answers it, the one that did not is silent. A HEARTBEAT is the probe rather than DATA
     * precisely because its answer needs no TSN bookkeeping to be unambiguous — RFC 4960 §8.3 says a
     * HEARTBEAT ACK goes back immediately or not at all.
     */
    @Test
    fun a_zero_checksum_from_an_unpermitted_peer_is_discarded() {
        val accepting = establishedPair(ZeroChecksumPolicy.AcceptOnly, ZeroChecksumPolicy.AcceptOnly)
        val refusing = establishedPair(ZeroChecksumPolicy.Disabled, ZeroChecksumPolicy.Disabled)

        val answered = accepting.post(toA = false, SctpEvent.DatagramReceived(zeroChecksumHeartbeatFor(accepting.b)))
        val ignored = refusing.post(toA = false, SctpEvent.DatagramReceived(zeroChecksumHeartbeatFor(refusing.b)))

        assertTrue(
            answered.filterIsInstance<SctpOutput.Transmit>().isNotEmpty(),
            "an endpoint that advertised MUST accept a zero checksum (RFC 9653 §5.3) and answer the HEARTBEAT",
        )
        assertTrue(
            ignored.isEmpty(),
            "an endpoint that advertised nothing must drop it — a zero is an incorrect CRC32c until we say otherwise",
        )
        assertEquals(
            SctpAssociationState.Established,
            refusing.b.state,
            "the packet is discarded silently (RFC 4960 §6.8); it is not an association failure",
        )
    }

    /**
     * A HEARTBEAT addressed to [target] with a zero in the checksum field — what a peer that wrongly
     * believed it had permission, or an attacker probing whether we check, would put on the wire.
     */
    private fun zeroChecksumHeartbeatFor(target: SctpAssociation): ReadBuffer =
        SctpPacketBuilder(5000u, 5000u, target.localVerificationTag)
            .add(SctpChunk.Heartbeat(SctpParameter.ofValue(ParameterType.HeartbeatInfo, bufferOf(0xAB, 0xCD, 0xEF, 0x01))))
            .encode(BufferFactory.managed(), OutboundChecksum.ZeroWherePermitted(ErrorDetectionMethodId.ZeroChecksum))
}

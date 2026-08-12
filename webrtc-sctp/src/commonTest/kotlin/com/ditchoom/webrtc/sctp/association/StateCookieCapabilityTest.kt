@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.codec.DecodeContext
import com.ditchoom.buffer.codec.EncodeContext
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.ErrorDetectionMethodId
import com.ditchoom.webrtc.sctp.Tsn
import com.ditchoom.webrtc.sctp.VerificationTag
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime

/**
 * The three fields the State Cookie gained, and the property that made changing it once worth insisting
 * on.
 *
 * The responder holds **no** TCB between the INIT and the COOKIE ECHO (RFC 4960 §5.1.3), so everything it
 * learned from the INIT is gone unless the cookie carries it. That makes every one of these fields a
 * silent-failure candidate in the same shape: nothing on the wire is malformed, no error is raised, the
 * association establishes — and one side is simply operating on a fact the other never agreed to.
 */
class StateCookieCapabilityTest {
    private fun cookie(
        capabilities: PeerCapabilities = PeerCapabilities.None,
        maxInbound: UShort = 0u,
        edmid: ErrorDetectionMethodId = ErrorDetectionMethodId.Reserved,
    ) = StateCookie(
        magic = StateCookie.MAGIC,
        peerTag = VerificationTag(0x11111111u),
        peerInitialTsn = Tsn(0x22222222u),
        peerRwnd = 0x33333333u,
        peerMaxInbound = maxInbound,
        capabilities = capabilities,
        peerZeroChecksum = edmid,
        ourTag = VerificationTag(0x44444444u),
        ourInitialTsn = Tsn(0x55555555u),
        localTieTag = VerificationTag(0x66666666u),
        peerTieTag = VerificationTag(0x77777777u),
    )

    private fun roundTrip(value: StateCookie): StateCookie {
        val buffer = BufferFactory.managed().allocate(StateCookie.SIZE_BYTES, ByteOrder.BIG_ENDIAN)
        StateCookieCodec.encode(buffer, value, EncodeContext.Empty)
        buffer.resetForRead()
        buffer.setLimit(StateCookie.SIZE_BYTES)
        return StateCookieCodec.decode(buffer, DecodeContext.Empty)
    }

    /**
     * All four combinations, not one. A packing bug that assigned both extensions the same bit — the most
     * likely mistake in a hand-written bitfield — round-trips a single value perfectly and only shows up
     * when the two flags disagree. Two of these four cases are the ones that discriminate.
     */
    @Test
    fun every_combination_of_capabilities_survives_the_round_trip() {
        for (forwardTsn in listOf(false, true)) {
            for (reConfig in listOf(false, true)) {
                val capabilities = PeerCapabilities.of(forwardTsn = forwardTsn, reConfig = reConfig)
                val decoded = roundTrip(cookie(capabilities = capabilities)).capabilities

                assertEquals(
                    forwardTsn,
                    decoded.forwardTsn,
                    "forwardTsn=$forwardTsn reConfig=$reConfig lost the RFC 3758 bit",
                )
                assertEquals(
                    reConfig,
                    decoded.reConfig,
                    "forwardTsn=$forwardTsn reConfig=$reConfig lost the RFC 6525 bit",
                )
            }
        }
    }

    /**
     * The default has to be "advertised nothing". An endpoint that wrongly believes its peer supports
     * RFC 6525 sends a RE-CONFIG the peer answers with an ERROR; one that wrongly believes RFC 3758
     * sends a FORWARD-TSN that is simply discarded, stalling every partially-reliable stream.
     */
    @Test
    fun a_zeroed_capability_field_advertises_nothing() {
        assertFalse(PeerCapabilities.None.forwardTsn, "no bits set must not read as RFC 3758 support")
        assertFalse(PeerCapabilities.None.reConfig, "no bits set must not read as RFC 6525 support")
    }

    @Test
    fun the_stream_count_and_the_error_detection_method_survive_the_round_trip() {
        val decoded =
            roundTrip(
                cookie(maxInbound = 0x0400u, edmid = ErrorDetectionMethodId.ZeroChecksum),
            )

        assertEquals(0x0400u.toUShort(), decoded.peerMaxInbound, "the §5.1.1 stream minimum must come home")
        assertEquals(
            ErrorDetectionMethodId.ZeroChecksum,
            decoded.peerZeroChecksum,
            "the RFC 9653 §8 identifier must survive, though nothing populates it with a real method yet",
        )
    }

    /**
     * The end-to-end property, driven through the real four-way handshake rather than the codec: the
     * responder — which kept no state at all between the INIT and the echo — comes up agreeing with the
     * initiator about how many inbound streams exist.
     *
     * Both sides compute `min(our MIS, peer's OS)` from different inputs at different times (the
     * initiator off the INIT ACK, the responder off a cookie it minted and forgot), so agreement here is
     * a real claim rather than a tautology.
     */
    @Test
    fun both_endpoints_agree_on_the_negotiated_stream_count_after_the_handshake() {
        val config = SctpConfig(outboundStreams = 300u, inboundStreams = 700u)
        val sim = SctpSim(config = config)
        sim.associateA()
        sim.run()

        assertEquals(SctpAssociationState.Established, sim.a.state, "the fixture needs an established association")
        assertEquals(SctpAssociationState.Established, sim.b.state, "the fixture needs an established association")

        val expected = minOf(config.inboundStreams, config.outboundStreams)
        assertEquals(expected, sim.a.negotiatedInboundStreams, "the initiator settled the §5.1.1 minimum")
        assertEquals(
            expected,
            sim.b.negotiatedInboundStreams,
            "the responder must recover the minimum from its cookie — the COOKIE ECHO carries no stream counts",
        )
    }

    /**
     * The capabilities half of the same end-to-end property. Both peers advertise RFC 3758 and RFC 6525,
     * so a responder that dropped the octet would come up believing its peer supports neither — and would
     * then silently refuse to send the chunks those extensions exist for, with the association looking
     * perfectly healthy.
     */
    @Test
    fun the_responder_recovers_the_peers_advertised_extensions_from_its_own_cookie() {
        val sim = SctpSim()
        sim.associateA()
        sim.run()

        assertTrue(sim.b.peerExtensions.forwardTsn, "the responder forgot the peer's RFC 3758 advertisement")
        assertTrue(sim.b.peerExtensions.reConfig, "the responder forgot the peer's RFC 6525 advertisement")
    }
}

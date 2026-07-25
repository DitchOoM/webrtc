@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.ErrorCauseCode
import com.ditchoom.webrtc.sctp.ParameterType
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.SctpDecodeResult
import com.ditchoom.webrtc.sctp.SctpPacket
import com.ditchoom.webrtc.sctp.SctpPacketBuilder
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.Tsn
import com.ditchoom.webrtc.sctp.VerificationTag
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * RFC 4960 §5.2.4 Table 2 — every row of "handle a COOKIE ECHO when a TCB exists", driven against a live
 * association by a synthetic peer that crafts its own INIT / COOKIE ECHO.
 *
 * Row (D) (both tags match) and row (B) (initialization collision) are covered end-to-end by
 * [SctpSimultaneousOpenTest]; what is here is the half a two-endpoint sim cannot express — a peer that
 * **restarts**, i.e. comes back with brand-new tags over a transport where our association is still up.
 * That is unreachable in the WebRTC profile proper (RFC 8831 §6 puts the association inside one DTLS
 * session, so a restarted peer arrives with a new transport), which is exactly why it needs a fixture: no
 * interop lane will ever exercise it for us.
 */
class SctpCookieEchoTableTest {
    private val now = Instant.fromEpochSeconds(10)
    private val restartTag = VerificationTag(0x5EED_1234u)
    private val restartTsn = Tsn(0x1000u)

    private fun established(): SctpSim {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        check(sim.a.state == SctpAssociationState.Established)
        return sim
    }

    private fun packets(outputs: List<SctpOutput>): List<SctpPacket> =
        outputs.filterIsInstance<SctpOutput.Transmit>().mapNotNull {
            it.packet.position(0)
            (SctpPacket.decode(it.packet.slice()) as? SctpDecodeResult.Success)?.packet
        }

    /** A packet carrying an INIT from a peer that has forgotten the association (zero Verification Tag). */
    private fun initPacket(tag: VerificationTag) =
        SctpPacketBuilder(
            SctpAssociation.SCTP_DATA_CHANNEL_PORT,
            SctpAssociation.SCTP_DATA_CHANNEL_PORT,
            VerificationTag(0u),
        ).add(
            SctpChunk.Init(
                initiateTag = tag,
                advertisedReceiverWindow = 65536u,
                outboundStreams = 16u,
                inboundStreams = 16u,
                initialTsn = restartTsn,
                parameters = emptyList(),
            ),
        ).encode()
            .also { it.position(0) }
            .slice()

    /** Drive [SctpSim.a] to SHUTDOWN-ACK-SENT: the peer shuts down and A, with nothing outstanding, acks. */
    private fun shutdownAckSent(sim: SctpSim) {
        val shutdown =
            SctpPacketBuilder(
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                sim.a.localVerificationTag,
            ).add(SctpChunk.Shutdown(Tsn(0u))).encode()
        shutdown.position(0)
        sim.a.handle(SctpEvent.DatagramReceived(shutdown.slice()), now)
        check(sim.a.state == SctpAssociationState.ShutdownAckSent) { "expected SHUTDOWN-ACK-SENT, got ${sim.a.state}" }
    }

    /** The INIT ACK our endpoint answers a restarting peer's INIT with. */
    private fun restartInitAck(
        association: SctpAssociation,
        tag: VerificationTag = restartTag,
    ): SctpChunk.InitAck {
        val outputs = association.handle(SctpEvent.DatagramReceived(initPacket(tag)), now)
        return packets(outputs).flatMap { it.chunks }.filterIsInstance<SctpChunk.InitAck>().single()
    }

    private fun cookieEchoFrom(
        initAck: SctpChunk.InitAck,
        association: SctpAssociation,
    ): List<SctpOutput> {
        val cookie = initAck.parameters.single { it.type == ParameterType.StateCookie }.value
        val echo =
            SctpPacketBuilder(
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                // RFC 4960 §8.5.1(D): a COOKIE ECHO carries the tag from the INIT ACK that minted it —
                // for a restart that is the NEW tag, not the one the live association still uses.
                initAck.initiateTag,
            ).add(SctpChunk.CookieEcho(cookie.slice())).encode()
        echo.position(0)
        return association.handle(SctpEvent.DatagramReceived(echo.slice()), now)
    }

    // ── Row (A): X X M M — the peer restarted ────────────────────────────────────────────────────────

    @Test
    fun an_unexpected_init_while_established_is_answered_with_a_new_tag_not_the_live_one() {
        val sim = established()
        val liveTag = sim.a.localVerificationTag
        val initAck = restartInitAck(sim.a)

        // RFC 4960 §5.2.2: the INIT ACK MUST contain a NEW Initiate Tag, and the association is untouched.
        assertNotEquals(liveTag, initAck.initiateTag, "a fresh Initiate Tag, not the live association's")
        assertEquals(SctpAssociationState.Established, sim.a.state, "the existing association is unchanged")
        assertEquals(liveTag, sim.a.localVerificationTag, "and still uses its own tag")
    }

    @Test
    fun a_restarted_peers_cookie_echo_restarts_the_association() {
        val sim = established()
        val initAck = restartInitAck(sim.a)
        val outputs = cookieEchoFrom(initAck, sim.a)

        assertTrue(outputs.any { it is SctpOutput.PeerRestarted }, "the ULP is told this was a RESTART: $outputs")
        assertTrue(
            outputs.none { it is SctpOutput.Aborted },
            "and NOT that the association was lost — the RFC's 'RESTART instead of COMMUNICATION LOST'",
        )
        assertEquals(SctpAssociationState.Established, sim.a.state, "the association comes back up")
        assertEquals(restartTag, sim.a.peerVerificationTag, "on the restarted peer's tag")
        assertEquals(initAck.initiateTag, sim.a.localVerificationTag, "and on the tag we offered it")
        assertTrue(
            packets(outputs).flatMap { it.chunks }.any { it is SctpChunk.CookieAck },
            "the restart is acknowledged",
        )
    }

    @Test
    fun an_init_while_shutdown_ack_sent_repeats_the_shutdown_ack() {
        val sim = established()
        shutdownAckSent(sim)

        val chunks = packets(sim.a.handle(SctpEvent.DatagramReceived(initPacket(restartTag)), now)).flatMap { it.chunks }

        // RFC 4960 §9.2: our SHUTDOWN COMPLETE was lost — repeat the ACK, do NOT start an association.
        assertTrue(chunks.any { it === SctpChunk.ShutdownAck }, "the SHUTDOWN ACK is repeated: $chunks")
        assertTrue(chunks.none { it is SctpChunk.InitAck }, "and no INIT ACK is offered")
        assertEquals(SctpAssociationState.ShutdownAckSent, sim.a.state)
    }

    @Test
    fun a_restart_landing_while_shutdown_ack_sent_refuses_to_set_up_an_association() {
        val sim = established()
        // The cookie is minted while the association is still up, and only comes home after we have
        // started shutting down — the one ordering in which action A can reach SHUTDOWN-ACK-SENT.
        val initAck = restartInitAck(sim.a)
        shutdownAckSent(sim)
        val outputs = cookieEchoFrom(initAck, sim.a)
        val chunks = packets(outputs).flatMap { it.chunks }

        assertTrue(outputs.none { it is SctpOutput.PeerRestarted }, "no association is set up")
        assertEquals(SctpAssociationState.ShutdownAckSent, sim.a.state, "and the shutdown stands")
        assertTrue(chunks.any { it === SctpChunk.ShutdownAck }, "the SHUTDOWN ACK is resent: $chunks")
        assertTrue(
            chunks.filterIsInstance<SctpChunk.Error>().any { err ->
                err.causes.any { it.code == ErrorCauseCode.CookieReceivedWhileShuttingDown }
            },
            "with a 'Cookie Received While Shutting Down' ERROR: $chunks",
        )
    }

    // ── Row (C) and the omitted rows: discard ────────────────────────────────────────────────────────

    @Test
    fun a_cookie_we_never_minted_is_discarded_and_changes_nothing() {
        val sim = established()
        val liveTag = sim.a.localVerificationTag
        val peerTag = sim.a.peerVerificationTag
        val junk =
            SctpPacketBuilder(
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                SctpAssociation.SCTP_DATA_CHANNEL_PORT,
                liveTag,
            ).add(SctpChunk.CookieEcho(payload(StateCookie.SIZE_BYTES, seed = 5))).encode()
        junk.position(0)
        val outputs = sim.a.handle(SctpEvent.DatagramReceived(junk.slice()), now)

        assertTrue(outputs.isEmpty(), "silently discarded (RFC 4960 §5.1.5), not answered: $outputs")
        assertEquals(SctpAssociationState.Established, sim.a.state)
        assertEquals(liveTag, sim.a.localVerificationTag, "tags untouched")
        assertEquals(peerTag, sim.a.peerVerificationTag)
    }

    @Test
    fun a_stale_cookie_naming_neither_association_is_discarded() {
        val sim = established()
        // A cookie minted for THIS association, replayed after the peer restarted the tags underneath it:
        // Local Tag matches nothing live and the Tie-Tags are zero — a row Table 2 does not list.
        val initAck = restartInitAck(sim.a)
        cookieEchoFrom(initAck, sim.a) // the restart lands; tags are now the restarted peer's
        val afterRestartLocal = sim.a.localVerificationTag
        val afterRestartPeer = sim.a.peerVerificationTag

        // Replaying the very same cookie now describes the association we already have (row D) — it must
        // be idempotent: acknowledged, never a second restart.
        val replayed = cookieEchoFrom(initAck, sim.a)
        assertTrue(replayed.none { it is SctpOutput.PeerRestarted }, "a replayed cookie does not restart again")
        assertEquals(afterRestartLocal, sim.a.localVerificationTag)
        assertEquals(afterRestartPeer, sim.a.peerVerificationTag)
    }

    // ── The restart is observable end-to-end: user data flows on the new association ──────────────────

    @Test
    fun user_data_flows_on_the_restarted_association() {
        val sim = established()
        val initAck = restartInitAck(sim.a)
        cookieEchoFrom(initAck, sim.a)

        val outputs =
            sim.a.handle(
                SctpEvent.SendMessage(
                    SctpSendOptions(StreamId(0), PayloadProtocolId.WebRtcBinary),
                    payload(32, seed = 11),
                ),
                now,
            )
        val data = packets(outputs).flatMap { it.chunks }.filterIsInstance<SctpChunk.Data>()
        assertEquals(1, data.size, "the restarted association carries user data")
        assertEquals(restartTag, packets(outputs).first().verificationTag, "stamped with the new peer tag")
    }
}

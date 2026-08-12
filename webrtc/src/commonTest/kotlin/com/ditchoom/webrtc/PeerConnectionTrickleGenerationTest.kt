@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.ice.CandidatePair
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.ice.IceAgentDriver
import com.ditchoom.webrtc.ice.IceCandidate
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sctp.datachannel.DataChannelPayload
import com.ditchoom.webrtc.sctp.datachannel.send
import com.ditchoom.webrtc.sdp.SdpType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The session-layer fixtures for **RFC 8838 §3.1 trickle generations** — the restart window, reproduced
 * on purpose instead of waited for.
 *
 * `PeerConnectionRestartTest` restarts with signaling and trickle running concurrently, which *usually*
 * delivers the offer first. Here the order is inverted deliberately: the restarting peer's re-gathered
 * candidates are delivered **before** the offer that announces the generation they belong to, which is
 * exactly what a signaling channel with two paths (or any real network) will eventually do on its own.
 *
 * Untagged, those candidates are indistinguishable from candidates of the generation the receiver is
 * about to abandon, so they are applied to it and discarded with it; the session still converges, but only
 * because RFC 8445 §7.3.1.3 peer-reflexive learning rediscovers the path from the checks themselves. The
 * second fixture pins that — it is the same scenario with the tag switched off, and it is what makes the
 * first one non-vacuous: the two differ in one config value and in nothing else.
 */
class PeerConnectionTrickleGenerationTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun a_candidate_that_overtakes_the_restart_offer_lands_in_the_generation_it_names() =
        runTest {
            val f = connectedPeers(TrickleGenerationPolicy.Tagged)

            // Alice restarts and re-gathers. Her new candidates are held at the signaling seam, not lost:
            // this is a signaling channel that delivers candidates faster than descriptions, nothing more.
            f.aliceToBob.close()
            f.alice.restartIce()
            val offer = f.alice.createOffer()
            f.alice.setLocalDescription(SdpType.Offer, offer)
            assertTrue(f.aliceToBob.awaitHeld(), "alice re-gathered on the new generation")

            // The overtake: bob sees the candidates BEFORE the offer that names their generation.
            f.aliceToBob.release()
            f.bob.setRemoteDescription(SdpType.Offer, offer)
            val answer = f.bob.createAnswer()
            f.bob.setLocalDescription(SdpType.Answer, answer)
            f.alice.setRemoteDescription(SdpType.Answer, answer)

            val pair = f.awaitBobsNewPair()
            assertIs<IceCandidate.Host>(
                pair.remote,
                "bob checked the candidate alice signaled — it was held for her new generation, not applied to the old one",
            )
        }

    @Test
    fun with_the_tag_switched_off_the_same_overtake_falls_back_on_peer_reflexive_learning() =
        runTest {
            // The causality proof for the fixture above, and the honest cost of
            // [TrickleGenerationPolicy.Untagged]. Identical script, one config value different: alice's
            // new-generation candidates arrive before bob has any way to place them, so they join the
            // generation bob is about to abandon and go with it. The session still converges — RFC 8445
            // §7.3.1.3 learns the path back from alice's own checks — but on a peer-reflexive candidate,
            // which is the symptom issue #70 describes.
            val f = connectedPeers(TrickleGenerationPolicy.Untagged)

            f.aliceToBob.close()
            f.alice.restartIce()
            val offer = f.alice.createOffer()
            f.alice.setLocalDescription(SdpType.Offer, offer)
            assertTrue(f.aliceToBob.awaitHeld(), "alice re-gathered on the new generation")

            f.aliceToBob.release()
            f.bob.setRemoteDescription(SdpType.Offer, offer)
            val answer = f.bob.createAnswer()
            f.bob.setLocalDescription(SdpType.Answer, answer)
            f.alice.setRemoteDescription(SdpType.Answer, answer)

            val pair = f.awaitBobsNewPair()
            assertIs<IceCandidate.PeerReflexive>(
                pair.remote,
                "without the tag the signaled candidate is lost and the path is rediscovered, not signaled",
            )
        }

    @Test
    fun a_restart_whose_candidates_overtake_the_offer_still_keeps_the_dtls_association() =
        runTest {
            // Where #70 and #72 meet. A restart re-offers the SAME `a=tls-id` and the SAME `a=fingerprint`
            // (RFC 8842 §5.3/§5.5) — that is how it says "keep the association" — while the ICE credentials
            // underneath it are wholly replaced. This fixture runs both claims through the *hostile*
            // ordering: the new generation's candidates arrive before the offer that names them, so the
            // routing that #70 added is what decides where they land, and the association continuity that
            // #72 made explicit has to hold across the same window. Neither existing fixture covers both —
            // `PeerConnectionRestartTest` asserts tls-id stability under in-order signaling, and the
            // fixtures above assert routing without looking at DTLS at all.
            val f = connectedPeers(TrickleGenerationPolicy.Tagged)
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "trickle/tlsid"))
            val streamId = channel.id
            assertEquals("before", echo(channel, "before"), "the channel works before the restart")

            val before = f.alice.createOffer()
            val tlsIdBefore = assertNotNull(tlsIdOf(before), "every description we emit carries a=tls-id")
            val fingerprintBefore = assertNotNull(fingerprintOf(before), "…and a fingerprint")

            f.aliceToBob.close()
            f.alice.restartIce()
            val offer = f.alice.createOffer()
            f.alice.setLocalDescription(SdpType.Offer, offer)
            assertTrue(f.aliceToBob.awaitHeld(), "alice re-gathered on the new generation")

            f.aliceToBob.release()
            f.bob.setRemoteDescription(SdpType.Offer, offer)
            val answer = f.bob.createAnswer()
            f.bob.setLocalDescription(SdpType.Answer, answer)
            f.alice.setRemoteDescription(SdpType.Answer, answer)

            val pair = f.awaitBobsNewPair()
            assertIs<IceCandidate.Host>(pair.remote, "the overtaking candidate was still routed to its own generation")

            // The ICE generation moved; the DTLS association did not, and says so in both attributes.
            val after = f.alice.createOffer()
            assertNotEquals(ufragOf(before), ufragOf(after), "the restart really did replace the ICE credentials…")
            assertEquals(tlsIdBefore, tlsIdOf(after), "…while re-offering the same tls-id (RFC 8842 §5.5)")
            assertEquals(fingerprintBefore, fingerprintOf(after), "…and the same fingerprint")
            assertEquals(streamId, channel.id, "so the association was kept, stream ids and all")
            assertEquals("after", echo(channel, "after"), "and the channel still round-trips over the new pair")
        }

    // ---- fixture plumbing ---------------------------------------------------------------------------

    private class Peers(
        val alice: NativePeerConnection,
        val bob: NativePeerConnection,
        val aliceToBob: TrickleGate,
    ) {
        var bobsFirstPair: CandidatePair? = null

        /** Bob's selected pair once the restart has moved him off the one he started on. */
        suspend fun awaitBobsNewPair(): CandidatePair {
            val before = bobsFirstPair
            val state =
                bob.connectionState.first {
                    it is PeerConnectionState.Connected && (it.path as? SelectedPath.Known)?.pair != before
                }
            return assertIs<SelectedPath.Known>((state as PeerConnectionState.Connected).path).pair
        }
    }

    /**
     * The signaling seam for trickled candidates, with a **gate**. Closed, it parks the lines the peer
     * emits; released, it delivers them in order. That is the whole apparatus needed to reproduce the
     * restart window deterministically: no timing, no sleeps, just "the candidates went first".
     */
    private class TrickleGate(
        scope: CoroutineScope,
        from: NativePeerConnection,
        private val to: NativePeerConnection,
    ) {
        private val held = mutableListOf<String>()
        private var open = true

        init {
            scope.launch {
                from.localIceCandidates.collect { line -> if (open) to.addIceCandidate(line) else held += line }
            }
        }

        fun close() {
            open = false
        }

        /** True once at least one candidate has actually been parked — the precondition, asserted not assumed. */
        suspend fun awaitHeld(): Boolean =
            withTimeoutOrNull(60.seconds) {
                while (held.isEmpty()) yield()
                true
            } ?: false

        suspend fun release() {
            open = true
            val queued = held.toList()
            held.clear()
            for (line in queued) to.addIceCandidate(line)
        }
    }

    /** Gathers one host candidate per ICE generation, on a fresh port — what an interface change looks like. */
    private class GenerationalGathering(
        private val ip: String,
        firstPort: Int,
    ) : IceGatheringPolicy {
        private var nextPort = firstPort

        override suspend fun gather(driver: IceAgentDriver) {
            driver.gatherHost(ip, nextPort++)
        }
    }

    private suspend fun TestScope.connectedPeers(policy: TrickleGenerationPolicy): Peers {
        val net = TestNet()
        val binder = DatagramBinder { net.bind(it) }
        val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
        val config = PeerConnectionConfig(trickleGeneration = policy)
        val alice =
            NativePeerConnection(
                scope = backgroundScope,
                clock = clock,
                random = Random(1),
                binder = binder,
                gathering = GenerationalGathering(ALICE_IP, ALICE_FIRST_PORT),
                dtls = PlaintextDtls,
                config = config,
            )
        val bob =
            NativePeerConnection(
                scope = backgroundScope,
                clock = clock,
                random = Random(2),
                binder = binder,
                gathering = GenerationalGathering(BOB_IP, BOB_FIRST_PORT),
                dtls = PlaintextDtls,
                config = config,
            )
        val aliceToBob = TrickleGate(backgroundScope, from = alice, to = bob)
        TrickleGate(backgroundScope, from = bob, to = alice)

        // Bob reflects whatever arrives on the channel it arrived on — he has no idea a restart is coming,
        // which is the point: continuity is asserted from the side that was never told.
        backgroundScope.launch {
            bob.incomingDataChannels.collect { channel ->
                launch { channel.receive().collect { channel.send(it) } }
            }
        }

        val offer = alice.createOffer()
        alice.setLocalDescription(SdpType.Offer, offer)
        bob.setRemoteDescription(SdpType.Offer, offer)
        val answer = bob.createAnswer()
        bob.setLocalDescription(SdpType.Answer, answer)
        alice.setRemoteDescription(SdpType.Answer, answer)

        val peers = Peers(alice, bob, aliceToBob)
        assertTrue(withTimeoutOrNull(timeout) { alice.awaitConnected() } != null, "alice connected")
        val bobState = withTimeoutOrNull(timeout) { bob.awaitConnected() }
        peers.bobsFirstPair = assertIs<SelectedPath.Known>((assertIs<PeerConnectionState.Connected>(bobState)).path).pair
        return peers
    }

    /** The `a=ice-ufrag` of a description — the ICE generation it advertises. */
    private fun ufragOf(sdp: String): String =
        sdp
            .lineSequence()
            .first { it.startsWith("a=ice-ufrag:") }
            .substringAfter(':')

    /** The `a=tls-id` a description carries (RFC 8842 §5.3), or null if it carries none. */
    private fun tlsIdOf(sdp: String): String? =
        sdp
            .lineSequence()
            .firstOrNull { it.startsWith("a=tls-id:") }
            ?.substringAfter(':')

    /** The `a=fingerprint` a description carries (RFC 8122) — the implicit statement of the same continuity. */
    private fun fingerprintOf(sdp: String): String? =
        sdp
            .lineSequence()
            .firstOrNull { it.startsWith("a=fingerprint:") }
            ?.substringAfter(':')

    private suspend fun echo(
        channel: Connection<DataChannelPayload>,
        text: String,
    ): String? {
        channel.send(textBuffer(text))
        return withTimeoutOrNull(timeout) { channel.receive().first().contentAsString() }
    }

    private fun textBuffer(s: String): ReadBuffer {
        val bytes = s.encodeToByteArray()
        val buf = BufferFactory.managed().allocate(maxOf(1, bytes.size), ByteOrder.BIG_ENDIAN)
        for (b in bytes) buf.writeByte(b)
        buf.resetForRead()
        buf.setLimit(bytes.size)
        return buf
    }

    private fun ReadBuffer.text(): String {
        val out = StringBuilder()
        for (i in position() until limit()) out.append((get(i).toInt() and 0xFF).toChar())
        return out.toString()
    }

    private suspend fun NativePeerConnection.awaitConnected(): PeerConnectionState =
        connectionState.first {
            when (it) {
                is PeerConnectionState.Connected -> true
                is PeerConnectionState.Failed -> error("expected a connection, but PeerConnection failed: ${it.reason}")
                else -> false
            }
        }

    private companion object {
        const val ALICE_IP = "10.0.0.1"
        const val BOB_IP = "10.0.0.2"
        const val ALICE_FIRST_PORT = 4000
        const val BOB_FIRST_PORT = 5000
    }
}

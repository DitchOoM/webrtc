@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.dtls.DtlsFailureReason
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.ice.IceAgentDriver
import com.ditchoom.webrtc.ice.LocalInterface
import com.ditchoom.webrtc.ice.NetworkId
import com.ditchoom.webrtc.ice.NetworkMonitor
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sdp.SdpType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The **ICE restart / renegotiation** fixtures for the session layer (RFC 8445 §9 through JSEP). The
 * motivating scenario is a mobile network change mid-session — Wi-Fi → cellular — and the property that
 * matters is not "ICE reconverges" but **"the SCTP association and every open data channel survive it"**.
 * §9 promises exactly that: *"during the restart, data can continue to be sent using existing data
 * sessions"*, and *"agents MUST NOT redetermine the roles as part of an ICE restart"*.
 *
 * Each peer gathers on a **fresh port per ICE generation** ([GenerationalGathering]) because that is what
 * an interface change actually looks like, and because the in-memory network — like a real OS — refuses to
 * re-bind an address that is still open. The old socket staying open is the point, not an obstacle.
 */
class PeerConnectionRestartTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun ice_restart_moves_to_a_new_pair_without_dropping_the_association() =
        runTest {
            val f = connectedPeers()
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/chat"))
            val streamId = channel.id
            assertEquals("before", echo(channel, "before"), "the channel works before the restart")
            val pairBefore = knownPair(f.alice.connectionState.value)
            val credentialsBefore = ufragOf(f.alice.createOffer())

            f.alice.restartIce()
            renegotiate(f.alice, f.bob)

            // The pair moved…
            val connected =
                assertNotNull(
                    withTimeoutOrNull(timeout) {
                        f.alice.connectionState.first { it is PeerConnectionState.Connected && knownPair(it) != pairBefore }
                    },
                    "alice reconverged on a new pair",
                )
            val pairAfter = knownPair(connected)
            assertNotEquals(pairBefore, pairAfter, "the restart nominated a different pair")
            assertNotEquals(credentialsBefore, ufragOf(f.alice.createOffer()), "…on fresh ICE credentials (RFC 8445 §9)")

            // …and the association did not: the SAME channel object, on the SAME stream, still round-trips.
            // A restart that quietly rebuilt DTLS/SCTP underneath would show up here as a dead channel or a
            // renumbered stream, which is precisely the failure §9 exists to prevent.
            assertEquals(streamId, channel.id, "the data channel kept its stream id across the restart")
            assertEquals("after", echo(channel, "after"), "the data channel still round-trips after the restart")
        }

    @Test
    fun data_keeps_flowing_on_the_old_pair_during_the_restart() =
        runTest {
            // The RFC 8445 §9 continuity claim, pinned. Before [IcePath] this worked only because a stale
            // field was never cleared — right behaviour, arrived at by a bug, untested and one refactor from
            // vanishing. Here the restart is applied and the peer has NOT yet seen the offer, so the only
            // thing that can be carrying this message is the retained generation's pair.
            val f = connectedPeers()
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/continuity"))
            assertEquals("before", echo(channel, "before"))

            f.alice.restartIce()
            f.alice.createOffer() // applies the restart; deliberately NOT signaled to bob yet
            val restarting =
                assertNotNull(
                    withTimeoutOrNull(timeout) { f.alice.connectionState.first { it is PeerConnectionState.Restarting } },
                    "the restart window is an observable state, not an invisible interval",
                )
            assertIs<SelectedPath.Known>((restarting as PeerConnectionState.Restarting).path)

            assertEquals("during", echo(channel, "during"), "data keeps flowing while the new generation converges")
        }

    @Test
    fun a_rolled_back_restart_offer_restores_the_previous_ice_generation() =
        runTest {
            val f = connectedPeers()
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/rollback"))
            assertEquals("before", echo(channel, "before"))
            val pairBefore = knownPair(f.alice.connectionState.value)

            f.alice.restartIce()
            val offer = f.alice.createOffer()
            f.alice.setLocalDescription(SdpType.Offer, offer)
            assertNotNull(withTimeoutOrNull(timeout) { f.alice.connectionState.first { it is PeerConnectionState.Restarting } })

            // The app abandons the round (a glare resolution, or the user cancelled). Without the ICE half of
            // rollback the agent would be left advertising credentials no peer has ever seen — reachable by
            // nobody, and not obviously broken until the next check times out.
            f.alice.setLocalDescription(SdpType.Rollback, "")

            val restored =
                assertNotNull(
                    withTimeoutOrNull(timeout) { f.alice.connectionState.first { it is PeerConnectionState.Connected } },
                    "the session returns to Connected on the generation the peer still knows",
                )
            assertEquals(pairBefore, knownPair(restored), "…on the same pair it was using before the abandoned offer")
            assertEquals("after", echo(channel, "after"), "and the channel never noticed")
        }

    @Test
    fun a_peer_initiated_restart_is_detected_from_new_remote_credentials() =
        runTest {
            // Bob never calls restartIce(). The only evidence he gets is an offer whose ufrag AND pwd both
            // changed (RFC 8445 §9 requires both) — and if he did not act on it his checklist would stay
            // bound to the old password and every check he sent would be discarded by an agent that no
            // longer knows it.
            val f = connectedPeers()
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/peer"))
            assertEquals("before", echo(channel, "before"))
            val bobPairBefore = knownPair(f.bob.connectionState.value)

            f.alice.restartIce()
            renegotiate(f.alice, f.bob)

            val bobAfter =
                assertNotNull(
                    withTimeoutOrNull(timeout) {
                        f.bob.connectionState.first { it is PeerConnectionState.Connected && knownPair(it) != bobPairBefore }
                    },
                    "bob restarted his own side off the peer's new credentials alone",
                )
            assertNotEquals(bobPairBefore, knownPair(bobAfter))
            assertEquals("after", echo(channel, "after"), "and the channel survived on both sides")
        }

    @Test
    fun the_old_interface_going_away_mid_restart_still_converges() =
        runTest {
            // The realistic mobile case: Wi-Fi does not politely wait for the new path to come up. Continuity
            // is lost here — that is what losing the interface *means* — but the session must still reconverge
            // on the new one rather than wedging on a pair whose socket has evaporated.
            val f = connectedPeers()
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/flap"))
            assertEquals("before", echo(channel, "before"))
            val pairBefore = knownPair(f.alice.connectionState.value)

            f.alice.restartIce()
            val offer = f.alice.createOffer()
            f.alice.setLocalDescription(SdpType.Offer, offer)
            f.bob.setRemoteDescription(SdpType.Offer, offer)
            f.net.tearDown(SocketAddress.ofLiteral(ALICE_IP, ALICE_FIRST_PORT))

            val answer = f.bob.createAnswer()
            f.bob.setLocalDescription(SdpType.Answer, answer)
            f.alice.setRemoteDescription(SdpType.Answer, answer)

            val connected =
                assertNotNull(
                    withTimeoutOrNull(timeout) {
                        f.alice.connectionState.first { it is PeerConnectionState.Connected && knownPair(it) != pairBefore }
                    },
                    "alice reconverges even though the outgoing interface vanished mid-restart",
                )
            assertNotEquals(pairBefore, knownPair(connected))
            assertEquals("after", echo(channel, "after"), "the association rode out the interface change")
        }

    @Test
    fun losing_the_selected_pairs_interface_restarts_automatically() =
        runTest {
            // No explicit restartIce() anywhere in this fixture: the policy notices, and tells the app a
            // round is owed. It cannot renegotiate by itself — it does not own the signaling channel — so
            // "restarts automatically" means exactly this handshake, and the signal is the load-bearing half.
            val monitor = ScriptedMonitor(listOf(iface("wifi", ALICE_IP)))
            val f = connectedPeers(aliceRestartPolicy = IceRestartPolicy.OnNetworkChange(monitor))
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/auto"))
            assertEquals("before", echo(channel, "before"))
            val pairBefore = knownPair(f.alice.connectionState.value)

            monitor.emit(listOf(iface("cellular", "10.0.0.9")))

            assertNotNull(
                withTimeoutOrNull(timeout) { f.alice.renegotiationNeeded.first() },
                "losing the selected pair's interface asks the app for a new offer/answer round",
            )
            renegotiate(f.alice, f.bob)

            val connected =
                assertNotNull(
                    withTimeoutOrNull(timeout) {
                        f.alice.connectionState.first { it is PeerConnectionState.Connected && knownPair(it) != pairBefore }
                    },
                    "and the round the policy asked for carries a genuine ICE restart",
                )
            assertNotEquals(pairBefore, knownPair(connected))
            assertEquals("after", echo(channel, "after"))
        }

    @Test
    fun an_unrelated_interface_appearing_does_not_restart() =
        runTest {
            // The guard against restart churn. A VPN or virtual adapter coming up changes the interface set
            // on a perfectly healthy session; a policy that restarted on *any* change would tear a working
            // path down for it, repeatedly, on exactly the mobile devices this feature exists to serve.
            val monitor = ScriptedMonitor(listOf(iface("wifi", ALICE_IP)))
            val f = connectedPeers(aliceRestartPolicy = IceRestartPolicy.OnNetworkChange(monitor))
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/churn"))
            assertEquals("before", echo(channel, "before"))
            val pairBefore = knownPair(f.alice.connectionState.value)

            monitor.emit(listOf(iface("wifi", ALICE_IP), iface("vpn", "10.0.0.77")))

            assertNull(
                withTimeoutOrNull(QUIET) { f.alice.renegotiationNeeded.first() },
                "an interface set that still carries the selected pair is not a reason to renegotiate",
            )
            assertEquals(pairBefore, knownPair(f.alice.connectionState.value), "the healthy session is untouched")
            assertEquals("after", echo(channel, "after"))
        }

    @Test
    fun a_re_answer_that_flips_the_dtls_role_is_refused() =
        runTest {
            // RFC 8842 §5.5: an endpoint that wants to keep its DTLS association re-offers `a=setup:actpass`
            // and keeps its fingerprint — the roles are fixed for the association's lifetime. A re-answer
            // implying the opposite role is asking for a NEW association, which we do not do underneath an
            // ICE restart. Refuse it with a typed reason; silently ignoring it would leave the peer
            // handshaking against a role we never adopted, and the session hanging with no explanation.
            val f = connectedPeers()

            f.alice.restartIce()
            val offer = f.alice.createOffer()
            f.alice.setLocalDescription(SdpType.Offer, offer)
            f.bob.setRemoteDescription(SdpType.Offer, offer)
            val answer = f.bob.createAnswer()
            f.alice.setRemoteDescription(SdpType.Answer, answer.replace("a=setup:active", "a=setup:passive"))

            val failed =
                assertNotNull(
                    withTimeoutOrNull(timeout) { f.alice.connectionState.first { it is PeerConnectionState.Failed } },
                    "a role flip on renegotiation is refused, not ignored",
                )
            assertEquals(
                PeerConnectionFailureReason.Dtls(DtlsFailureReason.RoleChangeOnRenegotiation),
                (failed as PeerConnectionState.Failed).reason,
            )
        }

    // ---- fixture plumbing ---------------------------------------------------------------------------

    private class Peers(
        val net: TestNet,
        val alice: NativePeerConnection,
        val bob: NativePeerConnection,
    )

    /**
     * Gathers one host candidate per ICE generation, on a **fresh port each time**. That is what a real
     * interface change looks like, and it is forced anyway: the network — like an OS — refuses to re-bind an
     * address that is still open, and across a restart the outgoing generation's socket deliberately is.
     */
    private class GenerationalGathering(
        private val ip: String,
        firstPort: Int,
    ) : IceGatheringPolicy {
        private var nextPort = firstPort

        override suspend fun gather(driver: IceAgentDriver) {
            driver.gatherHost(ip, nextPort++)
        }
    }

    /** A [NetworkMonitor] whose interface set is driven by the fixture — a scripted Wi-Fi↔cellular flip. */
    private class ScriptedMonitor(
        initial: List<LocalInterface>,
    ) : NetworkMonitor {
        private val state = MutableStateFlow(initial)

        override fun interfaces(): List<LocalInterface> = state.value

        override val changes: Flow<List<LocalInterface>> get() = state

        fun emit(interfaces: List<LocalInterface>) {
            state.value = interfaces
        }
    }

    /**
     * An interface as a real [NetworkMonitor] would report it: an address with **no meaningful port**.
     * Enumerating interfaces tells you nothing about which ephemeral port ICE bound on one, so a fixture
     * that helpfully supplies the matching port would prove the policy works only for a monitor that
     * cannot exist.
     */
    private fun iface(
        id: String,
        ip: String,
    ) = LocalInterface(NetworkId(id), SocketAddress.ofLiteral(ip, NO_PORT))

    private suspend fun TestScope.connectedPeers(aliceRestartPolicy: IceRestartPolicy = IceRestartPolicy.Manual): Peers {
        val net = TestNet()
        val binder = DatagramBinder { net.bind(it) }
        val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
        val alice =
            NativePeerConnection(
                scope = backgroundScope,
                clock = clock,
                random = Random(1),
                binder = binder,
                gathering = GenerationalGathering(ALICE_IP, ALICE_FIRST_PORT),
                dtls = PlaintextDtls,
                config = PeerConnectionConfig(iceRestartPolicy = aliceRestartPolicy),
            )
        val bob =
            NativePeerConnection(
                scope = backgroundScope,
                clock = clock,
                random = Random(2),
                binder = binder,
                gathering = GenerationalGathering(BOB_IP, BOB_FIRST_PORT),
                dtls = PlaintextDtls,
            )
        trickle(backgroundScope, from = alice, to = bob)
        trickle(backgroundScope, from = bob, to = alice)

        // Bob is the universal reflector every interop answerer runs: echo whatever arrives, on the channel
        // it arrived on. It has no idea a restart is coming, which is the point.
        backgroundScope.launch {
            bob.incomingDataChannels.collect { channel ->
                launch { channel.receive().collect { channel.send(it) } }
            }
        }

        renegotiate(alice, bob)
        assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice connected")
        assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob connected")
        return Peers(net, alice, bob)
    }

    /** One full offer/answer round over the app's signaling seam — the round a restart needs to be carried. */
    private suspend fun renegotiate(
        offerer: NativePeerConnection,
        answerer: NativePeerConnection,
    ) {
        val offer = offerer.createOffer()
        offerer.setLocalDescription(SdpType.Offer, offer)
        answerer.setRemoteDescription(SdpType.Offer, offer)
        val answer = answerer.createAnswer()
        answerer.setLocalDescription(SdpType.Answer, answer)
        offerer.setRemoteDescription(SdpType.Answer, answer)
    }

    /** The pair a live state is riding. A state that carries no known pair is a fixture bug, not a case. */
    private fun knownPair(state: PeerConnectionState) =
        when (state) {
            is PeerConnectionState.Connected -> assertIs<SelectedPath.Known>(state.path).pair
            is PeerConnectionState.Restarting -> assertIs<SelectedPath.Known>(state.path).pair
            else -> error("not a live state: $state")
        }

    private fun ufragOf(sdp: String): String =
        sdp
            .lineSequence()
            .first { it.startsWith("a=ice-ufrag:") }
            .substringAfter(':')

    private suspend fun echo(
        channel: Connection<ReadBuffer>,
        text: String,
    ): String? {
        channel.send(textBuffer(text))
        return withTimeoutOrNull(timeout) { channel.receive().first().text() }
    }

    private fun trickle(
        scope: CoroutineScope,
        from: NativePeerConnection,
        to: NativePeerConnection,
    ) {
        scope.launch {
            from.localIceCandidates.collect { to.addIceCandidate(it) }
        }
    }

    private suspend fun NativePeerConnection.awaitConnected(): PeerConnectionState =
        connectionState.first {
            when (it) {
                is PeerConnectionState.Connected -> true
                is PeerConnectionState.Failed -> error("expected a connection, but PeerConnection failed: ${it.reason}")
                else -> false
            }
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

    private companion object {
        const val ALICE_IP = "10.0.0.1"
        const val BOB_IP = "10.0.0.2"
        const val ALICE_FIRST_PORT = 4000

        /** What an interface enumeration reports for a port: nothing. */
        const val NO_PORT = 0
        const val BOB_FIRST_PORT = 5000

        /**
         * How long a "nothing should happen" assertion waits before believing it. Virtual time, so it costs
         * nothing; it is long enough that any restart the policy *was* going to request has been requested.
         */
        val QUIET = 30.seconds
    }
}

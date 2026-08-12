@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.ice.vnet.CountingBufferFactory
import com.ditchoom.webrtc.ice.vnet.Vnet
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import com.ditchoom.webrtc.stun.IpAddress
import com.ditchoom.webrtc.stun.TransportAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
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
 * [IceDataPath] / [DataCarrier] / [IcePath.carrier] / [IceCandidate.localSocket] — the seam an upper
 * layer folds into "did the path move" (RFC 8261 §6.1), and the reason it is not allowed to fold
 * [CandidatePair] instead.
 *
 * Every equality claim here ships with its discriminating opposite. "These two are the same path" is
 * green on a discriminant that answers *same* for everything, so each is paired with a move that must
 * register — a different local socket, a different peer address, a new generation nominating elsewhere.
 */
class IceDataPathTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    // ---- the discriminant, at the value level -------------------------------------------------------

    @Test
    fun an_unnominated_path_carries_nothing() {
        assertEquals(DataCarrier.None, IcePath.Unnominated.carrier, "nothing nominated ⇒ nowhere for data to go")
    }

    @Test
    fun a_socket_re_gathered_at_a_new_ordinal_is_the_same_data_path() {
        // The false positive an ICE restart produces on its own: gather ordinals restart with the
        // generation, so the SAME socket comes back with a different RFC 8445 §5.1.2.2 local preference.
        val socket = v4(ALICE_IP, ALICE_PORT)
        val policy = CandidatePreferencePolicy.Default
        val first = IceCandidate.host(socket, localPreference = policy.localPreference(socket.ip, interfaceIndex = 0))
        val second = IceCandidate.host(socket, localPreference = policy.localPreference(socket.ip, interfaceIndex = 1))
        assertNotEquals(first.priority, second.priority, "the ordinal really did change the §5.1.2.1 priority")

        val before = DataCarrier.Riding(CandidatePair(first, remote()))
        val after = DataCarrier.Riding(CandidatePair(second, remote()))

        assertNotEquals(before.pair, after.pair, "the pairs differ — which is why pair identity cannot be the discriminant")
        assertEquals(before.path, after.path, "the datagrams still leave the same socket for the same peer")
        assertEquals(before, after, "so the carrier does not move either")
    }

    @Test
    fun a_server_reflexive_pair_over_the_same_socket_is_the_same_data_path() {
        // Host(X, base = X) superseded by ServerReflexive(Y, base = X): two candidates, one socket.
        val socket = v4(ALICE_IP, ALICE_PORT)
        val host = IceCandidate.host(socket)
        val reflexive =
            IceCandidate.ServerReflexive(
                address = v4(ALICE_MAPPED_IP, ALICE_PORT),
                base = socket,
                component = ComponentId.Rtp,
                transport = IceTransport.Udp,
                foundation = Foundation.of(CandidateType.ServerReflexive, ALICE_IP, STUN_IP, IceTransport.Udp),
                priority = IceCandidate.computePriority(CandidateType.ServerReflexive, ComponentId.Rtp),
                relatedAddress = socket,
            )

        val overHost = DataCarrier.Riding(CandidatePair(host, remote()))
        val overReflexive = DataCarrier.Riding(CandidatePair(reflexive, remote()))

        assertNotEquals(overHost.pair, overReflexive.pair, "a different candidate is a different pair")
        assertEquals(overHost.path, overReflexive.path, "but one socket to one peer is one path")
        assertEquals(overHost, overReflexive, "and one carrier")
    }

    @Test
    fun a_different_local_socket_is_a_different_data_path() {
        val here = DataCarrier.Riding(CandidatePair(IceCandidate.host(v4(ALICE_IP, ALICE_PORT)), remote()))
        val moved = DataCarrier.Riding(CandidatePair(IceCandidate.host(v4(ALICE_IP, ALICE_PORT + 1)), remote()))
        assertNotEquals(here.path, moved.path, "a new local socket is a real move")
        assertNotEquals(here, moved, "and the carrier says so")
    }

    @Test
    fun a_different_peer_address_is_a_different_data_path() {
        val local = IceCandidate.host(v4(ALICE_IP, ALICE_PORT))
        val here = DataCarrier.Riding(CandidatePair(local, remote()))
        val moved = DataCarrier.Riding(CandidatePair(local, remote(port = BOB_PORT + 1)))
        assertNotEquals(here.path, moved.path, "the same socket addressing a new peer is a real move")
        assertNotEquals(here, moved, "and the carrier says so")
    }

    @Test
    fun path_equal_carriers_agree_on_hash_code() {
        // The fold in the session layer will key on these; equality without hashCode agreement would make
        // a Set or Map disagree with `==` about the very thing this type exists to decide.
        val socket = v4(ALICE_IP, ALICE_PORT)
        val one = DataCarrier.Riding(CandidatePair(IceCandidate.host(socket, localPreference = 65535), remote()))
        val two = DataCarrier.Riding(CandidatePair(IceCandidate.host(socket, localPreference = 100), remote()))
        val elsewhere = DataCarrier.Riding(CandidatePair(IceCandidate.host(v4(ALICE_IP, ALICE_PORT + 1)), remote()))

        assertEquals(1, setOf<DataCarrier>(one, two).size, "two paths that are one collapse to one entry")
        assertEquals(3, setOf<DataCarrier>(one, elsewhere, DataCarrier.None).size, "and genuinely distinct carriers do not")
    }

    // ---- transmit identity vs interface liveness ----------------------------------------------------

    @Test
    fun a_relayed_pair_transmits_from_its_base_and_stands_on_its_related_address() {
        // The one candidate kind where the two questions have different answers — and the reason both
        // properties exist. `channels` is keyed by the relayed base (the allocation is the channel), while
        // the interface the datagrams really leave on is the socket facing the TURN server.
        val localSocket = v4(ALICE_IP, ALICE_PORT)
        val relay =
            IceCandidate.Relayed(
                address = v4(RELAY_IP, RELAY_PORT),
                component = ComponentId.Rtp,
                transport = IceTransport.Udp,
                foundation = Foundation.of(CandidateType.Relayed, RELAY_IP, TURN_IP, IceTransport.Udp),
                priority = IceCandidate.computePriority(CandidateType.Relayed, ComponentId.Rtp),
                relatedAddress = localSocket,
            )
        val carrier = DataCarrier.Riding(CandidatePair(relay, remote()))

        assertEquals(v4(RELAY_IP, RELAY_PORT), carrier.path.fromBase, "transmission is keyed by the relayed base")
        assertEquals(localSocket, relay.localSocket, "the interface it stands on is the socket facing the TURN server")
        assertNotEquals(carrier.path.fromBase, relay.localSocket, "the two answers differ here — collapsing them loses one")
    }

    @Test
    fun every_other_candidate_kind_already_bases_on_its_local_socket() {
        val socket = v4(ALICE_IP, ALICE_PORT)
        val mapped = v4(ALICE_MAPPED_IP, ALICE_PORT)
        val host = IceCandidate.host(socket)
        val reflexive =
            IceCandidate.ServerReflexive(
                address = mapped,
                base = socket,
                component = ComponentId.Rtp,
                transport = IceTransport.Udp,
                foundation = Foundation.of(CandidateType.ServerReflexive, ALICE_IP, STUN_IP, IceTransport.Udp),
                priority = IceCandidate.computePriority(CandidateType.ServerReflexive, ComponentId.Rtp),
                relatedAddress = socket,
            )
        val peerReflexive =
            IceCandidate.PeerReflexive(
                address = mapped,
                base = socket,
                component = ComponentId.Rtp,
                transport = IceTransport.Udp,
                foundation = Foundation.of(CandidateType.PeerReflexive, ALICE_IP, serverIp = null, transport = IceTransport.Udp),
                priority = IceCandidate.computePriority(CandidateType.PeerReflexive, ComponentId.Rtp),
                relatedAddress = socket,
            )

        assertEquals(socket, host.localSocket, "a host candidate is its own socket")
        assertEquals(socket, reflexive.localSocket, "a server-reflexive candidate stands on the socket it was mapped from")
        assertEquals(socket, peerReflexive.localSocket, "and so does a peer-reflexive one")
        assertEquals(host.base, host.localSocket, "for these three the two questions coincide — which is why the fourth is missable")
    }

    // ---- against the production driver ---------------------------------------------------------------

    @Test
    fun the_carrier_names_the_socket_the_driver_transmits_from() =
        runTest {
            val fixture = connectedPeers(seed = 901)

            val carrier = assertIs<DataCarrier.Riding>(fixture.alice.path.value.carrier, "a converged agent carries data")
            assertEquals(
                vnetAddress(ALICE_IP, ALICE_PORT).toTransportAddress(),
                carrier.path.fromBase,
                "fromBase is the local socket alice gathered — the key `channels` is bound under",
            )
            assertEquals(
                vnetAddress(BOB_IP, BOB_PORT).toTransportAddress(),
                carrier.path.to,
                "and `to` is the address bob's candidate is reachable at",
            )
            assertTrue(
                fixture.vnet.isBound(carrier.path.fromBase.toSocketAddress()),
                "fromBase names a socket that is actually bound — not a candidate address nothing listens on",
            )
        }

    @Test
    fun a_restart_window_does_not_move_the_carrier_and_a_new_generations_pair_does() =
        runTest {
            // The property the session-layer fold rests on, and its discriminating half. RFC 8445 §9 keeps
            // data on the retained pair for the whole restart window, so a restart must NOT read as a path
            // change; the change is the new generation nominating somewhere else, and only then.
            val fixture = connectedPeers(seed = 902)
            val before = assertIs<DataCarrier.Riding>(fixture.alice.path.value.carrier)

            fixture.alice.restartAndAwait()
            fixture.bob.restartAndAwait()

            assertIs<IcePath.Restarting>(fixture.alice.path.value, "the restart window is open")
            assertEquals(before, fixture.alice.path.value.carrier, "and data still rides the retained pair — no move to report")

            // A real interface change: the new generation gathers a different socket. The vnet requires the
            // address to be free, so the old one is genuinely retired rather than merely renamed.
            fixture.alice.gatherHost(ALICE_IP, ALICE_PORT + 1)
            fixture.bob.gatherHost(BOB_IP, BOB_PORT + 1)
            connect(fixture.alice, fixture.bob)
            connect(fixture.bob, fixture.alice)
            assertNotNull(withTimeoutOrNull(timeout) { fixture.alice.awaitConnected() }, "alice reconverges")
            assertNotNull(withTimeoutOrNull(timeout) { fixture.bob.awaitConnected() }, "bob reconverges")

            val after = assertIs<DataCarrier.Riding>(fixture.alice.path.value.carrier, "the new generation carries data")
            assertNotEquals(before, after, "a path that really moved reads as a move")
            assertEquals(
                (ALICE_PORT + 1).toUShort(),
                after.path.fromBase.port,
                "and the carrier names the new socket, not the retired one",
            )
        }

    // ---- fixture plumbing ---------------------------------------------------------------------------

    private class Peers(
        val vnet: Vnet,
        val alice: IceAgentDriver,
        val bob: IceAgentDriver,
    )

    private suspend fun TestScope.connectedPeers(seed: Long): Peers {
        val vnet = Vnets.flat(CountingBufferFactory(BufferFactory.managed()))
        val binder = DatagramBinder { vnet.bind(it) }
        val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
        val alice = IceAgentDriver(IceRole.Controlling, Random(seed), binder, backgroundScope, clock)
        val bob = IceAgentDriver(IceRole.Controlled, Random(seed + 1), binder, backgroundScope, clock)
        alice.start()
        bob.start()
        alice.gatherHost(ALICE_IP, ALICE_PORT)
        bob.gatherHost(BOB_IP, BOB_PORT)
        connect(alice, bob)
        connect(bob, alice)
        assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice ICE connected")
        assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob ICE connected")
        return Peers(vnet, alice, bob)
    }

    // Scripted signaling: hand [from]'s credentials + candidates to [to] (the trickle seam, direct).
    private fun connect(
        to: IceAgentDriver,
        from: IceAgentDriver,
    ) {
        to.setRemoteCredentials(from.localCredentials)
        from.localCandidates.forEach { to.addRemoteCandidate(it) }
    }

    private suspend fun IceAgentDriver.awaitConnected(): IceConnectionState =
        state.first {
            when (it) {
                is IceConnectionState.Connected, is IceConnectionState.Completed -> true
                is IceConnectionState.Failed -> error("expected a connection, but ICE failed: ${it.reason}")
                else -> false
            }
        }

    private fun remote(
        ip: String = BOB_IP,
        port: Int = BOB_PORT,
    ): IceCandidate = IceCandidate.host(v4(ip, port))

    private fun v4(
        ip: String,
        port: Int,
    ): TransportAddress {
        val bits = ip.split(".").fold(0u) { acc, octet -> (acc shl 8) or octet.toUInt() }
        return TransportAddress(IpAddress.V4(bits), port.toUShort())
    }

    private companion object {
        const val ALICE_IP = "10.0.0.1"
        const val BOB_IP = "10.0.0.2"
        const val ALICE_MAPPED_IP = "203.0.113.1"
        const val STUN_IP = "203.0.113.2"
        const val TURN_IP = "203.0.113.3"
        const val RELAY_IP = "203.0.113.4"
        const val ALICE_PORT = 4000
        const val BOB_PORT = 5000
        const val RELAY_PORT = 60000
    }
}

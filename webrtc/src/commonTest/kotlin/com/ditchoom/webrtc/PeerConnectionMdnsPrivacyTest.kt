@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.flow.AddressFamily
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.ice.IceAgentDriver
import com.ditchoom.webrtc.ice.MDNS_UDP_PORT
import com.ditchoom.webrtc.ice.MdnsEndpoint
import com.ditchoom.webrtc.ice.MdnsGroupBinding
import com.ditchoom.webrtc.ice.MdnsGroupSocket
import com.ditchoom.webrtc.ice.MdnsMulticastBinder
import com.ditchoom.webrtc.ice.MdnsResolution
import com.ditchoom.webrtc.ice.MdnsResolver
import com.ditchoom.webrtc.sdp.SdpType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * mDNS candidate privacy at the session layer (issue #88, RFC 8828): a session configured with
 * [MdnsAdvertisePolicy.Advertise] publishes `<uuid>.local` names instead of its host addresses, answers the
 * peer's queries for them, and still establishes.
 *
 * The privacy claim is asserted **against the bytes that leave** — the candidate lines this session hands
 * its application to signal — because that is the only place the property is real. Establishing is not the
 * assertion and could never be: on one flat segment RFC 8445 §7.3.1.3 peer-reflexive learning finds the path
 * from our own checks whether or not a single name was ever resolved, which is exactly the trap recorded
 * against the `mdns-*` interop lanes. So what is asserted is that the peer **resolved our name to our
 * address**, and that the address appears nowhere on the wire.
 *
 * Both halves are the production classes over the in-memory [TestNet]; only [MdnsMulticastBinder] — bind
 * 5353, join the group — is substituted.
 */
class PeerConnectionMdnsPrivacyTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun an_advertising_session_publishes_a_name_its_peer_resolves_and_never_its_address() =
        runTest {
            val f = peers(advertise = true)
            f.negotiate()

            val line = assertNotNull(withTimeoutOrNull(timeout) { f.alice.localIceCandidates.first() }, "alice signaled a candidate")
            assertTrue(".local " in line, "the host candidate publishes a name, not an address: $line")
            assertTrue(ALICE_IP !in line, "and the private address is nowhere on the line — not even in the foundation: $line")

            // The name is worth nothing unless the peer can turn it back into an address. That is the
            // property this whole feature exists for, and it is asserted from BOB's side, over the wire.
            f.bob.addIceCandidate(line)
            val resolved = assertNotNull(withTimeoutOrNull(timeout) { f.bobResolutions.await() }, "bob resolved alice's name")
            assertEquals(ALICE_IP, resolved.host, "…to alice's real address")

            assertNotNull(withTimeoutOrNull(timeout) { f.awaitConnected() }, "and the session still establishes")
        }

    @Test
    fun with_advertising_disabled_the_same_session_publishes_the_address() =
        runTest {
            // The causality proof: identical script, one config value different. Without it the assertion
            // above could be satisfied by a session that simply never gathered a host candidate.
            val f = peers(advertise = false)
            f.negotiate()

            val line = assertNotNull(withTimeoutOrNull(timeout) { f.alice.localIceCandidates.first() })
            assertTrue("$ALICE_IP " in line, "the default publishes the host address exactly as it always did: $line")
            assertTrue(".local" !in line, "and mints no name: $line")
        }

    @Test
    fun an_advertising_session_whose_responder_is_unavailable_publishes_the_address_rather_than_a_dead_name() =
        runTest {
            // A container without the multicast capability. Privacy is lost; connectivity must not be —
            // a name nothing answers would cost the peer the candidate outright.
            val f = peers(advertise = true, groupAvailable = false)
            f.negotiate()

            val line = assertNotNull(withTimeoutOrNull(timeout) { f.alice.localIceCandidates.first() })
            assertTrue(".local" !in line, "no name is published when nothing could answer for it: $line")
            assertTrue("$ALICE_IP " in line, "the address goes out in the clear instead: $line")
            assertNotNull(withTimeoutOrNull(timeout) { f.awaitConnected() }, "and the session establishes exactly as before")
        }

    // ---- fixture plumbing ---------------------------------------------------------------------------

    private class Peers(
        val alice: NativePeerConnection,
        val bob: NativePeerConnection,
        val bobResolutions: Resolutions,
    ) {
        /** Run the offer/answer round — which is what starts gathering, and so what produces a candidate line. */
        suspend fun negotiate() {
            val offer = alice.createOffer()
            alice.setLocalDescription(SdpType.Offer, offer)
            bob.setRemoteDescription(SdpType.Offer, offer)
            val answer = bob.createAnswer()
            bob.setLocalDescription(SdpType.Answer, answer)
            alice.setRemoteDescription(SdpType.Answer, answer)
        }

        suspend fun awaitConnected(): PeerConnectionState =
            alice.connectionState.first {
                when (it) {
                    is PeerConnectionState.Connected -> true
                    is PeerConnectionState.Failed -> error("expected a connection, but PeerConnection failed: ${it.reason}")
                    else -> false
                }
            }
    }

    /** Records what the peer's resolver actually resolved — the `WEBRTC_REQUIRE_MDNS` discipline, in a fixture. */
    private class Resolutions(
        private val delegate: MdnsResolver,
    ) : MdnsResolver {
        private val resolved = kotlinx.coroutines.CompletableDeferred<SocketAddress>()

        override suspend fun resolve(hostname: String): MdnsResolution =
            delegate.resolve(hostname).also { if (it is MdnsResolution.Resolved) resolved.complete(it.address) }

        suspend fun await(): SocketAddress = resolved.await()
    }

    /** Binds `<ip>:5353` on the [TestNet] and joins the group — the [MdnsMulticastBinder] actual, in memory. */
    private class TestNetBinder(
        private val net: TestNet,
        private val ip: String,
        private val available: Boolean,
    ) : MdnsMulticastBinder {
        override suspend fun bind(family: AddressFamily): MdnsGroupBinding {
            if (!available) return MdnsGroupBinding.Unavailable
            val local = SocketAddress.ofLiteral(ip, MDNS_UDP_PORT)
            val channel = net.bind(local)
            net.join(GROUP, local)
            return MdnsGroupBinding.Bound(MdnsGroupSocket(channel, GROUP))
        }
    }

    private fun TestScope.peers(
        advertise: Boolean,
        groupAvailable: Boolean = true,
    ): Peers {
        val net = TestNet()
        val binder = DatagramBinder { net.bind(it) }
        val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
        val scope: CoroutineScope = backgroundScope

        val aliceMdns = endpoint(scope, net, ALICE_IP, seed = 11, available = groupAvailable)
        val bobMdns = endpoint(scope, net, BOB_IP, seed = 12, available = true)
        val bobResolutions = Resolutions(bobMdns)

        val alice =
            NativePeerConnection(
                scope = scope,
                clock = clock,
                random = Random(1),
                binder = binder,
                gathering = { d: IceAgentDriver -> d.gatherHost(ALICE_IP, ALICE_PORT) },
                dtls = PlaintextDtls,
                config =
                    PeerConnectionConfig(
                        mdnsAdvertising =
                            if (advertise) MdnsAdvertisePolicy.Advertise(aliceMdns) else MdnsAdvertisePolicy.Disabled,
                    ),
            )
        val bob =
            NativePeerConnection(
                scope = scope,
                clock = clock,
                random = Random(2),
                binder = binder,
                gathering = { d: IceAgentDriver -> d.gatherHost(BOB_IP, BOB_PORT) },
                dtls = PlaintextDtls,
                config = PeerConnectionConfig(mdnsResolver = bobResolutions),
            )
        // Bob's candidates flow to alice unconditionally; alice's are fed to bob by each test, because the
        // line alice publishes IS what those tests are about.
        scope.launch { bob.localIceCandidates.collect { alice.addIceCandidate(it) } }
        return Peers(alice, bob, bobResolutions)
    }

    private fun endpoint(
        scope: CoroutineScope,
        net: TestNet,
        ip: String,
        seed: Long,
        available: Boolean,
    ): MdnsEndpoint =
        MdnsEndpoint(
            scope = scope,
            binder = TestNetBinder(net, ip, available),
            families = listOf(AddressFamily.IPv4),
            random = Random(seed),
        )

    private companion object {
        const val ALICE_IP = "10.0.0.1"
        const val BOB_IP = "10.0.0.2"
        const val ALICE_PORT = 4000
        const val BOB_PORT = 5000
        val GROUP: SocketAddress = SocketAddress.ofLiteral("224.0.0.251", MDNS_UDP_PORT)
    }
}

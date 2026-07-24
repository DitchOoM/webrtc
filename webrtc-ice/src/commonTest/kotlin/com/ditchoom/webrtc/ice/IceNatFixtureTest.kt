@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.NatProfile
import com.ditchoom.webrtc.ice.vnet.Vnets
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * The canonical W3 NAT fixtures (EXECUTION_PLAN W3 exit criteria), driven end-to-end through the vnet's
 * NAT profiles, STUN, and TURN — all under `runTest` virtual time on every platform. Each is a full
 * gather → trickle → check → nominate saga; the assertions are on observable state (the selected pair's
 * candidate types), never a wall-clock budget (directive #4).
 */
@OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)
class IceNatFixtureTest {
    @Test
    fun full_cone_peers_connect_via_server_reflexive() =
        runTest {
            // Two full-cone NATs: host candidates are on isolated LANs (unreachable), but the srflx
            // mappings are endpoint-independent, so the peers meet by hole-punching on srflx.
            val meetup = Vnets.meetup(backgroundScope, profileA = NatProfile.FullCone, profileB = NatProfile.FullCone)
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 11, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 22, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()

            alice.bindHost("10.0.0.2", 5000, stunServer = meetup.stunAddress)
            bob.bindHost("10.0.1.2", 5000, stunServer = meetup.stunAddress)
            alice.connectTo(bob)
            bob.connectTo(alice)

            assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "Alice connects over srflx")
            assertNotNull(withTimeoutOrNull(TIMEOUT) { bob.awaitConnected() }, "Bob connects over srflx")
            // The only reachable path is server-reflexive (host LANs are isolated; no relay gathered).
            assertEquals(CandidateType.ServerReflexive, alice.selectedPair!!.remote.type, "Alice's selected remote is srflx")
        }

    @Test
    fun dual_symmetric_nats_connect_only_via_relay() =
        runTest {
            // The load-bearing fixture (RFC §5.2): behind symmetric NATs, srflx is per-destination and
            // mutually filtered, so host and srflx both fail — only the TURN relay connects.
            val meetup = Vnets.meetup(backgroundScope, profileA = NatProfile.Symmetric, profileB = NatProfile.Symmetric)
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 33, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 44, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()

            alice.bindHost("10.0.0.2", 5000, stunServer = meetup.stunAddress)
            alice.gatherRelay(meetup.turnAddress, Vnets.TURN_USERNAME, Vnets.TURN_PASSWORD, "10.0.0.2", 6000)
            bob.bindHost("10.0.1.2", 5000, stunServer = meetup.stunAddress)
            bob.gatherRelay(meetup.turnAddress, Vnets.TURN_USERNAME, Vnets.TURN_PASSWORD, "10.0.1.2", 6000)
            alice.connectTo(bob)
            bob.connectTo(alice)

            assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "Alice connects — via the relay")
            assertNotNull(withTimeoutOrNull(TIMEOUT) { bob.awaitConnected() }, "Bob connects — via the relay")
            assertEquals(CandidateType.Relayed, alice.selectedPair!!.local.type, "Alice's selected local is the relay")
            assertEquals(CandidateType.Relayed, bob.selectedPair!!.local.type, "Bob's selected local is the relay")
        }

    @Test
    fun mixed_symmetric_and_port_restricted_peers_fall_back_to_relay() =
        runTest {
            // The `mixed-sym-port` lane: one symmetric peer, one port-restricted. The symmetric side's
            // srflx mapping is per-destination, so the advertised (STUN-learned) srflx is useless to the
            // port-restricted peer — even with host+srflx+relay all gathered, only the relay bridges them.
            val meetup = Vnets.meetup(backgroundScope, profileA = NatProfile.Symmetric, profileB = NatProfile.PortRestrictedCone)
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 55, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 66, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()

            alice.bindHost("10.0.0.2", 5000, stunServer = meetup.stunAddress)
            alice.gatherRelay(meetup.turnAddress, Vnets.TURN_USERNAME, Vnets.TURN_PASSWORD, "10.0.0.2", 6000)
            bob.bindHost("10.0.1.2", 5000, stunServer = meetup.stunAddress)
            bob.gatherRelay(meetup.turnAddress, Vnets.TURN_USERNAME, Vnets.TURN_PASSWORD, "10.0.1.2", 6000)
            alice.connectTo(bob)
            bob.connectTo(alice)

            assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "Alice connects — via the relay")
            assertNotNull(withTimeoutOrNull(TIMEOUT) { bob.awaitConnected() }, "Bob connects — via the relay")
            // Neither host nor srflx bridges a symmetric↔port-restricted mix: the selected pair is relayed.
            val pair = alice.selectedPair!!
            assertEquals(
                CandidateType.Relayed,
                pair.local.type,
                "the symmetric peer can only be reached on its relay, got local=${pair.local.type} remote=${pair.remote.type}",
            )
        }

    private companion object {
        val TIMEOUT = 60.seconds
    }
}

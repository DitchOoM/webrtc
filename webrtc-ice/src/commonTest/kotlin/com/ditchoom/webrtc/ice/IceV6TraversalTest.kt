@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.Filtering
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.stun.IpAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * **Routed-IPv6 traversal parity** — the deterministic `commonTest` analogue of the harness's IPv6 L2
 * lanes, so Apple/iOS/Node (and every other target) inherit the same v6 NAT-traversal + TURN(v6) +
 * forced-relay coverage the Linux-only Docker matrix proves over real routed IPv6, all under `runTest`
 * virtual time. Over routed IPv6 there is no NAT66 (see `RoutedFilter`/`RoutedFirewall`):
 *
 *  - [port_restricted_v6_peers_connect_directly_by_hole_punching] mirrors the `port-restricted` lane on
 *    the v6 family — a stateful filtering router still lets two peers meet **directly** over v6.
 *  - [firewall_forces_a_v6_relay_when_direct_is_blocked] mirrors the `firewall-relay6` lane — an
 *    administrative firewall drops direct/srflx, so ICE must *discover* the v6 TURN relay (RFC 8656,
 *    including the `REQUESTED-ADDRESS-FAMILY=IPv6` allocation the v6 relay demands).
 *
 * Assertions are on observable state (the connected state + the selected pair's family/type) and a
 * `withTimeoutOrNull` watchdog, never a wall-clock budget (directive #4).
 */
@OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)
class IceV6TraversalTest {
    @Test
    fun port_restricted_v6_peers_connect_directly_by_hole_punching() =
        runTest {
            // Routed v6 with port-dependent filtering: no NAT, no relay — the return path opens once each
            // side has sent out, so host↔host connectivity checks punch through and meet directly over v6.
            val meetup = Vnets.routedFilteredV6(backgroundScope, filtering = Filtering.AddressAndPortDependent)
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 61, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 62, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()

            alice.bindHost("fd00:31::100", 5000, stunServer = meetup.stunAddress)
            bob.bindHost("fd00:32::100", 5000, stunServer = meetup.stunAddress)
            alice.connectTo(bob)
            bob.connectTo(alice)

            assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "Alice connects directly over v6")
            assertNotNull(withTimeoutOrNull(TIMEOUT) { bob.awaitConnected() }, "Bob connects directly over v6")
            assertTrue(
                alice.selectedPair!!
                    .local.address.ip is IpAddress.V6,
                "the selected local is IPv6",
            )
            assertTrue(
                alice.selectedPair!!
                    .remote.address.ip is IpAddress.V6,
                "and the selected remote is IPv6",
            )
            // Direct path, not a relay: over routed v6 with an open-once-punched filter, the host pair wins.
            assertEquals(CandidateType.Host, alice.selectedPair!!.local.type, "the direct v6 host pair is selected, no relay")
        }

    @Test
    fun firewall_forces_a_v6_relay_when_direct_is_blocked() =
        runTest {
            // firewall-relay6: the routed-v6 firewall drops WAN→LAN except from the TURN server, so direct
            // and srflx host↔host checks never complete and ICE must fall back to the v6 relay it discovers.
            val meetup = Vnets.firewalledV6(backgroundScope)
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 63, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 64, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()

            // Each peer gathers a host (firewall-blocked for direct) and a v6 relay (the only path through).
            alice.bindHost("fd00:31::100", 5000, stunServer = meetup.stunAddress)
            alice.gatherRelay(meetup.turnAddress, Vnets.TURN_USERNAME, Vnets.TURN_PASSWORD, "fd00:31::100", 6000)
            bob.bindHost("fd00:32::100", 5000, stunServer = meetup.stunAddress)
            bob.gatherRelay(meetup.turnAddress, Vnets.TURN_USERNAME, Vnets.TURN_PASSWORD, "fd00:32::100", 6000)
            alice.connectTo(bob)
            bob.connectTo(alice)

            assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "Alice connects — via the discovered v6 relay")
            assertNotNull(withTimeoutOrNull(TIMEOUT) { bob.awaitConnected() }, "Bob connects — via the discovered v6 relay")

            // The selected pair must traverse the relay on at least one endpoint (the harness's Relayed
            // assertion), and stay entirely on IPv6.
            val pair = alice.selectedPair!!
            assertTrue(
                pair.local.type == CandidateType.Relayed || pair.remote.type == CandidateType.Relayed,
                "a firewall-forced relay: the selected pair has a Relayed endpoint, got local=${pair.local.type} remote=${pair.remote.type}",
            )
            assertTrue(pair.local.address.ip is IpAddress.V6, "the selected local is IPv6 (v6 relay, not a v4/loopback fallback)")
            assertTrue(pair.remote.address.ip is IpAddress.V6, "the selected remote is IPv6")
        }

    private companion object {
        val TIMEOUT = 60.seconds
    }
}

@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.Vnets
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * The first end-to-end proof of the ICE core: two [IceAgent]s establish a session over the flat vnet
 * (two host candidates, mutually reachable) entirely under `runTest` virtual time. The controlling
 * agent nominates; both reach a connected state with the same selected pair. Assertion discipline is
 * observable state + the `runTest`/`withTimeoutOrNull` watchdog, never a wall-clock budget (directive #4).
 */
@OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)
class IceConnectivityTest {
    @Test
    fun two_agents_connect_host_to_host_over_flat_vnet() =
        runTest {
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 1, vnet = vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 2, vnet = vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()

            alice.bindHost("10.0.0.1", 4000)
            bob.bindHost("10.0.0.2", 5000)
            alice.connectTo(bob)
            bob.connectTo(alice)

            val aliceState = withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }
            val bobState = withTimeoutOrNull(TIMEOUT) { bob.awaitConnected() }

            assertNotNull(aliceState, "the controlling agent must reach a connected state")
            assertNotNull(bobState, "the controlled agent must reach a connected state")
            assertNotNull(alice.selectedPair, "Alice selected a pair")
            assertNotNull(bob.selectedPair, "Bob selected a pair")

            // Both agents converge on the same transport addresses (mirror pairs).
            assertEquals(alice.selectedPair!!.local.base, bob.selectedPair!!.remote.address, "Alice's local base is Bob's remote")
            assertEquals(alice.selectedPair!!.remote.address, bob.selectedPair!!.local.base, "and vice versa")
        }

    @Test
    fun controlling_agent_completes_after_nomination() =
        runTest {
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 7, vnet = vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 8, vnet = vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()
            alice.bindHost("192.168.1.10", 3000)
            bob.bindHost("192.168.1.20", 3000)
            alice.connectTo(bob)
            bob.connectTo(alice)

            withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }
            // Drive a little longer so the checklist drains and the controlling agent reaches Completed.
            val completed = withTimeoutOrNull(TIMEOUT) { alice.state.first { it is IceConnectionState.Completed } }
            assertTrue(completed is IceConnectionState.Completed, "the controlling agent completes once the checklist is exhausted")
        }

    @Test
    fun role_conflict_is_resolved_by_the_tie_breaker() =
        runTest {
            // Both agents start believing they are controlling (RFC 8445 §7.3.1.1) — a lite-vs-lite or
            // double-offer glare. The larger tie-breaker keeps the role; the other switches, and they
            // still converge on a single selected pair.
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 100, vnet = vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlling, seed = 200, vnet = vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()
            alice.bindHost("10.1.0.1", 4000)
            bob.bindHost("10.1.0.2", 5000)
            alice.connectTo(bob)
            bob.connectTo(alice)

            assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "Alice connects despite the initial role clash")
            assertNotNull(withTimeoutOrNull(TIMEOUT) { bob.awaitConnected() }, "Bob connects despite the initial role clash")
            assertTrue(alice.agent.role != bob.agent.role, "exactly one agent ends up controlling")
        }

    private companion object {
        val TIMEOUT = 30.seconds
    }
}

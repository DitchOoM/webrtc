@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
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
 * Dual-stack ICE (Phase 1.5-A) end-to-end over the vnet. The affirmative counterpart to
 * `IceReviewRegressionTest`'s cross-family `NoCandidatePairs` reject: a v6 local **does** pair with a v6
 * remote and reach a connected state, and a dual-stack agent deterministically prefers the IPv6 pair
 * (RFC 8445 §5.1.2.2 → RFC 6724, via [CandidatePreferencePolicy]). Assertion discipline is observable
 * state + the `withTimeoutOrNull` watchdog, never a wall-clock budget (directive #4).
 */
@OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)
class IceDualStackTest {
    @Test
    fun v6_host_pairs_with_v6_host_and_connects() =
        runTest {
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 11, vnet = vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 12, vnet = vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()

            alice.bindHost("2001:db8::1", 4000)
            bob.bindHost("2001:db8::2", 5000)
            alice.connectTo(bob)
            bob.connectTo(alice)

            val aliceState = withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }
            val bobState = withTimeoutOrNull(TIMEOUT) { bob.awaitConnected() }

            assertNotNull(aliceState, "the controlling agent reaches a connected state over IPv6 (not NoCandidatePairs)")
            assertNotNull(bobState, "the controlled agent reaches a connected state over IPv6")
            assertTrue(
                alice.selectedPair!!
                    .local.address.ip is IpAddress.V6,
                "the selected pair is IPv6",
            )
            // Mirror pairs: Alice's local base is Bob's remote and vice-versa.
            assertEquals(alice.selectedPair!!.local.base, bob.selectedPair!!.remote.address, "Alice's local base is Bob's remote")
            assertEquals(alice.selectedPair!!.remote.address, bob.selectedPair!!.local.base, "and vice versa")
        }

    @Test
    fun dual_stack_agents_select_the_ipv6_pair() =
        runTest {
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 21, vnet = vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 22, vnet = vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()

            // Each agent is dual-stack: a v4 host AND a v6 GUA host of the same component.
            alice.bindHost("10.0.0.1", 4000)
            alice.bindHost("2001:db8:a::1", 4000)
            bob.bindHost("10.0.0.2", 5000)
            bob.bindHost("2001:db8:a::2", 5000)
            alice.connectTo(bob)
            bob.connectTo(alice)

            assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "Alice connects")
            assertNotNull(withTimeoutOrNull(TIMEOUT) { bob.awaitConnected() }, "Bob connects")

            // The v6 GUA host out-prioritizes the v4 host (CandidatePreferencePolicy), so the nominated pair is v6.
            assertTrue(
                alice.selectedPair!!
                    .local.address.ip is IpAddress.V6,
                "a dual-stack agent nominates the IPv6 pair, got ${alice.selectedPair!!.local.address.ip}",
            )
            assertTrue(
                bob.selectedPair!!
                    .local.address.ip is IpAddress.V6,
                "and both sides agree on the v6 pair",
            )
        }

    private companion object {
        val TIMEOUT = 30.seconds
    }
}

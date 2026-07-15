@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.ImpairmentConfig
import com.ditchoom.webrtc.ice.vnet.NatProfile
import com.ditchoom.webrtc.ice.vnet.Vnets
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * The W3 **timeline fuzz smoke lane** (pinned seeds) and the ICE **invariant set** (RFC §5.3): across a
 * spread of seeds and NAT profiles the agent must (1) reach a definite state and never hang — liveness;
 * (2) select a valid, role-symmetric pair; and (3) replay bit-for-bit for a fixed seed — the
 * determinism a ddmin shrinker needs. A deep-run campaign with a shrinker is a JVM lane (W5+); this is
 * the always-on smoke that guards the invariants on every platform.
 */
@OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)
class IceFuzzTest {
    @Test
    fun establishes_under_loss_and_jitter_across_seeds() =
        runTest {
            // Loss + reordering on the check path: connectivity-check retransmission (the W1
            // StunTransaction) must still drive both agents to a connected state (liveness invariant).
            val impairment = ImpairmentConfig(loss = 0.2, minDelay = 5.milliseconds, maxDelay = 40.milliseconds)
            for (seed in SEEDS) {
                val vnet = Vnets.flatImpaired(backgroundScope, impairment, seed = seed)
                val clock = IceDriver.clockOf { testScheduler.currentTime }
                val alice = IceDriver(IceRole.Controlling, seed = seed, vnet = vnet, scope = backgroundScope, clock = clock)
                val bob = IceDriver(IceRole.Controlled, seed = seed + 1, vnet = vnet, scope = backgroundScope, clock = clock)
                alice.start()
                bob.start()
                alice.bindHost("10.0.0.1", 4000)
                bob.bindHost("10.0.0.2", 5000)
                alice.connectTo(bob)
                bob.connectTo(alice)

                assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "seed $seed: connects despite loss (no hang)")
                assertNotNull(withTimeoutOrNull(TIMEOUT) { bob.awaitConnected() }, "seed $seed: peer connects too")
                // Role-symmetry invariant: each agent's selected local base is the other's selected remote.
                assertEquals(alice.selectedPair!!.local.base, bob.selectedPair!!.remote.address, "seed $seed: pairs mirror")
                assertEquals(bob.selectedPair!!.local.base, alice.selectedPair!!.remote.address, "seed $seed: pairs mirror")
            }
        }

    @Test
    fun establishment_is_deterministic_for_a_fixed_seed() =
        runTest {
            // Same seed ⇒ identical selected pair — the replay precondition a shrinker relies on.
            val first = runSrflx(this, seed = 4242)
            val second = runSrflx(this, seed = 4242)
            assertNotNull(first, "the fixed-seed run connects")
            assertEquals(first, second, "a fixed seed yields the identical selected transport addresses")
        }

    @Test
    fun every_nat_profile_reaches_a_terminal_state() =
        runTest {
            // Coverage across the NAT taxonomy — each must terminate (connect or a typed failure), never
            // hang. Cone profiles connect on srflx; symmetric (host-only, no relay) fails AllPairsFailed.
            val profiles =
                listOf(NatProfile.FullCone, NatProfile.AddressRestrictedCone, NatProfile.PortRestrictedCone, NatProfile.Symmetric)
            for ((index, profile) in profiles.withIndex()) {
                val meetup = Vnets.meetup(backgroundScope, profileA = profile, profileB = profile)
                val clock = IceDriver.clockOf { testScheduler.currentTime }
                val alice = IceDriver(IceRole.Controlling, seed = 500L + index, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
                val bob = IceDriver(IceRole.Controlled, seed = 600L + index, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
                alice.start()
                bob.start()
                alice.bindHost("10.0.0.2", 5000, stunServer = meetup.stunAddress)
                bob.bindHost("10.0.1.2", 5000, stunServer = meetup.stunAddress)
                alice.connectTo(bob)
                bob.connectTo(alice)

                assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.state.firstTerminal() }, "$profile: reaches a terminal state, never hangs")
            }
        }

    // Run a full-cone srflx establishment and return the selected transport addresses (or null).
    private suspend fun runSrflx(
        scope: TestScope,
        seed: Long,
    ): Pair<String, String>? {
        val meetup = Vnets.meetup(scope.backgroundScope, profileA = NatProfile.FullCone, profileB = NatProfile.FullCone)
        val clock = IceDriver.clockOf { scope.testScheduler.currentTime }
        val alice = IceDriver(IceRole.Controlling, seed = seed, vnet = meetup.vnet, scope = scope.backgroundScope, clock = clock)
        val bob = IceDriver(IceRole.Controlled, seed = seed + 1, vnet = meetup.vnet, scope = scope.backgroundScope, clock = clock)
        alice.start()
        bob.start()
        alice.bindHost("10.0.0.2", 5000, stunServer = meetup.stunAddress)
        bob.bindHost("10.0.1.2", 5000, stunServer = meetup.stunAddress)
        alice.connectTo(bob)
        bob.connectTo(alice)
        withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() } ?: return null
        val pair = alice.selectedPair ?: return null
        return pair.local.address.toString() to pair.remote.address.toString()
    }

    private suspend fun StateFlow<IceConnectionState>.firstTerminal(): IceConnectionState =
        first { it is IceConnectionState.Connected || it is IceConnectionState.Completed || it is IceConnectionState.Failed }

    private companion object {
        val SEEDS = listOf(1L, 7L, 42L, 99L, 12345L)
        val TIMEOUT = 60.seconds
    }
}

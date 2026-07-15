@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.NatProfile
import com.ditchoom.webrtc.ice.vnet.Vnets
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * The ICE **lifecycle** fixtures (EXECUTION_PLAN W3 exit criteria + the typed-failure surface): a
 * candidate flapping mid-check, a `NetworkId` change forcing an ICE restart, RFC 7675 consent expiry,
 * and the all-pairs-failed terminal. Each asserts the agent reaches a definite observable state and
 * never hangs — the liveness invariant (RFC §5.3 #5), enforced by the `runTest` watchdog.
 */
@OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)
class IceLifecycleTest {
    @Test
    fun connection_survives_a_candidate_flapping_mid_check() =
        runTest {
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 1, vnet = vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 2, vnet = vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()

            // Alice has two interfaces; the higher-priority one is torn down just as checks begin.
            val doomed = alice.bindHost("10.0.0.1", 4000)
            alice.bindHost("10.0.0.3", 4001)
            bob.bindHost("10.0.0.2", 5000)
            alice.connectTo(bob)
            bob.connectTo(alice)
            alice.drop(doomed)

            assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "Alice still connects after the flap")
            assertNotNull(withTimeoutOrNull(TIMEOUT) { bob.awaitConnected() }, "Bob connects")
            assertNotEquals(doomed.base, alice.selectedPair!!.local.base, "the selected pair avoids the dropped candidate")
        }

    @Test
    fun network_id_change_triggers_restart_and_reconnects() =
        runTest {
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 5, vnet = vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 6, vnet = vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()
            alice.bindHost("10.0.0.1", 4000)
            bob.bindHost("10.0.0.2", 5000)
            alice.connectTo(bob)
            bob.connectTo(alice)
            assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "initial connection")

            val credentialsBeforeRestart = alice.agent.localCredentials

            // A Wi-Fi→cellular flip: both sides restart, re-gather on the new interface, re-signal. Await
            // the restart landing (state → New) before reading the regenerated credentials, since Restart
            // is processed asynchronously on the driver loop.
            alice.post(IceEvent.Restart)
            bob.post(IceEvent.Restart)
            withTimeoutOrNull(TIMEOUT) { alice.state.first { it is IceConnectionState.New } }
            withTimeoutOrNull(TIMEOUT) { bob.state.first { it is IceConnectionState.New } }
            alice.bindHost("10.9.0.1", 4000) // the new interface
            bob.bindHost("10.9.0.2", 5000)
            alice.connectTo(bob)
            bob.connectTo(alice)

            // The state flow conflates the transient Connected into Completed, so accept either — what
            // matters is the selected pair now uses the new interface.
            val reconnected = withTimeoutOrNull(TIMEOUT) { alice.state.first { selectedOf(it)?.local?.base?.ip() == "10.9.0.1" } }
            assertNotNull(reconnected, "Alice reconnects over the new interface after the restart")
            assertNotEquals(credentialsBeforeRestart, alice.agent.localCredentials, "restart regenerates local credentials (RFC 8445 §9)")
        }

    @Test
    fun consent_expiry_fails_the_connection_when_the_peer_goes_silent() =
        runTest {
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val config = IceConfig(consentInterval = 1.seconds, consentTimeout = 5.seconds)
            val alice = IceDriver(IceRole.Controlling, seed = 3, vnet = vnet, scope = backgroundScope, clock = clock, config = config)
            val bob = IceDriver(IceRole.Controlled, seed = 4, vnet = vnet, scope = backgroundScope, clock = clock, config = config)
            alice.start()
            bob.start()
            val bobHost = bob.bindHost("10.0.0.2", 5000)
            alice.bindHost("10.0.0.1", 4000)
            alice.connectTo(bob)
            bob.connectTo(alice)
            assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "connect first")

            // The peer's socket vanishes — consent refreshes stop being answered (RFC 7675 §5.1).
            bob.drop(bobHost)

            val failure = withTimeoutOrNull(TIMEOUT) { alice.state.first { it is IceConnectionState.Failed } }
            assertTrue(
                failure is IceConnectionState.Failed && failure.reason == IceFailureReason.ConsentExpired,
                "consent expiry is a typed ConsentExpired failure, got $failure",
            )
        }

    @Test
    fun all_pairs_failing_is_a_typed_terminal_failure() =
        runTest {
            // Symmetric NATs with only host candidates (no srflx usable, no relay gathered): every pair is
            // unreachable, so the checklist exhausts to a typed AllPairsFailed rather than hanging.
            val meetup = Vnets.meetup(backgroundScope, profileA = NatProfile.Symmetric, profileB = NatProfile.Symmetric)
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 7, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 8, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()
            alice.bindHost("10.0.0.2", 5000)
            bob.bindHost("10.0.1.2", 5000)
            alice.connectTo(bob)
            bob.connectTo(alice)

            val failure = withTimeoutOrNull(TIMEOUT) { alice.state.first { it is IceConnectionState.Failed } }
            assertTrue(
                failure is IceConnectionState.Failed && failure.reason is IceFailureReason.AllPairsFailed,
                "host-only across symmetric NATs fails with AllPairsFailed, got $failure",
            )
        }

    private fun selectedOf(state: IceConnectionState): CandidatePair? =
        when (state) {
            is IceConnectionState.Connected -> state.selected
            is IceConnectionState.Completed -> state.selected
            else -> null
        }

    private companion object {
        val TIMEOUT = 90.seconds
    }
}

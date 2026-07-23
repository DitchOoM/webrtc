@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.ImpairmentConfig
import com.ditchoom.webrtc.ice.vnet.Vnets
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.job
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * **ICE-restart convergence under loss (RFC 8445 §9, CO-3).** Mirrors
 * [IceLifecycleTest.network_id_change_triggers_restart_and_reconnects] but runs the restart over a seeded
 * [ImpairmentConfig] pipe at 5/10/20 % per-datagram loss across a seed sweep. A Wi-Fi→cellular flip
 * restarts both agents; they re-gather on a new interface, re-signal, and re-nominate — and the fresh
 * connectivity checks (including the post-restart nomination) must converge despite dropped checks, on
 * the W1 [StunTransaction] retransmission.
 *
 * Two observables: the selected pair must move to the **new** interface (`10.9.0.x`), and the restart must
 * regenerate the local credentials (`assertNotEquals`, RFC 8445 §9). Per the template, the state flow
 * conflates the transient Connected into Completed, so convergence is matched on the selected-pair
 * predicate rather than a specific state. Loss is seeded (directive #2); the watchdog is `runTest` virtual
 * time, never a wall-clock budget (directive #4).
 *
 * Each seed runs in its own child scope that is cancelled before the next iteration, so the long-lived
 * driver/impairment loops never accumulate across the sweep — otherwise every later iteration would also
 * be advancing all earlier iterations' still-live loops, an O(N²) blowup that overruns `runTest`'s
 * wall-clock dispatch budget on the slower native/JS lanes (surfacing as `UncompletedCoroutinesError`).
 */
class IceRestartLossTest {
    @Test
    fun ice_restart_reconverges_under_loss_across_seeds() =
        runTest {
            for (loss in LOSS_RATES) {
                for (s in 0 until SEEDS_PER_RATE) {
                    val seed = BASE_SEED + s
                    val diag = "loss=$loss seed=$seed"
                    // A per-seed child scope: cancelled in `finally` so its driver/impairment loops don't
                    // outlive the iteration. Its Job is a child of backgroundScope's, so a thrown assertion
                    // still tears it down when the whole test unwinds.
                    val trial = CoroutineScope(backgroundScope.coroutineContext + Job(backgroundScope.coroutineContext.job))
                    try {
                        val vnet = Vnets.flatImpaired(trial, ImpairmentConfig(loss = loss), seed = seed)
                        val clock = IceDriver.clockOf { testScheduler.currentTime }
                        val alice = IceDriver(IceRole.Controlling, seed = seed, vnet = vnet, scope = trial, clock = clock)
                        val bob = IceDriver(IceRole.Controlled, seed = seed + SEED_SPREAD, vnet = vnet, scope = trial, clock = clock)
                        alice.start()
                        bob.start()
                        alice.bindHost("10.0.0.1", 4000)
                        bob.bindHost("10.0.0.2", 5000)
                        alice.connectTo(bob)
                        bob.connectTo(alice)
                        assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "initial connection under loss ($diag)")

                        val credentialsBeforeRestart = alice.agent.localCredentials

                        // The Wi-Fi→cellular flip: both sides restart, re-gather on the new interface, re-signal.
                        // Restart is a local event (not lossy); await it landing (state → New) before re-gathering.
                        alice.post(IceEvent.Restart)
                        bob.post(IceEvent.Restart)
                        assertNotNull(
                            withTimeoutOrNull(TIMEOUT) { alice.state.first { it is IceConnectionState.New } },
                            "alice restarts ($diag)",
                        )
                        assertNotNull(
                            withTimeoutOrNull(TIMEOUT) { bob.state.first { it is IceConnectionState.New } },
                            "bob restarts ($diag)",
                        )
                        alice.bindHost("10.9.0.1", 4000) // the new interface
                        bob.bindHost("10.9.0.2", 5000)
                        alice.connectTo(bob)
                        bob.connectTo(alice)

                        // The re-nomination must converge on the new interface despite dropped post-restart checks.
                        val reconnected =
                            withTimeoutOrNull(TIMEOUT) { alice.state.first { selectedOf(it)?.local?.base?.ip() == "10.9.0.1" } }
                        assertNotNull(reconnected, "alice re-nominates over the new interface after the restart under loss ($diag)")
                        assertNotEquals(
                            credentialsBeforeRestart,
                            alice.agent.localCredentials,
                            "restart regenerates local credentials (RFC 8445 §9) ($diag)",
                        )
                    } finally {
                        // cancelAndJoin (not cancel): on Kotlin/JS cancellation is asynchronous, so a bare
                        // cancel() can leave a cancelled coroutine's `delay`-backed Node timer pending past the
                        // test's end (the `node:internal/timers` JS flake). Joining drains the child scope
                        // deterministically under virtual time before the next seed proceeds.
                        trial.coroutineContext.job.cancelAndJoin()
                    }
                }
            }
        }

    private fun selectedOf(state: IceConnectionState): CandidatePair? =
        when (state) {
            is IceConnectionState.Connected -> state.selected
            is IceConnectionState.Completed -> state.selected
            else -> null
        }

    private companion object {
        val LOSS_RATES = listOf(0.05, 0.10, 0.20)
        const val SEEDS_PER_RATE = 5
        const val BASE_SEED = 830_000L // distinct base so seeds don't collide with the sibling loss lanes
        const val SEED_SPREAD = 613L
        val TIMEOUT = 90.seconds
    }
}

@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.CountingBufferFactory
import com.ditchoom.webrtc.ice.vnet.ImpairmentConfig
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.stun.StunRetransmitPolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.job
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * **Consent-freshness convergence under loss (RFC 7675, CO-3).** The mirror-opposite of
 * [IceLifecycleTest.consent_expiry_fails_the_connection_when_the_peer_goes_silent]: there the peer goes
 * silent and consent *must* fail; here **both peers stay alive** on a lossy link and consent must *not*
 * fail — a single dropped consent check does not fail the pair (RFC 7675; [IceAgent] "a lost consent check
 * doesn't fail the pair"), and re-consent converges on the next interval.
 *
 * The knobs make the invariant sharp: a **compressed** `consentInterval` (many refresh cycles in the
 * window) with a `consentTimeout` long enough to survive several consecutive dropped refreshes. Over a
 * long observation window at 5/10/20 % loss across a seed sweep, the connection must stay
 * Connected/Completed and **never** reach `Failed(ConsentExpired)`.
 *
 * This test also carries the directive-#6 no-leak assertion for the exact regression class the storm
 * exposed: a shared [CountingBufferFactory] is threaded through the vnet, and allocation growth over the
 * window must scale with the messages sent (consent checks + their retransmits), not with the ~50 ms Ta
 * timer ticks — a per-tick leak would blow far past the bound. Loss is seeded (directive #2); the watchdog
 * is `runTest` virtual time, never a wall-clock budget (directive #4).
 */
class IceConsentLossTest {
    @Test
    fun consent_freshness_survives_loss_across_seeds() =
        runTest {
            for (loss in LOSS_RATES) {
                for (s in 0 until SEEDS_PER_RATE) {
                    val seed = BASE_SEED + s
                    val diag = "loss=$loss seed=$seed"
                    // A per-seed child scope: cancelled in `finally` so its driver/impairment loops don't
                    // outlive the iteration and accumulate across the sweep (which would overrun runTest's
                    // wall-clock dispatch budget on the slower native/JS lanes — UncompletedCoroutinesError).
                    val trial = CoroutineScope(backgroundScope.coroutineContext + Job(backgroundScope.coroutineContext.job))
                    try {
                        val factory = CountingBufferFactory(BufferFactory.Default)
                        val vnet = Vnets.flatImpaired(trial, ImpairmentConfig(loss = loss), seed = seed, bufferFactory = factory)
                        val clock = IceDriver.clockOf { testScheduler.currentTime }
                        // Fast consent with many closely-spaced check retransmits (small RTO): a consent
                        // response reliably lands well inside the timeout even at 20 % loss, so re-consent
                        // converges rather than the pair aging out on an unlucky run of drops. The timeout is
                        // comfortably larger than a check's useful retransmit span; the window spans several
                        // timeouts (so a fragile pair *would* expire within it).
                        val config =
                            IceConfig(
                                consentInterval = CONSENT_INTERVAL,
                                consentTimeout = CONSENT_TIMEOUT,
                                checkPolicy = StunRetransmitPolicy(rto = 100.milliseconds, maxTransmissions = 10),
                            )
                        val alice =
                            IceDriver(IceRole.Controlling, seed = seed, vnet = vnet, scope = trial, clock = clock, config = config)
                        val bob =
                            IceDriver(
                                IceRole.Controlled,
                                seed = seed + SEED_SPREAD,
                                vnet = vnet,
                                scope = trial,
                                clock = clock,
                                config = config,
                            )
                        alice.start()
                        bob.start()
                        alice.bindHost("10.0.0.1", 4000)
                        bob.bindHost("10.0.0.2", 5000)
                        alice.connectTo(bob)
                        bob.connectTo(alice)
                        assertNotNull(withTimeoutOrNull(CONNECT_TIMEOUT) { alice.awaitConnected() }, "alice connects under loss ($diag)")
                        assertNotNull(withTimeoutOrNull(CONNECT_TIMEOUT) { bob.awaitConnected() }, "bob connects under loss ($diag)")

                        val allocationsAfterConnect = factory.allocations
                        // Observe for a long window of consent cycles. Watching for Failed both advances virtual
                        // time and asserts the negative: if consent ever expired, this returns non-null.
                        val failed = withTimeoutOrNull(OBSERVE_WINDOW) { alice.state.first { it is IceConnectionState.Failed } }
                        assertNull(failed, "consent re-converges under loss; the pair never fails ConsentExpired ($diag)")

                        val stillUp =
                            alice.state.value.let { it is IceConnectionState.Connected || it is IceConnectionState.Completed }
                        assertTrue(stillUp, "the connection is still live after the observation window ($diag)")

                        // Directive #6: allocation grows with consent messages (+ their retransmits), not per Ta
                        // tick. A per-tick leak over the window would allocate ~OBSERVE_WINDOW/Ta buffers.
                        val growth = factory.allocations - allocationsAfterConnect
                        assertTrue(growth > 0, "consent refreshes keep flowing under loss (growth=$growth, $diag)")
                        assertTrue(
                            growth < CONSENT_CYCLES * PER_CYCLE_ALLOCATION_BOUND,
                            "allocations scale with messages, not Ta ticks (growth=$growth over $CONSENT_CYCLES cycles, $diag)",
                        )
                    } finally {
                        // cancelAndJoin (not cancel): on Kotlin/JS cancellation is asynchronous — a bare cancel()
                        // returns before the cancelled coroutines' `delay`-backed Node timers are cleared, so a
                        // stray timer can fire after the test completes and surface as `node:internal/timers`
                        // (crashing whichever test runs next). Joining drains the child scope — clearing every
                        // pending timer — deterministically under virtual time before the next seed proceeds.
                        trial.coroutineContext.job.cancelAndJoin()
                    }
                }
            }
        }

    private companion object {
        val LOSS_RATES = listOf(0.05, 0.10, 0.20)
        const val SEEDS_PER_RATE = 4
        const val BASE_SEED = 820_000L // distinct base so seeds don't collide with the sibling loss lanes
        const val SEED_SPREAD = 613L
        val CONSENT_INTERVAL = 1.seconds

        // The window comfortably exceeds the consent timeout (so a fragile pair *would* expire within it); the
        // timeout is in turn comfortably larger than a check's useful retransmit span. Kept compact (and the
        // sweep modest) so the whole sweep's virtual-time advancement stays light on the JS runner — every
        // advanced virtual millisecond still costs real dispatch work, and a stray leaked timer past test-end
        // is the `node:internal/timers` JS flake — the observable is state, never a wall-clock assertion (#4).
        val CONSENT_TIMEOUT = 10.seconds
        val OBSERVE_WINDOW = 16.seconds
        const val CONSENT_CYCLES = 16 // OBSERVE_WINDOW / CONSENT_INTERVAL
        val CONNECT_TIMEOUT = 30.seconds

        // Generous per-cycle bound: each cycle a consent check may retransmit several times and each surviving
        // datagram costs one vnet copy-on-send snapshot. A per-Ta-tick leak (300 ticks over the window) would
        // blow far past CONSENT_CYCLES * this bound.
        const val PER_CYCLE_ALLOCATION_BOUND = 80
    }
}

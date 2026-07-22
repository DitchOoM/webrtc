@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.ImpairmentConfig
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
 * **ICE nomination under loss (WS-1).** [IceFuzzTest] proves liveness under one impairment profile across a
 * few seeds; this drills the specific sub-property the "storm" class threatened at the ICE layer —
 * **nomination convergence** — across a wide seed sweep at 5/10/20 % per-datagram loss.
 *
 * The controlling agent drives nomination by sending USE-CANDIDATE on a connectivity check and needs the
 * check's binding **response** back to promote the pair; when either the USE-CANDIDATE request or its
 * response is dropped, nomination must still converge on retransmission rather than stall. The observable
 * is strong: the **controlling** agent must reach [IceConnectionState.Completed] — which happens *only*
 * after a pair is nominated and the checklist drains (RFC 8445 §8.1.2) — not merely `Connected`. Both
 * agents must then agree on a single mirror-symmetric selected pair. Loss is seeded (directive #2), so each
 * failing seed is a bit-for-bit replayable scenario; the watchdog is `runTest` virtual time, never a
 * wall-clock budget (directive #4).
 */
class IceNominationLossTest {
    @Test
    fun nomination_converges_under_loss_across_seeds() =
        runTest {
            for (loss in LOSS_RATES) {
                val impairment = ImpairmentConfig(loss = loss)
                for (s in 0 until SEEDS_PER_RATE) {
                    val seed = BASE_SEED + s
                    val vnet = Vnets.flatImpaired(backgroundScope, impairment, seed = seed)
                    val clock = IceDriver.clockOf { testScheduler.currentTime }
                    val alice = IceDriver(IceRole.Controlling, seed = seed, vnet = vnet, scope = backgroundScope, clock = clock)
                    val bob = IceDriver(IceRole.Controlled, seed = seed + SEED_SPREAD, vnet = vnet, scope = backgroundScope, clock = clock)
                    alice.start()
                    bob.start()
                    alice.bindHost("10.0.0.1", 4000)
                    bob.bindHost("10.0.0.2", 5000)
                    alice.connectTo(bob)
                    bob.connectTo(alice)

                    val diag = "loss=$loss seed=$seed"
                    // Completed (not just Connected): the controlling agent got here only by nominating a pair
                    // and draining the checklist — i.e. nomination converged despite the dropped checks.
                    val completed = withTimeoutOrNull(TIMEOUT) { alice.state.first { it is IceConnectionState.Completed } }
                    assertNotNull(completed, "controlling agent nominated and completed under loss ($diag)")
                    assertNotNull(withTimeoutOrNull(TIMEOUT) { bob.awaitConnected() }, "controlled agent connected under loss ($diag)")

                    val alicePair = assertNotNull(alice.selectedPair, "alice selected a pair ($diag)")
                    val bobPair = assertNotNull(bob.selectedPair, "bob selected a pair ($diag)")
                    assertEquals(alicePair.local.base, bobPair.remote.address, "mirror pairs ($diag)")
                    assertEquals(bobPair.local.base, alicePair.remote.address, "mirror pairs ($diag)")
                    assertTrue(alice.agent.role != bob.agent.role, "roles stay symmetric ($diag)")
                }
            }
        }

    private companion object {
        val LOSS_RATES = listOf(0.05, 0.10, 0.20)
        const val SEEDS_PER_RATE = 16
        const val BASE_SEED = 770_000L // arbitrary distinct base so seeds don't collide with the sibling fuzz lane
        const val SEED_SPREAD = 977L
        val TIMEOUT = 60.seconds
    }
}

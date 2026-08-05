@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.Vnets
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **Closing a connected driver returns its drive loop.** It used to spin instead, forever.
 *
 * [IceAgentDriver.close] closes the inbox, and the timed branch of `driveLoop`'s `select` answered `null`
 * for a closed inbox *and* for an expired deadline, which the `when` below it read as "timer fired". A
 * driver closed with any deadline armed — and a connected session always has one, consent if nothing
 * else — therefore re-entered `handle(TimerFired)` and never returned. The coroutine died only when its
 * surrounding scope was cancelled.
 *
 * ## Why no fixture caught it before
 *
 * Nothing closed a *connected* pair. `IceAgentDriverTest` establishes and lets `runTest` cancel
 * `backgroundScope`; the lifecycle fixtures one layer up close a peer that never connected, and with no
 * deadline armed the loop takes the **untimed** branch, whose `?: return` was always correct. The bug
 * lived exactly in the gap between those two.
 *
 * ## Why this fixture has to break the spin itself
 *
 * The obvious shape — close, yield a bounded number of times, assert the loop did not run again — does
 * not work here, and the reason is worth writing down: `select` **completes without suspending** when one
 * of its clauses is already ready, and a closed `onReceiveCatching` always is. So the broken loop never
 * reaches a suspension point, never re-dispatches, and never yields the thread. It is a hard CPU spin,
 * not a busy sequence of dispatches. Under `runTest` that hangs the whole test — every observation the
 * test body might make is starved, including the timeout that would have reported it.
 *
 * So the probe doubles as the circuit-breaker. [IceAgentDriver] takes its clock as an injected seam
 * (directive #2) and `driveLoop` reads it on every pass, which makes a counting clock an exact measure of
 * "did this loop run again". Past a budget it throws [CancellationException] — the one throw that unwinds
 * the spinning coroutine without turning into a test failure of its own — so the run always terminates
 * and the verdict is an ordinary assertion. No wall-clock is consulted anywhere (directive #4): under the
 * fix the loop reads the clock a couple of times and returns, under the bug it blows the budget, and
 * neither outcome depends on how fast the machine is.
 */
class IceAgentDriverCloseTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun closing_a_connected_driver_returns_its_drive_loop_instead_of_spinning() =
        runTest {
            val vnet = Vnets.flat()
            val binder = DatagramBinder { vnet.bind(it) }

            // `reads` runs the whole time — before close it proves the probe is wired to live loops, after
            // close it is the measurement. The budget only arms at close, because establishment reads the
            // clock constantly and legitimately.
            var reads = 0
            var counting = false
            var readsAfterClose = 0
            var spun = false
            val clock: () -> Instant = {
                reads++
                if (counting) {
                    readsAfterClose++
                    if (readsAfterClose > SPIN_BUDGET) {
                        spun = true
                        // Unwind the spinning loop so the run can finish and report. Cancellation, not an
                        // error: this is the fixture stopping a coroutine it owns, not a failure to raise.
                        throw CancellationException("drive loop spun past the budget after close")
                    }
                }
                epoch + testScheduler.currentTime.milliseconds
            }

            val alice = IceAgentDriver(IceRole.Controlling, Random(101), binder, backgroundScope, clock)
            val bob = IceAgentDriver(IceRole.Controlled, Random(102), binder, backgroundScope, clock)
            alice.start()
            bob.start()
            alice.gatherHost("10.0.0.1", 4000)
            bob.gatherHost("10.0.0.2", 5000)
            connect(alice, bob)
            connect(bob, alice)

            // Connected, so both agents certainly have a deadline armed — the precondition the bug needed.
            assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice ICE connected")
            assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob ICE connected")

            // Anti-vacuity, and it has to be asserted *here* rather than after the close. A correctly
            // closing loop reads the clock **zero** more times: it is parked in the `select`, the closed
            // channel resumes it, and it returns without going round again. So "reads happened after
            // close" is not evidence of anything — the evidence that this probe is wired to live loops is
            // that it moved while they were running.
            assertEquals(true, reads > 0, "the clock probe never fired — no drive loop was running to measure")

            counting = true
            alice.close()
            bob.close()

            // Let both loops run down. A loop that returns needs only the passes it takes to observe the
            // closed inbox; a loop that spins blows the budget here and unwinds.
            runCurrent()

            assertEquals(
                false,
                spun,
                "a closed driver's drive loop kept running: it read the clock more than $SPIN_BUDGET " +
                    "times after close() instead of returning",
            )
        }

    // Scripted signaling: hand [from]'s credentials + candidates to [to] (the trickle seam, direct).
    private fun connect(
        to: IceAgentDriver,
        from: IceAgentDriver,
    ) {
        to.setRemoteCredentials(from.localCredentials)
        from.localCandidates.forEach { to.addRemoteCandidate(it) }
    }

    private suspend fun IceAgentDriver.awaitConnected(): IceConnectionState =
        state.first {
            when (it) {
                is IceConnectionState.Connected, is IceConnectionState.Completed -> true
                is IceConnectionState.Failed -> error("expected a connection, but ICE failed: ${it.reason}")
                else -> false
            }
        }

    private companion object {
        // Comfortably above the handful of clock reads two correct shutdowns take, and far below the
        // unbounded number a spin produces — the gap between the two outcomes is orders of magnitude, so
        // the exact value is not load-bearing.
        const val SPIN_BUDGET = 1000
    }
}

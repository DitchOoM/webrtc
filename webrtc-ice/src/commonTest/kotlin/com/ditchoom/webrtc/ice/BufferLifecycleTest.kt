@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.CountingBufferFactory
import com.ditchoom.webrtc.ice.vnet.Vnets
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * Buffer-factory injectability + **steady-RSS / no-leak** validation (directive #6). The whole build
 * path and the vnet share **one caller-supplied [BufferFactory]** — a consumer can hand in a pool — and
 * the agent must not leak: on the idle/consent path it allocates in proportion to the messages it sends,
 * never per timer tick, so RSS stays flat over a long-lived connection. A per-tick allocation
 * regression (the class the sans-io timer machinery is prone to) shows up here as unbounded growth.
 */
@OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)
class BufferLifecycleTest {
    @Test
    fun the_injected_buffer_factory_is_used_for_the_agents_datagrams() =
        runTest {
            val factory = CountingBufferFactory(BufferFactory.Default)
            establish(this, factory)
            // If the caller's factory were ignored (a hardwired BufferFactory.Default somewhere on the
            // datagram path), it would see zero allocations. Every outbound check + vnet copy rides it.
            assertTrue(factory.allocations > 0, "the injected factory allocates the agents' datagrams (pool-injectable)")
        }

    @Test
    fun allocations_stay_bounded_across_consent_cycles_no_per_tick_leak() =
        runTest {
            val factory = CountingBufferFactory(BufferFactory.Default)
            // Fast consent, no expiry: keep a live connection and watch its allocation growth.
            val config = IceConfig(consentInterval = 1.seconds, consentTimeout = 1000.seconds)
            val pair = establish(this, factory, config)

            val afterConnect = factory.allocations
            // Run the connection idle-but-alive for CYCLES consent refreshes.
            delay((CYCLES + 1).seconds)
            val afterCycles = factory.allocations

            val growth = afterCycles - afterConnect
            // Consent is active (some allocation happened) but bounded per cycle — no per-timer-tick leak.
            assertTrue(growth > 0, "consent refreshes keep flowing (growth=$growth)")
            assertTrue(
                growth < CYCLES * PER_CYCLE_ALLOCATION_BOUND,
                "allocations grow with messages, not ticks (growth=$growth over $CYCLES cycles)",
            )
            // And the connection is still healthy — the bound isn't achieved by the session dying.
            assertTrue(
                pair.first.state.value
                    .let { it is IceConnectionState.Connected || it is IceConnectionState.Completed },
                "still connected",
            )
        }

    // Bring up a host-to-host connection over the flat vnet, both agents + the vnet sharing [factory].
    private suspend fun establish(
        scope: kotlinx.coroutines.test.TestScope,
        factory: BufferFactory,
        config: IceConfig = IceConfig(),
    ): Pair<IceDriver, IceDriver> {
        val vnet = Vnets.flat(bufferFactory = factory)
        val clock = IceDriver.clockOf { scope.testScheduler.currentTime }
        val alice = IceDriver(IceRole.Controlling, seed = 1, vnet = vnet, scope = scope.backgroundScope, clock = clock, config = config)
        val bob = IceDriver(IceRole.Controlled, seed = 2, vnet = vnet, scope = scope.backgroundScope, clock = clock, config = config)
        alice.start()
        bob.start()
        alice.bindHost("10.0.0.1", 4000)
        bob.bindHost("10.0.0.2", 5000)
        alice.connectTo(bob)
        bob.connectTo(alice)
        assertNotNull(withTimeoutOrNull(30.seconds) { alice.awaitConnected() }, "alice connects")
        assertNotNull(withTimeoutOrNull(30.seconds) { bob.awaitConnected() }, "bob connects")
        return alice to bob
    }

    private companion object {
        const val CYCLES = 10
        const val PER_CYCLE_ALLOCATION_BOUND = 40 // generous: a per-tick leak would blow far past this
    }
}

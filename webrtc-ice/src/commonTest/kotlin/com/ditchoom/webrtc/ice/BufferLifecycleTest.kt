@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.vnet.CountingBufferFactory
import com.ditchoom.webrtc.ice.vnet.LeakTrackingFactory
import com.ditchoom.webrtc.ice.vnet.NatProfile
import com.ditchoom.webrtc.ice.vnet.Vnets
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
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

    /**
     * The half the two tests above cannot see: whether anything the agent allocated ever **came back**.
     * Allocation-rate bounds say the agent allocates per message rather than per tick; they say nothing
     * about lifetime, and a session that allocates per message and frees none still grows without bound
     * for as long as it is up.
     */
    @Test
    fun buffers_come_back_when_the_session_that_allocated_them_is_done() =
        runTest {
            // The tracker goes to the AGENTS (IceConfig), not to the vnet: the vnet's copy-on-receive
            // allocates from the same seam, and pointing one at both would attribute the test harness's
            // buffers to production code and "fix" the wrong thing.
            val tracker = LeakTrackingFactory()
            val config = IceConfig(consentInterval = 1.seconds, consentTimeout = 1000.seconds, bufferFactory = tracker)
            val pair = establish(this, BufferFactory.Default, config)
            // Long enough for the steady-state allocator — consent checks, one per interval, forever —
            // to have run several times over.
            delay((CYCLES + 1).seconds)
            assertTrue(
                pair.first.state.value
                    .let { it is IceConnectionState.Connected || it is IceConnectionState.Completed },
                "still connected — the count below must be a live session's, not a dead one's",
            )
            tracker.assertNoLeaks("an ICE session over $CYCLES consent cycles")
        }

    /**
     * Gathering is the half a *session* fixture never reaches: [gatherServerReflexive] runs before the
     * agent's receive loop exists, so nothing above it can release what it built. Its Binding request is
     * one allocation per interface per generation — and an ICE restart re-gathers every one of them.
     */
    @Test
    fun a_server_reflexive_gather_returns_its_request_buffer() =
        runTest {
            val tracker = LeakTrackingFactory()
            val meetup = Vnets.meetup(backgroundScope, profileA = NatProfile.FullCone, profileB = NatProfile.FullCone)
            val socket = meetup.vnet.bind(meetup.aliceHost)

            val result = gatherServerReflexive(socket, meetup.stunAddress, Random(11), bufferFactory = tracker)

            assertIs<ServerReflexiveResult.Discovered>(result, "the vnet STUN server answered")
            tracker.assertNoLeaks("a server-reflexive gather that succeeded")
        }

    /**
     * The same, on the path that transmits the request *repeatedly*: a silent server costs
     * `timeout / retransmitInterval` sends of the one buffer, and the release has to happen exactly once
     * no matter how many of those there were. This is the case a `return` inside the loop would miss.
     */
    @Test
    fun a_server_reflexive_gather_returns_its_request_buffer_when_the_server_never_answers() =
        runTest {
            val tracker = LeakTrackingFactory()
            val vnet = Vnets.flat()
            val socket = vnet.bind(SocketAddress.ofLiteral("10.0.0.1", 4000))

            val result =
                gatherServerReflexive(
                    socket,
                    SocketAddress.ofLiteral("192.0.2.99", 3478), // nothing is bound here — every send is dropped
                    Random(12),
                    bufferFactory = tracker,
                )

            assertIs<ServerReflexiveResult.Unavailable.NoResponse>(result, "no server, no srflx")
            tracker.assertNoLeaks("a server-reflexive gather that timed out after several retransmissions")
        }

    @Test
    fun anti_vacuity_the_tracker_catches_a_buffer_that_is_never_released() =
        runTest {
            // Without this, a green assertNoLeaks above could mean "nothing leaks" or "the probe cannot
            // see a leak at all" — and the arithmetic metric this replaced was wrong in BOTH directions.
            val tracker = LeakTrackingFactory()
            val config = IceConfig(consentInterval = 1.seconds, consentTimeout = 1000.seconds, bufferFactory = tracker)
            establish(this, BufferFactory.Default, config)
            tracker.allocate(64, ByteOrder.BIG_ENDIAN) // deliberately never released
            assertFailsWith<AssertionError>("a buffer that never came back must be reported") {
                tracker.assertNoLeaks("a session with one deliberately leaked buffer")
            }
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

@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.deterministic
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The whole ICE agent over sockets [udpDatagramBinder] bound: two production [IceAgentDriver]s gather
 * **ephemeral** host candidates on real loopback and complete connectivity checks against each other.
 *
 * Its cross-platform sibling is `UdpDatagramBinderTest` in `socketTest`, which proves the seam itself
 * (a datagram out, the same datagram back) on the JVM *and* on Kotlin/Native. This one goes further —
 * gathering, pairing, checks, nomination — and stays JVM-only for a reason that is worth writing down:
 * under `runBlocking` on Kotlin/Native the same scenario does not converge, while the identical stack
 * establishes fine on real sockets inside the L2 container harness. That is a property of driving this
 * many cooperating loops from a single-threaded `runBlocking`, not of the binder, so pinning it here
 * keeps a real proof green rather than parking an unexplained red one in the native lane.
 *
 * Real sockets mean real time and a real dispatcher, so the watchdog is a `withTimeout` on observable
 * state, never a wall-clock budget (directive 4).
 */
class UdpDatagramBinderIceTest {
    @Test
    fun ice_completes_over_real_loopback_sockets_bound_by_the_helper() =
        runBlocking {
            withTimeout(30.seconds) {
                val scope = CoroutineScope(coroutineContext + Job())
                val clock: () -> Instant = { Clock.System.now() }
                val binder = udpDatagramBinder()

                // The SEND side needs a native-memory factory on Kotlin/Native and `IceConfig`'s default
                // is not one: io_uring `sendmsg` refuses a GC-heap buffer outright ("send requires a
                // native-memory buffer"). Injected here exactly as the interop peer injects it, so this
                // test measures the binder rather than that unrelated default. The default itself is a
                // real trap for a native consumer, and a separate question from this fixture.
                val net = BufferFactory.deterministic()
                val config = IceConfig(bufferFactory = net)
                val alice = IceAgentDriver(IceRole.Controlling, Random(501), binder, scope, clock, config)
                val bob = IceAgentDriver(IceRole.Controlled, Random(502), binder, scope, clock, config)
                try {
                    alice.start()
                    bob.start()

                    val aliceHost = alice.gatherHost("127.0.0.1", 0)
                    val bobHost = bob.gatherHost("127.0.0.1", 0)
                    // The kernel assigned these; if the driver had published what it *asked* for, both
                    // would read 0 and neither peer would have anywhere to send.
                    assertNotEquals(0.toUShort(), aliceHost.address.port, "alice's candidate names its real port")
                    assertNotEquals(0.toUShort(), bobHost.address.port, "bob's candidate names its real port")

                    connect(alice, bob)
                    connect(bob, alice)
                    alice.awaitConnected()
                    bob.awaitConnected()

                    val nominated = assertIs<IcePath.Nominated>(alice.path.value, "alice nominated a pair")
                    assertEquals(bobHost.address, nominated.pair.remote.address, "…bob's signalled host socket")
                } finally {
                    alice.close()
                    bob.close()
                    scope.cancel()
                }
            }
        }

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
}

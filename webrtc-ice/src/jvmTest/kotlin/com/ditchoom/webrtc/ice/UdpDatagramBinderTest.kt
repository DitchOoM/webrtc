@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.ice

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
 * [udpDatagramBinder] on a **real kernel**: two production [IceAgentDriver]s bind loopback sockets through
 * the shipped helper, gather **ephemeral** host candidates, and complete ICE against each other.
 *
 * This is what makes the helper a claim rather than a convenience wrapper. Every other ICE fixture runs
 * over the in-memory vnet, so it proves the driver; only this proves the one line the driver is handed in
 * production — and it proves it in the shape a real gathering policy uses, `bind(ip, 0)`, where the OS
 * (not the caller) chooses the port and the candidate has to say which one it got.
 *
 * JVM-only and **not** virtual-time: real sockets need a real dispatcher and real time, so the watchdog is
 * a `withTimeout` rather than a wall-clock budget (directive 4). socket-udp ships no wasm/browser actual,
 * and [udpDatagramBinder] does not exist there to test.
 */
class UdpDatagramBinderTest {
    @Test
    fun ice_completes_over_real_loopback_sockets_bound_by_the_helper() =
        runBlocking {
            withTimeout(30.seconds) {
                val scope = CoroutineScope(coroutineContext + Job())
                val clock: () -> Instant = { Clock.System.now() }
                val binder = udpDatagramBinder()
                val alice = IceAgentDriver(IceRole.Controlling, Random(501), binder, scope, clock)
                val bob = IceAgentDriver(IceRole.Controlled, Random(502), binder, scope, clock)
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

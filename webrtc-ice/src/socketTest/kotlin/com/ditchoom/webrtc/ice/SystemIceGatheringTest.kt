@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.deterministic
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * [systemIceGathering] against a **real kernel, on more than one platform** — the production gathering
 * policy issue #136 added, exercised through nothing but its public surface.
 *
 * That last part is the point. Before this, every native test either ran on the vnet or injected its own
 * gathering, binder and buffer factory, so the defaults were exercised everywhere except the one place
 * they are used — which is exactly how #123 (a receive-side factory override that killed srflx and relay
 * gathering on every native lane) and #125 (a send-side default with no native address) both shipped.
 * A test that assembles its own gathering cannot catch either.
 *
 * Real sockets, so real time and a real dispatcher: the watchdog is a `withTimeout` on observable state,
 * never a wall-clock budget (directive 4).
 */
class SystemIceGatheringTest {
    @Test
    fun gathers_host_candidates_on_this_host_s_own_interfaces() =
        runBlocking {
            withTimeout(WATCHDOG) {
                withDriver { driver ->
                    systemIceGathering(binder = udpDatagramBinder(), includeLoopback = true).gather(driver)

                    val candidates = driver.localCandidates
                    assertTrue(candidates.isNotEmpty(), "no ICE servers configured, but a host has host candidates")
                    assertTrue(
                        candidates.all { it is IceCandidate.Host },
                        "with no ICE servers there is nothing to reflect or relay: ${candidates.map { it.type }}",
                    )
                    // The policy always binds port 0, and `gatherHost` reads back the port the socket
                    // actually received. A platform that mis-reports it publishes an unreachable candidate.
                    assertTrue(
                        candidates.all { it.address.port != PORT_ZERO },
                        "every candidate names the ephemeral port it received, not the 0 it asked for",
                    )
                    assertTrue(
                        candidates.any {
                            it.address.ip
                                .toString()
                                .isLoopbackText()
                        },
                        "includeLoopback = true must actually include it: ${candidates.map { it.address.ip }}",
                    )
                    assertTrue(
                        candidates.none {
                            it.address.ip
                                .toString()
                                .lowercase()
                                .startsWith("fe80")
                        },
                        "IPv6 link-local is never gatherable — it is meaningless without its scope id",
                    )
                }
            }
        }

    /**
     * The anti-vacuity half of the test above: the loopback filter is the default, so if it did nothing
     * the assertion above would pass for the wrong reason on every host.
     */
    @Test
    fun skips_loopback_unless_asked_for_it() =
        runBlocking {
            withTimeout(WATCHDOG) {
                withDriver { driver ->
                    systemIceGathering(binder = udpDatagramBinder()).gather(driver)

                    assertTrue(
                        driver.localCandidates.none {
                            it.address.ip
                                .toString()
                                .isLoopbackText()
                        },
                        "loopback is off by default: ${driver.localCandidates.map { it.address.ip }}",
                    )
                }
            }
        }

    /**
     * Every server we decline is declined **by reason**. The failure this replaces is silent: a consumer
     * configures `turns:` (or forgets the credential), gathers no relay candidate, and has nothing to
     * distinguish that from a TURN server that never answered.
     */
    @Test
    fun refuses_unusable_servers_by_name_rather_than_dropping_them() =
        runBlocking {
            withTimeout(WATCHDOG) {
                withDriver { driver ->
                    val notices = mutableListOf<IceGatheringNotice>()
                    systemIceGathering(
                        binder = udpDatagramBinder(),
                        iceServers =
                            listOf(
                                IceServer("turns:turn.example.org", "user", "credential"),
                                IceServer("turn:turn.example.org?transport=tcp", "user", "credential"),
                                IceServer("turn:turn.example.org"),
                            ),
                        includeLoopback = true,
                        onNotice = { notices += it },
                    ).gather(driver)

                    assertEquals(
                        listOf(
                            IceGatheringNotice.ServerUrlRejected(
                                "turns:turn.example.org",
                                IceServerUrlRejection.TlsTransportUnsupported,
                            ),
                            IceGatheringNotice.ServerUrlRejected(
                                "turn:turn.example.org?transport=tcp",
                                IceServerUrlRejection.TcpTransportUnsupported,
                            ),
                            IceGatheringNotice.ServerCredentialMissing("turn:turn.example.org"),
                        ),
                        notices,
                        "each refusal names the URL and the reason",
                    )
                    assertTrue(
                        driver.localCandidates.isNotEmpty(),
                        "a refused server costs its own candidates, never the host candidates",
                    )
                }
            }
        }

    /**
     * A STUN name that does not resolve is a configuration fact, not a crash. `.invalid` is reserved by
     * RFC 6761 §6.4 precisely so it never resolves, which is what makes this deterministic without a
     * network fixture.
     */
    @Test
    fun an_unresolvable_server_costs_its_candidates_not_the_session() =
        runBlocking {
            withTimeout(WATCHDOG) {
                withDriver { driver ->
                    val notices = mutableListOf<IceGatheringNotice>()
                    systemIceGathering(
                        binder = udpDatagramBinder(),
                        iceServers = listOf(IceServer("stun:nothing.here.invalid:3478")),
                        includeLoopback = true,
                        onNotice = { notices += it },
                    ).gather(driver)

                    assertEquals(
                        listOf<IceGatheringNotice>(IceGatheringNotice.ServerUnresolved("stun:nothing.here.invalid:3478")),
                        notices,
                    )
                    assertTrue(driver.localCandidates.isNotEmpty(), "host gathering survived the dead STUN server")
                }
            }
        }

    private suspend fun withDriver(block: suspend (IceAgentDriver) -> Unit) {
        // A scope of its own, cancelled in `finally`: the driver's drive loop and one forwarder per bound
        // socket outlive `gather()`, and leaving them on the caller's scope would hang `runBlocking`.
        val scope = CoroutineScope(Job())
        try {
            val driver =
                IceAgentDriver(
                    role = IceRole.Controlling,
                    random = Random(SEED),
                    binder = udpDatagramBinder(),
                    scope = scope,
                    clock = { Clock.System.now() },
                    config = IceConfig(bufferFactory = BufferFactory.deterministic()),
                )
            driver.start()
            block(driver)
        } finally {
            scope.cancel()
        }
    }

    private fun String.isLoopbackText(): Boolean = this == "::1" || startsWith("127.")

    private companion object {
        val WATCHDOG = 30.seconds
        const val SEED = 136L
        val PORT_ZERO: UShort = 0u
    }
}

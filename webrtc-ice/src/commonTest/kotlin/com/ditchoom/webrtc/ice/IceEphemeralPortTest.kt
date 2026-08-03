@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.vnet.Vnets
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Gathering on an **ephemeral port** — `bind(ip, 0)`, the way a production policy has to bind.
 *
 * A pinned port cannot survive an ICE restart: the outgoing generation keeps its sockets until the new
 * one nominates (that is the continuity guarantee), so re-gathering onto the same port asks the OS to
 * re-bind an address still in use. Real stacks therefore take whatever port the kernel gives them — and
 * until this fixture existed, [IceAgentDriver.gatherHost] built the candidate from the address it *asked*
 * for, so `bind(ip, 0)` advertised `ip:0`: a place the peer cannot send to, on a candidate that looks
 * perfectly well-formed on the wire.
 *
 * The load-bearing assertion is the last one — that the nominated pair rides the **signalled host**
 * candidate. A `:0` candidate does not merely lower the odds: the peer has no reachable address to check,
 * so the only way through is peer-reflexive discovery from whichever side happened to punch first, which
 * is exactly the silent degradation this catches.
 */
class IceEphemeralPortTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun the_vnet_hands_out_a_real_port_for_a_zero_bind() =
        runTest {
            // Anti-vacuity: everything below is only a test if the seam models ephemeral binding at all.
            // A vnet that bound port 0 literally would let the driver's own bug through untouched.
            val vnet = Vnets.flat()
            val channel = vnet.bind(SocketAddress.ofLiteral("10.0.0.1", 0))
            assertNotEquals(0, channel.localAddress.port, "a zero bind must be assigned a real port")
            assertEquals("10.0.0.1", channel.localAddress.host, "the ephemeral bind stays on the requested address")

            val second = vnet.bind(SocketAddress.ofLiteral("10.0.0.1", 0))
            assertNotEquals(
                channel.localAddress.port,
                second.localAddress.port,
                "two ephemeral binds on one address must not collide",
            )
        }

    @Test
    fun ephemeral_gathering_advertises_the_port_the_socket_actually_got() =
        runTest {
            val vnet = Vnets.flat()
            val binder = DatagramBinder { vnet.bind(it) }
            val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
            val alice = IceAgentDriver(IceRole.Controlling, Random(401), binder, backgroundScope, clock)
            val bob = IceAgentDriver(IceRole.Controlled, Random(402), binder, backgroundScope, clock)
            alice.start()
            bob.start()

            // Neither side pins a port — the production shape.
            val aliceHost = alice.gatherHost("10.0.0.1", 0)
            val bobHost = bob.gatherHost("10.0.0.2", 0)

            assertNotEquals(0.toUShort(), aliceHost.address.port, "alice's host candidate names a real port")
            assertNotEquals(0.toUShort(), bobHost.address.port, "bob's host candidate names a real port")
            assertNotEquals(
                aliceHost.address.port,
                bobHost.address.port,
                "two ephemeral gathers must not claim the same port",
            )

            connect(alice, bob)
            connect(bob, alice)
            assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice ICE connected")
            assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob ICE connected")

            // The pair that won is the one we SIGNALLED, not one rediscovered peer-reflexively from an
            // inbound check — which is the only way an `ip:0` advertisement could ever have converged.
            val nominated = assertIs<IcePath.Nominated>(alice.path.value, "alice's path is a nominated pair")
            assertEquals(
                CandidateType.Host,
                nominated.pair.remote.type,
                "the nominated remote is bob's signalled host candidate, not a peer-reflexive rediscovery",
            )
            assertEquals(bobHost.address, nominated.pair.remote.address, "…at the port bob actually bound")
            assertTrue(
                nominated.pair.local.address == aliceHost.address,
                "…checked from alice's own ephemeral socket, got ${nominated.pair.local.address}",
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
}

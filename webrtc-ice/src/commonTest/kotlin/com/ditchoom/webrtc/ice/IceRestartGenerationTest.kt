@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.ice.vnet.CountingBufferFactory
import com.ditchoom.webrtc.ice.vnet.Vnet
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The **ICE generation** fixtures for an RFC 8445 §9 restart, against the *production*
 * [IceAgentDriver] (not the test [IceDriver]) so socket retirement — which only the production driver
 * owns — is actually exercised.
 *
 * Every claim here used to be either absent or true by accident. Continuity across a restart worked
 * only because the driver's selected-pair field was never cleared; rollback left the agent advertising
 * credentials no peer had seen; the peer's consent checks went unanswered for the whole restart window.
 * These pin all four down: continuity, retirement ordering, rollback, and role preservation.
 */
class IceRestartGenerationTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun data_keeps_flowing_on_the_retained_pair_while_the_restart_is_in_flight() =
        runTest {
            val fixture = connectedPeers(seed = 401)
            val before = assertIs<IcePath.Nominated>(fixture.alice.path.value).pair

            // Restart, but do NOT re-gather yet: this is the window RFC 8445 §9 is about.
            fixture.alice.restartAndAwait()

            val restarting = assertIs<IcePath.Restarting>(fixture.alice.path.value, "the restart window is a named state")
            assertEquals(before, restarting.previous, "app data continues on the pair the old generation nominated")
            assertTrue(fixture.vnet.isBound(vnetAddress(ALICE_IP, ALICE_PORT)), "the outgoing generation's socket stays bound")

            // And it is not merely named — it carries.
            fixture.alice.appDataTransport().send(textBuffer("still here"))
            assertEquals(
                "still here",
                withTimeoutOrNull(timeout) {
                    fixture.bob
                        .appDataTransport()
                        .receive()
                        ?.text()
                },
                "the peer receives application data sent during the restart window",
            )
        }

    @Test
    fun the_outgoing_generations_socket_is_retired_only_once_the_new_pair_nominates() =
        runTest {
            val fixture = connectedPeers(seed = 402)
            val oldAlice = vnetAddress(ALICE_IP, ALICE_PORT)
            fixture.alice.restartAndAwait()
            fixture.bob.restartAndAwait()
            assertTrue(fixture.vnet.isBound(oldAlice), "still bound mid-restart — closing here would tear down live data")

            // A real interface change lands on a new base; the vnet requires the address to be free, which
            // is exactly what makes "did the old socket get released?" an observable rather than a guess.
            fixture.alice.gatherHost(ALICE_IP, ALICE_PORT + 1)
            fixture.bob.gatherHost(BOB_IP, BOB_PORT + 1)
            connect(fixture.alice, fixture.bob)
            connect(fixture.bob, fixture.alice)
            assertNotNull(withTimeoutOrNull(timeout) { fixture.alice.awaitConnected() }, "alice reconverges")
            assertNotNull(withTimeoutOrNull(timeout) { fixture.bob.awaitConnected() }, "bob reconverges")

            val after = assertIs<IcePath.Nominated>(fixture.alice.path.value, "the new generation nominated")
            assertEquals(
                ALICE_PORT + 1,
                after.pair.local.address.port
                    .toInt(),
                "the path moved to the new base",
            )
            assertFalse(fixture.vnet.isBound(oldAlice), "and only now is the outgoing generation's socket retired")
            assertTrue(fixture.vnet.isBound(vnetAddress(ALICE_IP, ALICE_PORT + 1)), "the new base stays bound")
        }

    @Test
    fun restart_and_await_returns_the_new_generations_credentials() =
        runTest {
            val fixture = connectedPeers(seed = 403)
            val before = fixture.alice.localCredentials

            val applied = fixture.alice.restartAndAwait()

            assertNotEquals(before.ufrag, applied.ufrag, "a restart regenerates the ufrag (RFC 8445 §9)")
            assertNotEquals(before.password, applied.password, "and the password")
            assertEquals(
                applied,
                fixture.alice.localCredentials,
                "the returned credentials are the ones the agent now honours — an offer built from them cannot be stale",
            )
        }

    @Test
    fun a_rolled_back_restart_restores_the_previous_generation() =
        runTest {
            val fixture = connectedPeers(seed = 404)
            val before = fixture.alice.localCredentials
            val pairBefore = assertIs<IcePath.Nominated>(fixture.alice.path.value).pair

            val restarted = fixture.alice.restartAndAwait()
            assertNotEquals(before, restarted, "the restart generation is live")
            fixture.alice.rollbackRestart()

            assertEquals(before, fixture.alice.localCredentials, "rollback restores credentials the peer has actually seen")
            val path = assertIs<IcePath.Nominated>(fixture.alice.path.value, "and the pair is nominated again, not merely retained")
            assertEquals(pairBefore, path.pair)
            assertEquals(IceConnectionState.Completed(pairBefore), fixture.alice.state.value, "the restored generation's state comes back")

            // The restored generation is live, not a museum piece: it still carries data and still runs
            // consent, so the rolled-back session is genuinely usable rather than merely well-labelled.
            fixture.alice.appDataTransport().send(textBuffer("rolled back"))
            assertEquals(
                "rolled back",
                withTimeoutOrNull(timeout) {
                    fixture.bob
                        .appDataTransport()
                        .receive()
                        ?.text()
                },
            )
            advanceThroughConsent()
            assertEquals(
                IceConnectionState.Completed(pairBefore),
                fixture.alice.state.value,
                "consent keeps refreshing after a rollback — the frozen window did not count against it",
            )
        }

    @Test
    fun the_retained_generation_answers_the_peers_consent_checks() =
        runTest {
            // Only alice restarts. Bob still holds alice's OLD credentials — his answer is, realistically,
            // still in signaling — and keeps refreshing consent (RFC 7675) on the pair alice is deliberately
            // still carrying data over. If alice ignored those checks, bob would revoke consent and tear
            // down exactly the session RFC 8445 §9 promises to keep alive.
            val fixture = connectedPeers(seed = 405)
            fixture.alice.restartAndAwait()

            advanceThroughConsent()

            assertIs<IcePath.Restarting>(fixture.alice.path.value, "alice is still mid-restart")
            assertIs<IceConnectionState.Completed>(fixture.bob.state.value, "bob's consent survived the whole restart window")
        }

    @Test
    fun a_restart_does_not_redetermine_roles() =
        runTest {
            // RFC 8445 §9 → §6.1.1: "agents MUST NOT redetermine the roles as part of an ICE restart."
            val fixture = connectedPeers(seed = 406)
            val aliceRole = fixture.alice.agent.role
            val bobRole = fixture.bob.agent.role
            assertNotEquals(aliceRole, bobRole, "the pre-restart roles are opposite")

            fixture.alice.restartAndAwait()
            fixture.bob.restartAndAwait()
            fixture.alice.gatherHost(ALICE_IP, ALICE_PORT + 1)
            fixture.bob.gatherHost(BOB_IP, BOB_PORT + 1)
            connect(fixture.alice, fixture.bob)
            connect(fixture.bob, fixture.alice)
            assertNotNull(withTimeoutOrNull(timeout) { fixture.alice.awaitConnected() }, "alice reconverges")
            assertNotNull(withTimeoutOrNull(timeout) { fixture.bob.awaitConnected() }, "bob reconverges")

            assertEquals(aliceRole, fixture.alice.agent.role, "alice keeps her role across the restart")
            assertEquals(bobRole, fixture.bob.agent.role, "bob keeps his")
        }

    @Test
    fun a_restart_on_top_of_an_in_flight_restart_keeps_the_original_retained_pair() =
        runTest {
            // The second restart's generation never nominated, so it owns nothing to preserve. Letting it
            // become the retained one would drop the live pair — and with it, the data riding it.
            val fixture = connectedPeers(seed = 407)
            val original = assertIs<IcePath.Nominated>(fixture.alice.path.value).pair

            fixture.alice.restartAndAwait()
            fixture.alice.restartAndAwait()

            assertEquals(original, assertIs<IcePath.Restarting>(fixture.alice.path.value).previous)
            assertTrue(fixture.vnet.isBound(vnetAddress(ALICE_IP, ALICE_PORT)), "the original socket is still the one held open")
            fixture.alice.appDataTransport().send(textBuffer("twice over"))
            assertEquals(
                "twice over",
                withTimeoutOrNull(timeout) {
                    fixture.bob
                        .appDataTransport()
                        .receive()
                        ?.text()
                },
            )
        }

    // ---- fixture plumbing ---------------------------------------------------------------------------

    private class Peers(
        val vnet: Vnet,
        val alice: IceAgentDriver,
        val bob: IceAgentDriver,
        val buffers: CountingBufferFactory,
    )

    private suspend fun kotlinx.coroutines.test.TestScope.connectedPeers(seed: Long): Peers {
        val buffers = CountingBufferFactory(BufferFactory.managed())
        val vnet = Vnets.flat(buffers)
        val binder = DatagramBinder { vnet.bind(it) }
        val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
        val alice = IceAgentDriver(IceRole.Controlling, Random(seed), binder, backgroundScope, clock)
        val bob = IceAgentDriver(IceRole.Controlled, Random(seed + 1), binder, backgroundScope, clock)
        alice.start()
        bob.start()
        alice.gatherHost(ALICE_IP, ALICE_PORT)
        bob.gatherHost(BOB_IP, BOB_PORT)
        connect(alice, bob)
        connect(bob, alice)
        assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice ICE connected")
        assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob ICE connected")
        return Peers(vnet, alice, bob, buffers)
    }

    /**
     * Advance past a full RFC 7675 consent timeout. Observable state is asserted afterwards; this only
     * moves virtual time far enough that a *missing* consent response would have expired the pair — a
     * schedule, not a wall-clock budget (directive #4).
     */
    private suspend fun kotlinx.coroutines.test.TestScope.advanceThroughConsent() {
        testScheduler.advanceTimeBy(IceConfig().consentTimeout + IceConfig().consentInterval)
        testScheduler.runCurrent()
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

    private fun textBuffer(s: String): ReadBuffer {
        val bytes = s.encodeToByteArray()
        val buf = BufferFactory.managed().allocate(maxOf(1, bytes.size), ByteOrder.BIG_ENDIAN)
        for (b in bytes) buf.writeByte(b)
        buf.resetForRead()
        buf.setLimit(bytes.size)
        return buf
    }

    private fun ReadBuffer.text(): String {
        val out = StringBuilder()
        for (i in position() until limit()) out.append((get(i).toInt() and 0xFF).toChar())
        return out.toString()
    }

    private companion object {
        const val ALICE_IP = "10.0.0.1"
        const val BOB_IP = "10.0.0.2"
        const val ALICE_PORT = 4000
        const val BOB_PORT = 5000
    }
}

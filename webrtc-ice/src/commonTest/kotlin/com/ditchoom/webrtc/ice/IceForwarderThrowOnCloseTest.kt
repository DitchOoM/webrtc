@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The forwarder must survive a [DatagramChannel] that **throws** from an in-flight `receive()` when its
 * socket is closed underneath it, rather than returning [DatagramReadResult.Closed].
 *
 * This is not hypothetical and not a vnet quirk. socket-udp's `NioDatagramChannel.receive()` reaches into
 * its selector before re-checking its own closed flag, so a `close()` landing between the select returning
 * and that call raises `ClosedSelectorException`. Nothing in this stack used to close a socket while a read
 * was in flight — until ICE restart, which retires the outgoing generation's sockets by design. The escaped
 * throw did not merely stop that forwarder: `forward` launches into the **consumer's** scope, so it took the
 * whole peer process down mid-restart. It is exactly the failure the `jvm-restart` interop lane hit.
 *
 * The invariant asserted here is the one that matters at the seam: a throwing socket ends *that base's*
 * forwarding and nothing else. The driver stays usable, its other sockets keep delivering, and the scope
 * that owns it is still alive — an ICE agent whose peer's socket misbehaves must reach a typed terminal on
 * its own schedule, never die on someone else's exception.
 */
class IceForwarderThrowOnCloseTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun a_socket_that_throws_on_close_ends_its_own_forwarder_and_nothing_else() =
        runTest {
            val vnet = Vnets.flat()
            val hostile = ThrowOnCloseChannel(vnet.bind(vnetAddress("10.0.0.1", 4000)))
            // The doomed base is served by the hostile channel; every other bind is an ordinary vnet socket.
            val binder =
                DatagramBinder { address ->
                    if (address == vnetAddress("10.0.0.1", 4000)) hostile else vnet.bind(address)
                }
            val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
            val alice = IceAgentDriver(IceRole.Controlling, Random(901), binder, backgroundScope, clock)
            val bob = IceAgentDriver(IceRole.Controlled, Random(902), DatagramBinder { vnet.bind(it) }, backgroundScope, clock)
            alice.start()
            bob.start()
            val doomed = alice.gatherHost("10.0.0.1", 4000)
            alice.gatherHost("10.0.0.1", 4001)
            bob.gatherHost("10.0.0.2", 5000)

            // Pull the socket out from under the in-flight read. Before the guard this throw escaped the
            // launched forwarder and cancelled backgroundScope — taking `bob`, the vnet and the test with it.
            alice.drop(doomed)
            // Prove the throw actually happened rather than inferring it from `closed`, which `drop` sets
            // trivially — an assertion that cannot fail would leave the whole fixture proving nothing.
            assertNotNull(
                withTimeoutOrNull(timeout) { hostile.threw.await() },
                "the hostile socket raised from an in-flight receive, which is the condition under test",
            )

            connect(alice, bob)
            connect(bob, alice)

            assertNotNull(
                withTimeoutOrNull(timeout) { alice.awaitConnected() },
                "the surviving base still converges — one socket's throw is not the agent's problem",
            )
            assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "and the peer is untouched")
            assertTrue(backgroundScope.isActive, "the consumer's scope survived: the throw never escaped the forwarder")
        }

    @Test
    fun a_turn_allocation_whose_socket_throws_on_close_does_not_take_the_scope_down() =
        runTest {
            // The second instance of the same defect, and the one the jvm-restart interop lane actually died
            // on. TurnAllocation.startLoop() reads `underlying` in a coroutine launched into the consumer's
            // scope, and TurnAllocation.close() closes `underlying` out from under it — so retiring the
            // outgoing generation's relay socket on nomination fires the throw by design, not by accident.
            val meetup = Vnets.meetup(backgroundScope)
            val hostile = ThrowOnCloseChannel(meetup.vnet.bind(vnetAddress("10.0.0.2", 6000)))
            val allocation =
                TurnAllocation(
                    hostile,
                    meetup.turnAddress,
                    Vnets.TURN_USERNAME,
                    Vnets.TURN_PASSWORD,
                    Random(903),
                    backgroundScope,
                )
            assertNotNull(withTimeoutOrNull(timeout) { allocation.allocate() }, "the relay allocated over the vnet TURN server")

            allocation.close() // closes `underlying` under the live demux read — the retirement path

            assertNotNull(
                withTimeoutOrNull(timeout) { hostile.threw.await() },
                "the allocation's socket raised from its in-flight receive",
            )
            assertTrue(backgroundScope.isActive, "the consumer's scope survived the TURN demux loop's throw")
        }

    /**
     * A [DatagramChannel] that raises from an in-flight [receive] once closed, the way a selector-backed
     * real-UDP actual does — instead of politely returning [DatagramReadResult.Closed].
     */
    private class ThrowOnCloseChannel(
        private val delegate: DatagramChannel,
    ) : DatagramChannel {
        var closed: Boolean = false
            private set

        /** Completes the first time [receive] actually raises, so the fixture can prove it did. */
        val threw: CompletableDeferred<Unit> = CompletableDeferred()

        override val localAddress: SocketAddress? get() = delegate.localAddress
        override val isOpen: Boolean get() = !closed && delegate.isOpen
        override val maxWritableSize: Int get() = delegate.maxWritableSize
        override val capabilities: DatagramCapabilities get() = delegate.capabilities

        override suspend fun receive(): DatagramReadResult {
            val result = delegate.receive()
            if (closed) {
                threw.complete(Unit)
                throw IllegalStateException("selector closed under an in-flight receive")
            }
            return result
        }

        override suspend fun send(
            payload: ReadBuffer,
            to: SocketAddress?,
            options: DatagramSendOptions,
        ) = delegate.send(payload, to, options)

        override fun close() {
            closed = true
            delegate.close()
        }
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

@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.vnet.LeakTrackingFactory
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The send-side sibling of [IceForwarderThrowOnCloseTest]: an [AddressedDatagramChannel] that **raises
 * from `send`** must cost the datagram and nothing more.
 *
 * Not hypothetical. socket-udp's `send` used to return normally having sent nothing on four of five
 * backends; DitchOoM/socket#278 makes every backend raise a typed `DatagramSendException` instead, and a
 * raise is also what the JVM path already does today when the channel is closed under it. The webrtc side
 * of that change is #143.
 *
 * Two distinct harms are pinned here, and the second is the one worth the fixture:
 *
 * 1. **The buffer leaked.** `apply()` released only after a successful `send`, so a raise skipped the
 *    release — against the ownership invariant #142 established.
 * 2. **The rest of the output batch was abandoned.** `apply()` pumps a `List<IceOutput>`, so an escaped
 *    raise dropped every remaining output, `ConnectionStateChanged` and `PathChanged` included. The
 *    driver's observable state then silently stopped matching the core state machine — strictly worse
 *    than the lost datagram that caused it, and invisible.
 */
class IceSendThrowTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun a_raising_send_costs_the_datagram_and_nothing_else() =
        runTest {
            val vnet = Vnets.flat()
            val tracker = LeakTrackingFactory()
            // Raises on the first send only, then delegates. That is the sharpest shape for the batch
            // defect: exactly one transmit fails, so anything still broken afterwards is the abandonment
            // rather than a peer that simply never heard from us.
            val flaky = RaiseOnceOnSendChannel(vnet.bind(vnetAddress("10.0.0.1", 4000)))
            val binder =
                DatagramBinder { address ->
                    if (address == vnetAddress("10.0.0.1", 4000)) flaky else vnet.bind(address)
                }
            val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
            val alice =
                IceAgentDriver(
                    IceRole.Controlling,
                    Random(911),
                    binder,
                    backgroundScope,
                    clock,
                    IceConfig(bufferFactory = tracker),
                )
            val bob = IceAgentDriver(IceRole.Controlled, Random(912), DatagramBinder { vnet.bind(it) }, backgroundScope, clock)
            alice.start()
            bob.start()
            alice.gatherHost("10.0.0.1", 4000)
            bob.gatherHost("10.0.0.2", 5000)

            connect(alice, bob)
            connect(bob, alice)

            // (2) The batch survived: state still reaches the observers. Before the fix the raise escaped
            // `apply()`, and every ConnectionStateChanged behind it in that batch was dropped on the floor.
            assertNotNull(
                withTimeoutOrNull(timeout) { alice.awaitConnected() },
                "one raising send must not stop the agent converging — ICE retransmits lost checks by design",
            )
            assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "and the peer is untouched")

            // Prove the raise actually happened. Without this the fixture would pass just as well against
            // a channel that never misbehaved, and would be asserting nothing at all.
            assertEquals(1, flaky.raised, "the channel must have raised exactly once — the condition under test")
            assertTrue(backgroundScope.isActive, "the consumer's scope survived: the raise never escaped the drive loop")

            // (1) And the datagram that failed to send still came back to the pool.
            tracker.assertNoLeaks("an ICE session whose first send raised")
        }

    @Test
    fun the_failed_transmit_is_reported_rather_than_swallowed() =
        runTest {
            // The other half of "non-fatal": a caught failure that told nobody would leave a socket
            // refusing every send indistinguishable from a peer that stopped answering — the session would
            // end at NoCandidatePairs/ConsentExpired, naming the symptom while the cause was local.
            val vnet = Vnets.flat()
            val flaky = RaiseOnceOnSendChannel(vnet.bind(vnetAddress("10.0.0.1", 4000)))
            val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
            val alice =
                IceAgentDriver(
                    IceRole.Controlling,
                    Random(921),
                    DatagramBinder { address ->
                        if (address == vnetAddress("10.0.0.1", 4000)) flaky else vnet.bind(address)
                    },
                    backgroundScope,
                    clock,
                )
            val bob = IceAgentDriver(IceRole.Controlled, Random(922), DatagramBinder { vnet.bind(it) }, backgroundScope, clock)
            alice.start()
            bob.start()
            alice.gatherHost("10.0.0.1", 4000)
            bob.gatherHost("10.0.0.2", 5000)
            connect(alice, bob)
            connect(bob, alice)

            val failure = withTimeoutOrNull(timeout) { alice.transmitFailed.first() }
            assertNotNull(failure, "the refused transmit must surface on the diagnostics flow")
            assertEquals(
                RAISE_MESSAGE,
                failure.cause.message,
                "the diagnostic carries the socket's own cause through intact, not a re-wrapped stand-in",
            )
        }

    /**
     * A channel that raises from [send] exactly once, the way a real-UDP actual does when the socket is
     * closed under it or the payload exceeds what the interface will carry.
     */
    private class RaiseOnceOnSendChannel(
        private val delegate: AddressedDatagramChannel,
    ) : AddressedDatagramChannel {
        var raised: Int = 0
            private set

        override val localAddress: SocketAddress get() = delegate.localAddress
        override val isOpen: Boolean get() = delegate.isOpen
        override val maxWritableSize: Int get() = delegate.maxWritableSize
        override val capabilities: DatagramCapabilities get() = delegate.capabilities

        override suspend fun receive(): DatagramReadResult = delegate.receive()

        override suspend fun send(
            payload: ReadBuffer,
            to: SocketAddress,
            options: DatagramSendOptions,
        ) {
            if (raised == 0) {
                raised++
                throw IllegalStateException(RAISE_MESSAGE)
            }
            delegate.send(payload, to, options)
        }

        override fun close() = delegate.close()
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
        const val RAISE_MESSAGE = "socket refused the datagram"
    }
}

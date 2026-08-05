@file:OptIn(ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.Datagram
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime

/**
 * What the typed send failure actually buys, once socket-udp classifies one (DitchOoM/socket#278).
 *
 * The classification itself happens in `socketMain` ([TypedSendChannel]) because socket's
 * `DatagramSendError` cannot be named from here (ARCHITECTURE §11.6). What *this* pins is the half that
 * lives in `commonMain` and is therefore testable on every platform: that a reason crossing the boundary
 * as an [IceTransmitException] changes control flow, and that only the one reason that should.
 */
class IceTransmitReasonTest {
    private val stunServer = SocketAddress.ofLiteral("192.0.2.1", 3478)
    private val local = SocketAddress.ofLiteral("10.0.0.1", 5000)

    /**
     * `PayloadTooLarge` is permanent for these bytes: the socket has already measured them against its
     * limit, so re-sending the identical datagram every retransmit interval until the budget expires
     * cannot do anything but waste it. The gather must give up on the **first** refusal.
     */
    @Test
    fun an_oversized_request_stops_retransmitting_immediately() =
        runTest {
            val channel = RefusingChannel(local, IceTransmitFailureReason.PayloadTooLarge(attempted = 1500, limit = 1200))

            val result = gatherServerReflexive(channel, stunServer, Random(1), bufferFactory = BufferFactory.Default)

            assertIs<ServerReflexiveResult.Unavailable.SendFailed>(result, "an unsendable payload is a send failure")
            assertEquals(
                1,
                channel.attempts,
                "the socket already measured this payload — retransmitting it unchanged cannot succeed, " +
                    "so the budget must not be spent on it",
            )
        }

    /**
     * The anti-vacuity direction, and the one that matters more: every *other* reason stays retryable.
     * A short-circuit that fired on anything else would turn a momentary local refusal into a lost
     * candidate — the exact over-correction webrtc#143 warns against.
     */
    @Test
    fun every_other_reason_keeps_retransmitting() =
        runTest {
            for (
            reason in
            listOf(
                IceTransmitFailureReason.Transient,
                IceTransmitFailureReason.DestinationUnreachable,
                IceTransmitFailureReason.Unknown,
            )
            ) {
                val channel = RefusingChannel(local, reason)

                val result = gatherServerReflexive(channel, stunServer, Random(1), bufferFactory = BufferFactory.Default)

                assertIs<ServerReflexiveResult.Unavailable.SendFailed>(result, "$reason still yields a send failure")
                assertTrue(
                    channel.attempts > 1,
                    "$reason must keep retransmitting across the budget — it may succeed on a later " +
                        "attempt, and giving up costs the candidate (attempts=${channel.attempts})",
                )
            }
        }

    /**
     * An untranslated binder — the vnet, or an app sharing a demuxed socket with QUIC-P2P — raises a
     * plain exception with no reason attached. It must classify as [IceTransmitFailureReason.Unknown]
     * and therefore keep retrying, which is exactly how this module behaved before any typing existed.
     */
    @Test
    fun an_untyped_failure_is_unknown_and_still_retried() =
        runTest {
            val channel = RefusingChannel(local, reason = null)

            val result = gatherServerReflexive(channel, stunServer, Random(1), bufferFactory = BufferFactory.Default)

            assertIs<ServerReflexiveResult.Unavailable.SendFailed>(result)
            assertTrue(channel.attempts > 1, "an unclassified failure must stay retryable")
        }

    /**
     * A channel that refuses every send, optionally with a classified [reason]. A null [reason] models a
     * binder that does not translate socket's typed errors — it raises the way an unwrapped channel does.
     */
    private class RefusingChannel(
        override val localAddress: SocketAddress,
        private val reason: IceTransmitFailureReason?,
    ) : AddressedDatagramChannel {
        var attempts: Int = 0
            private set

        private val inbound = Channel<Datagram>(Channel.UNLIMITED)
        private var closed = false

        override val isOpen: Boolean get() = !closed
        override val maxWritableSize: Int = 65507
        override val capabilities: DatagramCapabilities = DatagramCapabilities()

        override suspend fun receive(): DatagramReadResult {
            val datagram = inbound.receiveCatching().getOrNull()
            return if (datagram != null) DatagramReadResult.Received(datagram) else DatagramReadResult.Closed()
        }

        override suspend fun send(
            payload: ReadBuffer,
            to: SocketAddress,
            options: DatagramSendOptions,
        ) {
            attempts++
            val cause = IllegalStateException("refused")
            throw if (reason == null) cause else IceTransmitException(reason, cause)
        }

        override fun close() {
            closed = true
            inbound.close()
        }
    }
}

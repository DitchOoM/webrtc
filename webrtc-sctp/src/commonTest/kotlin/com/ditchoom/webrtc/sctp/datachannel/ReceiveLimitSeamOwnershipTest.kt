@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.LeakTrackingFactory
import com.ditchoom.webrtc.sctp.association.ReceiveMessageLimit
import com.ditchoom.webrtc.sctp.association.SctpConfig
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlin.random.Random
import kotlin.test.Test
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **A message refused for size gives every buffer back.**
 *
 * This repo's recurring leak shape is "a decode whose result nobody returns" — the three `TurnAllocation`
 * leaks were all of it — and a refusal path is that shape by construction: it is the branch where a
 * decoded chunk is examined and then nobody takes it. The receive ceiling adds two such branches at once,
 * the refusal itself and the ABORT-and-teardown it triggers, and both run over an association holding
 * *partially* reassembled fragments, which is the state the ordinary teardown fixtures never reach.
 *
 * A tracker on `SctpConfig.bufferFactory` and nothing under it, one per peer, exactly as
 * `SctpSendSeamOwnershipTest` — a shared tracker would let the sender's discipline mask the receiver's,
 * and the receiver is the whole point here.
 *
 * `assertPoolDrained` is the gate. `assertNoLeaks` runs first only because it names *which* buffer: a
 * refusal that dropped a fragment copy would fail the first, while a refusal that took a slice to measure
 * the chunk and never handed it back would pass the first and fail the second.
 */
class ReceiveLimitSeamOwnershipTest {
    private val epoch = Instant.fromEpochSeconds(0)

    private fun TestScope.clock(): () -> Instant = { epoch + testScheduler.currentTime.milliseconds }

    private suspend fun awaitTrue(
        timeout: Duration = 120.seconds,
        condition: () -> Boolean,
    ) = withTimeout(timeout) { while (!condition()) delay(1.milliseconds) }

    private fun bytes(size: Int): ReadBuffer {
        val buf = BufferFactory.managed().allocate(maxOf(1, size), ByteOrder.BIG_ENDIAN)
        repeat(size) { buf.writeByte((it and 0xFF).toByte()) }
        buf.resetForRead()
        buf.setLimit(size)
        return buf
    }

    /**
     * The receiver's ceiling is [CEILING]; the sender's own gate is told the peer will take anything, so
     * it puts a message four times that on the wire. The receiver refuses it mid-run — with earlier
     * fragments already copied and held — ABORTs, and tears down.
     */
    @Test
    fun a_refused_oversized_message_returns_every_buffer_on_both_peers() =
        runTest {
            val clientSctp = LeakTrackingFactory()
            val serverSctp = LeakTrackingFactory()
            val transports = MemoryTransportPair(backgroundScope, seed = 61)
            val client =
                SctpDataChannelStack(
                    transports.clientTransport,
                    backgroundScope,
                    clock(),
                    SctpRole.Client,
                    SctpConfig(bufferFactory = clientSctp),
                    Random(61),
                )
            val server =
                SctpDataChannelStack(
                    transports.serverTransport,
                    backgroundScope,
                    clock(),
                    SctpRole.Server,
                    SctpConfig(bufferFactory = serverSctp, receiveMessageLimit = ReceiveMessageLimit.Bytes(CEILING.toLong())),
                    Random(62),
                )
            // The sender must be allowed to commit the violation, which is the only way to reach the
            // receiver's refusal at all — no conforming peer produces this.
            client.setPeerMessageLimit(PeerMessageLimit.Unlimited)
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "oversize"))
            server.acceptBidirectional()

            val oversized = bytes(CEILING * 4)
            try {
                // The send itself may complete (the association accepted it) or fail (the abort arrived
                // first). Which one is a race with the wire and is deliberately NOT asserted here — what
                // this fixture is about is the memory afterwards.
                runCatching { channel.send(DataChannelPayload.Binary(oversized)) }
            } finally {
                oversized.freeIfNeeded()
            }

            awaitTrue { server.isTornDown }
            transports.cutWire()
            awaitTrue { client.isTornDown }
            testScheduler.advanceUntilIdle()

            // Both assertions carry their own anti-vacuity check (a run that allocated nothing fails
            // them), so a receiver that somehow refused the message without ever reaching its buffer
            // factory cannot report a clean census here.
            clientSctp.assertNoLeaks("the oversizing sender's SCTP seam")
            clientSctp.assertPoolDrained("the oversizing sender's SCTP seam")
            serverSctp.assertNoLeaks("the refusing receiver's SCTP seam")
            serverSctp.assertPoolDrained("the refusing receiver's SCTP seam")
        }

    private companion object {
        // Several fragments at the default 1200-byte payload, so the refusal fires with fragment copies
        // already held rather than on the first chunk — the state the ordinary teardown fixtures skip.
        private const val CEILING = 3600
    }
}

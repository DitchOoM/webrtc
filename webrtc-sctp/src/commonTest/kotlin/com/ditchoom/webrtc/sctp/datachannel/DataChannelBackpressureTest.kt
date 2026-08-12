@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.association.SctpConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

private val EPOCH = Instant.fromEpochSeconds(0)

/** Watermarks small enough that a handful of messages crosses them — the mechanism, not the default, is under test. */
private const val HIGH_WATER = 8 * 1024
private const val LOW_WATER = 4 * 1024
private const val MESSAGE_BYTES = 4 * 1024
private const val ATTEMPTS = 64

private fun payload(size: Int): ReadBuffer {
    val buf = BufferFactory.managed().allocate(size, ByteOrder.BIG_ENDIAN)
    repeat(size) { buf.writeByte((it and 0xFF).toByte()) }
    buf.resetForRead()
    buf.setLimit(size)
    return buf
}

/**
 * An in-memory transport pair whose client→server direction can be BLACKHOLED mid-association. Blackholing
 * is what makes "the send window is full" reachable deterministically: with no datagrams arriving the server
 * never SACKs, so the client's cwnd/rwnd stop opening, `trySend` stops draining, and everything the
 * application hands to `send()` piles up in the association's pending-send queue — exactly the state
 * backpressure exists to bound. No timing and no wall clock: the gate is a boolean the test flips.
 */
private class GatedTransportPair {
    private val aToB = Channel<ReadBuffer>(Channel.UNLIMITED)
    private val bToA = Channel<ReadBuffer>(Channel.UNLIMITED)

    /** While false, every client→server datagram is dropped (a black hole, not a close — the peer is mute, not gone). */
    var clientToServerOpen: Boolean = true

    val clientTransport: SctpDatagramTransport = Endpoint(aToB, bToA, gated = true)
    val serverTransport: SctpDatagramTransport = Endpoint(bToA, aToB, gated = false)

    /**
     * Close the server→client direction. This — not `clientTransport.close()` — is what tears the CLIENT
     * down: a transport's `close()` closes the channel it SENDS on, and the client's reader loop blocks on
     * the channel it RECEIVES from, which is the one the server sends on.
     */
    fun cutServerToClient() = serverTransport.close()

    private inner class Endpoint(
        private val sendCh: Channel<ReadBuffer>,
        private val recvCh: Channel<ReadBuffer>,
        private val gated: Boolean,
    ) : SctpDatagramTransport {
        override suspend fun send(packet: ReadBuffer) {
            if (gated && !clientToServerOpen) return
            packet.position(0)
            sendCh.trySend(packet.slice())
        }

        override suspend fun receive(): ReadBuffer? = recvCh.receiveCatching().getOrNull()

        override fun close() {
            sendCh.close()
        }
    }
}

class DataChannelBackpressureTest {
    private fun TestScope.clock(): () -> Instant = { EPOCH + testScheduler.currentTime.milliseconds }

    /**
     * Run every task that is runnable at the CURRENT virtual time, without letting the clock move.
     *
     * `advanceUntilIdle()` alone is not enough here: on kotlinx-coroutines 1.11.0 it does not start a
     * freshly-launched `backgroundScope` coroutine, so the sender under test would never enter `send()`.
     * `runCurrent()` does. Holding the clock still is also what keeps the blackholed phase deterministic —
     * no virtual time passes, so no T3-rtx fires and the association cannot retransmit or abort out from
     * under the assertion. The parked/unparked state is reached purely by dispatch, never by duration.
     */
    private fun TestScope.settle(rounds: Int = 40) = repeat(rounds) { runCurrent() }

    /** Let the retransmission timers actually fire, in bounded steps, once the path is restored. */
    private fun TestScope.settleWithTime(rounds: Int = 40) =
        repeat(rounds) {
            advanceTimeBy(1.seconds)
            runCurrent()
        }

    private fun config() =
        SctpConfig(
            sendBufferHighWaterBytes = HIGH_WATER,
            sendBufferLowWaterBytes = LOW_WATER,
            bufferFactory = BufferFactory.managed(),
        )

    private fun TestScope.stacks(
        pair: GatedTransportPair,
        scope: CoroutineScope,
        seed: Int,
    ): Pair<SctpDataChannelStack, SctpDataChannelStack> {
        val client = SctpDataChannelStack(pair.clientTransport, scope, clock(), SctpRole.Client, config(), Random(seed))
        val server = SctpDataChannelStack(pair.serverTransport, scope, clock(), SctpRole.Server, config(), Random(seed + 1))
        client.start()
        server.start()
        return client to server
    }

    /**
     * The core guarantee of the suspending send: once the association is behind, `send()` stops returning.
     * A caller that can outrun the wire is throttled by the suspension itself, with nothing to poll and
     * nothing to register.
     *
     * `BufferedDataChannel` has since added a gauge and a wait, and this fixture is what keeps them from
     * being read as a replacement: the suspension is still the whole contract for a producer loop, and it
     * still holds for a caller that never looks at `bufferedAmount`.
     */
    @Test
    fun send_suspends_once_the_send_buffer_is_full_and_resumes_when_it_drains() =
        runTest {
            val pair = GatedTransportPair()
            val (client, _) = stacks(pair, backgroundScope, seed = 1)

            val channel = client.open(DataChannelConfig(label = "bulk"))
            settle()

            // The peer goes mute: nothing more is acknowledged, so the window never reopens.
            pair.clientToServerOpen = false

            var completed = 0
            val sender =
                backgroundScope.launch {
                    repeat(ATTEMPTS) {
                        channel.send(payload(MESSAGE_BYTES))
                        completed++
                    }
                }
            settle()

            // The sender is parked mid-loop — NOT spinning, NOT having queued all 64 messages into memory.
            assertTrue(sender.isActive, "sender must still be suspended inside send() while the window is full")
            assertTrue(completed > 0, "sends below the high-water mark complete eagerly (the fast path)")
            assertTrue(
                completed < ATTEMPTS,
                "send() must suspend once queued bytes exceed the high-water mark; instead all $ATTEMPTS " +
                    "messages were accepted, which is unbounded buffering",
            )
            assertEquals(1, client.parkedSenders, "exactly the one blocked sender is parked")
            assertTrue(
                client.bufferedBytes > HIGH_WATER,
                "precondition: the send buffer is genuinely above the high-water mark " +
                    "(was ${client.bufferedBytes})",
            )

            // The queue is bounded by the mark plus the single message that crossed it, per parked sender —
            // this is the memory guarantee, and it is what an unbounded queue would violate.
            assertTrue(
                client.bufferedBytes <= HIGH_WATER + MESSAGE_BYTES,
                "queued bytes must stay within one message of the high-water mark " +
                    "(was ${client.bufferedBytes}, bound ${HIGH_WATER + MESSAGE_BYTES})",
            )

            // Reopen the path. The client's T3-rtx retransmits, the server SACKs, the queue drains past the
            // low-water mark, and the parked sender is resumed — no nudge from the application required.
            val parkedAt = completed
            pair.clientToServerOpen = true
            settleWithTime()

            assertTrue(
                completed > parkedAt,
                "a drained send buffer must resume the parked sender (was $parkedAt, still $completed)",
            )
            assertEquals(ATTEMPTS, completed, "every message eventually sends once the peer drains the window")
            assertFalse(sender.isActive, "the send loop completes once all messages are accepted")
            assertEquals(0, client.parkedSenders, "no sender stays parked once the buffer has drained")
        }

    /**
     * The leak the suspend-only design could plausibly introduce: a sender parked on backpressure is NOT in
     * the command inbox — its command was already processed and its message queued; only the resume is
     * outstanding. A teardown that drained just the inbox would leave it suspended forever on an association
     * that will never drain again. It must fail typed instead.
     */
    @Test
    fun sender_parked_on_backpressure_fails_typed_when_the_association_tears_down() =
        runTest {
            val pair = GatedTransportPair()
            val (client, _) = stacks(pair, backgroundScope, seed = 3)

            val channel = client.open(DataChannelConfig(label = "bulk"))
            settle()
            pair.clientToServerOpen = false

            var thrown: Throwable? = null
            var completed = 0
            val sender =
                backgroundScope.launch {
                    try {
                        repeat(ATTEMPTS) {
                            channel.send(payload(MESSAGE_BYTES))
                            completed++
                        }
                    } catch (t: Throwable) {
                        thrown = t
                    }
                }
            settle()
            assertTrue(sender.isActive, "precondition: the sender is parked on backpressure")
            assertEquals(1, client.parkedSenders, "precondition: exactly one parked sender")
            assertTrue(completed < ATTEMPTS, "precondition: not every message was accepted")

            // Tear the association down underneath the parked sender.
            pair.cutServerToClient()
            settle()

            assertTrue(client.isTornDown, "precondition: the stack observed the transport close")
            assertFalse(
                sender.isActive,
                "a sender parked on backpressure must be resumed by teardown, not left suspended forever",
            )
            assertIs<SctpClosedException>(
                thrown,
                "teardown must fail the parked send() with the typed close exception, not a bare cancellation",
            )
            assertEquals(0, client.parkedSenders, "teardown drains the parked-sender queue (no leak)")
        }

    /** A sender that never outruns the association must not pay for backpressure — the fast path stays eager. */
    @Test
    fun sends_below_the_high_water_mark_never_suspend() =
        runTest {
            val pair = GatedTransportPair()
            val (client, server) = stacks(pair, backgroundScope, seed = 5)

            val channel = client.open(DataChannelConfig(label = "chat"))
            val incoming = server.acceptBidirectional()
            settle()

            val received = mutableListOf<Int>()
            backgroundScope.launch { incoming.receive().collect { received.add(it.expectBinary().remaining()) } }
            settle()

            var completed = 0
            val sender =
                backgroundScope.launch {
                    repeat(20) {
                        channel.send(payload(64))
                        completed++
                    }
                }
            settle()

            assertFalse(sender.isActive, "small sends on a draining association must never park")
            assertEquals(20, completed, "every small send completes eagerly")
            assertEquals(0, client.parkedSenders, "nothing parks below the high-water mark")
            assertEquals(20, received.size, "and all of them arrive")
        }
}

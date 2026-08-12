@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.association.SctpConfig
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

private val EPOCH = Instant.fromEpochSeconds(0)

// Water marks low enough that a handful of messages crosses them, so the queue is observably deep.
private const val HIGH_WATER = 8 * 1024
private const val LOW_WATER = 4 * 1024
private const val MESSAGE_BYTES = 4 * 1024

private fun payload(size: Int): ReadBuffer {
    val buf = BufferFactory.managed().allocate(size, ByteOrder.BIG_ENDIAN)
    repeat(size) { buf.writeByte((it and 0xFF).toByte()) }
    buf.resetForRead()
    buf.setLimit(size)
    return buf
}

/**
 * A transport pair whose client→server direction can be **held** and then let go.
 *
 * Holding rather than dropping, deliberately. A black-holed datagram comes back only through a
 * retransmission timer, which means advancing virtual time — and a gauge asserted after a clock advance is
 * asserting a schedule as much as a value. Held datagrams flow the instant the hold is released, so every
 * assertion here is on observable state at the current instant, with `runCurrent` as the only pump.
 */
private class HoldingTransportPair {
    private val aToB = Channel<ReadBuffer>(Channel.UNLIMITED)
    private val bToA = Channel<ReadBuffer>(Channel.UNLIMITED)
    private val held = ArrayDeque<ReadBuffer>()

    /** While true, client→server datagrams are parked rather than delivered. Releasing flushes them in order. */
    var holding: Boolean = false
        set(value) {
            field = value
            if (!value) {
                while (held.isNotEmpty()) aToB.trySend(held.removeFirst())
            }
        }

    val clientTransport: SctpDatagramTransport = Endpoint(aToB, bToA, holdable = true)
    val serverTransport: SctpDatagramTransport = Endpoint(bToA, aToB, holdable = false)

    private inner class Endpoint(
        private val sendCh: Channel<ReadBuffer>,
        private val recvCh: Channel<ReadBuffer>,
        private val holdable: Boolean,
    ) : SctpDatagramTransport {
        override suspend fun send(packet: ReadBuffer) {
            packet.position(0)
            val view = packet.slice()
            if (holdable && holding) held.addLast(view) else sendCh.trySend(view)
        }

        override suspend fun receive(): ReadBuffer? = recvCh.receiveCatching().getOrNull()

        override fun close() {
            sendCh.close()
        }
    }
}

/**
 * **`bufferedAmount` and `awaitBufferedAmountLow`** — W3C's send-side gauge, for the producers that
 * `send()`'s suspension cannot serve.
 *
 * Two properties carry the design:
 *
 * - The gauge is a **projection** of the association's unsent queue, not a counter this layer keeps. Two
 *   counters for one quantity is the shape that drifts, and a `bufferedAmount` disagreeing with what is
 *   actually queued is worse than not having one.
 * - It counts **application** bytes only. The stack's own RFC 8832 DCEP OPEN and ACK ride the same stream
 *   and are not something the application queued or can drain, so a gauge that counted them would tick up
 *   on a channel nobody has sent on — and `awaitBufferedAmountLow(ZERO)` would then be waiting on protocol
 *   chatter.
 */
class BufferedAmountTest {
    private fun TestScope.clock(): () -> Instant = { EPOCH + testScheduler.currentTime.milliseconds }

    private fun config() =
        SctpConfig(
            sendBufferHighWaterBytes = HIGH_WATER,
            sendBufferLowWaterBytes = LOW_WATER,
            bufferFactory = BufferFactory.managed(),
        )

    private fun TestScope.settle(rounds: Int = 60) = repeat(rounds) { runCurrent() }

    @Test
    fun a_negative_amount_is_unconstructible_and_zero_is_named() {
        assertFailsWith<IllegalArgumentException> { BufferedAmount(-1) }
        assertEquals(0L, BufferedAmount.ZERO.bytes)
        assertTrue(BufferedAmount(1) > BufferedAmount.ZERO, "amounts compare as byte counts")
    }

    /**
     * A channel that has only ever exchanged DCEP reports **zero**. The OPEN and the ACK are real queued
     * bytes on this stream — a gauge reading the association's whole unsent queue would report them.
     */
    @Test
    fun dcep_traffic_is_not_counted_as_application_data() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, config(), Random(1))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, config(), Random(2))
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "control-only"))
            server.acceptBidirectional()
            settle()

            assertEquals(
                BufferedAmount.ZERO,
                channel.bufferedAmount.value,
                "a channel that has only exchanged DCEP has nothing the application queued",
            )
            client.shutdown()
        }

    /**
     * The gauge rises with what `send()` queues and falls back to zero as the association drains it. The
     * transport is gated shut first, so the queue is observably deep rather than racing the wire.
     */
    @Test
    fun the_gauge_tracks_the_unsent_queue_and_drains_to_zero() =
        runTest {
            val gate = HoldingTransportPair()
            val client =
                SctpDataChannelStack(gate.clientTransport, backgroundScope, clock(), SctpRole.Client, config(), Random(3))
            val server =
                SctpDataChannelStack(gate.serverTransport, backgroundScope, clock(), SctpRole.Server, config(), Random(4))
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "gauge"))
            server.acceptBidirectional()
            settle()

            gate.holding = true
            // Sends past the high-water mark park their caller, so they are launched rather than awaited.
            repeat(6) { backgroundScope.launch { channel.send(payload(MESSAGE_BYTES)) } }
            settle()

            val queued = channel.bufferedAmount.value
            assertTrue(queued > BufferedAmount.ZERO, "a stopped wire leaves application bytes queued")

            gate.holding = false
            settle(400)
            assertEquals(BufferedAmount.ZERO, channel.bufferedAmount.value, "and the gauge returns to zero as it drains")
            client.shutdown()
        }

    /**
     * `awaitBufferedAmountLow` is the wait W3C spells as a mutable threshold plus an event. The threshold
     * is a **parameter**, so there is no latch to arm and nothing to correlate with the current amount —
     * the property form's "threshold lowered while an event is pending" is unrepresentable here.
     */
    @Test
    fun await_buffered_amount_low_resumes_when_the_queue_drains() =
        runTest {
            val gate = HoldingTransportPair()
            val client =
                SctpDataChannelStack(gate.clientTransport, backgroundScope, clock(), SctpRole.Client, config(), Random(5))
            val server =
                SctpDataChannelStack(gate.serverTransport, backgroundScope, clock(), SctpRole.Server, config(), Random(6))
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "await"))
            server.acceptBidirectional()
            settle()

            gate.holding = true
            repeat(6) { backgroundScope.launch { channel.send(payload(MESSAGE_BYTES)) } }
            settle()
            assertTrue(channel.bufferedAmount.value > BufferedAmount.ZERO, "precondition: something is queued")

            var resumed = false
            backgroundScope.launch {
                channel.awaitBufferedAmountLow()
                resumed = true
            }
            settle()
            assertTrue(!resumed, "a waiter must not resume while the channel still has data queued")

            gate.holding = false
            settle(400)
            assertTrue(resumed, "and resumes once it has drained")
            client.shutdown()
        }

    /** Already below the threshold: the wait is a predicate over a published value, so it returns at once. */
    @Test
    fun await_returns_immediately_when_already_below_the_threshold() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, config(), Random(7))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, config(), Random(8))
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "idle"))
            server.acceptBidirectional()
            settle()

            var resumed = false
            backgroundScope.launch {
                channel.awaitBufferedAmountLow(BufferedAmount(MESSAGE_BYTES.toLong()))
                resumed = true
            }
            settle()
            assertTrue(resumed, "an idle channel is already below any threshold")
            client.shutdown()
        }

    /**
     * A waiter on a channel that closes must be released, not stranded. Nothing will republish the gauge
     * for a channel the stack has dropped, so the close publishes zero itself — which is also true: the
     * association reclaims its unsent fragments at teardown.
     */
    @Test
    fun closing_a_channel_releases_a_waiter() =
        runTest {
            val gate = HoldingTransportPair()
            val client =
                SctpDataChannelStack(gate.clientTransport, backgroundScope, clock(), SctpRole.Client, config(), Random(9))
            val server =
                SctpDataChannelStack(gate.serverTransport, backgroundScope, clock(), SctpRole.Server, config(), Random(10))
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "closing"))
            server.acceptBidirectional()
            settle()

            gate.holding = true
            repeat(6) { backgroundScope.launch { channel.send(payload(MESSAGE_BYTES)) } }
            settle()
            assertTrue(channel.bufferedAmount.value > BufferedAmount.ZERO, "precondition: something is queued")

            var resumed = false
            backgroundScope.launch {
                channel.awaitBufferedAmountLow()
                resumed = true
            }
            settle()
            assertTrue(!resumed, "precondition: the waiter is parked")

            channel.close()
            settle()
            assertTrue(resumed, "a closed channel has nothing left to drain, so the waiter is released")
        }
}

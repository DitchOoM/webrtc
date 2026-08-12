@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.association.ReceiveMessageLimit
import com.ditchoom.webrtc.sctp.association.ReceiveOverrunWindows
import com.ditchoom.webrtc.sctp.association.SctpConfig
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

private val EPOCH = Instant.fromEpochSeconds(0)

// Small enough that a handful of unread messages shuts the receiver's window, and the overrun ceiling with
// it. The default 1 MiB would need thousands of messages to reach the same state.
private const val WINDOW_BYTES = 8_000
private const val MESSAGE_BYTES = 1_000

private fun payload(size: Int): ReadBuffer {
    val buf = BufferFactory.managed().allocate(maxOf(1, size), ByteOrder.BIG_ENDIAN)
    repeat(size) { buf.writeByte((it and 0xFF).toByte()) }
    buf.resetForRead()
    buf.setLimit(size)
    return buf
}

/**
 * **The credit seam** (RFC 4960 §3.3.2): every message the association delivers holds receive-window space
 * until the upper layer is finished with it, and every path a message can take gives that space back.
 *
 * The failure this fixture exists to catch is not a crash. A forgotten credit shrinks the advertised window
 * permanently, one message at a time, and a session only notices after it has moved enough data to close
 * the window entirely — which is why the assertions here are on the *advertised value* rather than on a
 * session surviving. A stack that never credits passes every liveness test in this module.
 */
class ReceiveCreditSeamTest {
    private fun TestScope.clock(): () -> Instant = { EPOCH + testScheduler.currentTime.milliseconds }

    // The message ceiling comes down with the window: `SctpConfig` refuses a pair where a message this
    // endpoint permits could never fit in the buffer it is willing to hold, and the 256 KiB default against
    // an 8 KB window is exactly that pair.
    private fun config() =
        SctpConfig(
            receiveWindowBytes = WINDOW_BYTES.toUInt(),
            receiveOverrun = ReceiveOverrunWindows(2),
            receiveMessageLimit = ReceiveMessageLimit.Bytes(WINDOW_BYTES.toLong()),
            bufferFactory = BufferFactory.managed(),
        )

    private fun TestScope.stacks(pair: MemoryTransportPair): Pair<SctpDataChannelStack, SctpDataChannelStack> {
        val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, config(), Random(1))
        val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, config(), Random(2))
        client.start()
        server.start()
        return client to server
    }

    private fun TestScope.settle(rounds: Int = 40) = repeat(rounds) { runCurrent() }

    /**
     * A collector that reads every message keeps the window open indefinitely. Sixteen messages is twice
     * the window, so a stack that credited nothing would have shut it before the eighth and stalled.
     */
    @Test
    fun a_collector_that_reads_keeps_the_window_open() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val (client, server) = stacks(pair)
            val channel = client.open(DataChannelConfig(label = "credit"))
            val incoming = server.acceptBidirectional()

            val seen = Channel<Int>(Channel.UNLIMITED)
            backgroundScope.launch {
                incoming.receive().collect { message ->
                    seen.send(message.expectBinary().remaining())
                    message.release()
                }
            }

            val total = (2 * WINDOW_BYTES) / MESSAGE_BYTES
            repeat(total) { channel.send(payload(MESSAGE_BYTES)) }
            settle(200)

            val received = ArrayList<Int>()
            repeat(total) { received += seen.tryReceive().getOrNull() ?: -1 }
            assertEquals(List(total) { MESSAGE_BYTES }, received, "twice the window flows through a reading collector")
            assertEquals(0L, server.outstandingReceiveBytes, "and nothing is left charged once it has all been read")

            client.shutdown()
        }

    /**
     * **The half that a liveness test cannot see.** A collector that stops reading must leave the window
     * charged — that is what makes the peer stop — and resuming must give it back.
     *
     * Asserted on `outstandingReceiveBytes`, which is the association's own count of delivered-but-
     * uncredited bytes. A stack that credited at *delivery* rather than at consumption would read zero
     * here throughout and would provide no backpressure at all, while still passing every other fixture in
     * this module.
     */
    @Test
    fun an_unread_message_stays_charged_until_the_collector_takes_it() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val (client, server) = stacks(pair)
            val channel = client.open(DataChannelConfig(label = "hold"))
            val incoming = server.acceptBidirectional()

            channel.send(payload(MESSAGE_BYTES))
            settle()
            assertEquals(
                MESSAGE_BYTES.toLong(),
                server.outstandingReceiveBytes,
                "a delivered but unread message holds its window space",
            )

            val message = incoming.receive().first()
            message.release()
            settle()
            assertEquals(0L, server.outstandingReceiveBytes, "taking it from the flow returns the space")

            client.shutdown()
        }

    /**
     * A DCEP OPEN/ACK occupies receive buffer like anything else and no application ever sees it, so the
     * only place its space can come back is where its buffer does. Every channel opened here exchanges an
     * OPEN and an ACK; if either leaked its charge, the count below would be non-zero.
     */
    @Test
    fun control_messages_credit_their_own_space() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val (client, server) = stacks(pair)
            repeat(4) { client.open(DataChannelConfig(label = "dcep-$it")) }
            repeat(4) { server.acceptBidirectional() }
            settle()

            assertEquals(0L, server.outstandingReceiveBytes, "the peer's DCEP OPENs credited their own bytes")
            assertEquals(0L, client.outstandingReceiveBytes, "and so did the ACKs coming back")

            client.shutdown()
        }

    /**
     * RFC 8831 §6.6's empty message rides a single `0x00` marker that is stripped at decode — the buffer is
     * released there, so the byte's charge has to come back there too. It cannot ride on to the application
     * on a payload that references nothing, which is what [InboundDelivery.Unmetered] says.
     */
    @Test
    fun an_empty_message_credits_its_marker_byte_at_decode() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val (client, server) = stacks(pair)
            val channel = client.open(DataChannelConfig(label = "empty"))
            val incoming = server.acceptBidirectional()

            channel.send(DataChannelPayload.Text(""))
            channel.send(DataChannelPayload.Binary(BufferFactory.managed().allocate(0, ByteOrder.BIG_ENDIAN)))
            settle()
            // Nothing has been collected yet, and yet nothing is charged: both markers were spent at decode.
            assertEquals(0L, server.outstandingReceiveBytes, "an empty message owes nothing once decoded")

            val first = incoming.receive().first()
            assertEquals("", first.expectText(), "…and it still arrives")
            settle()
            assertEquals(0L, server.outstandingReceiveBytes, "consuming an Unmetered delivery credits nothing twice")

            client.shutdown()
        }

    /**
     * A message that is discarded rather than delivered — RFC 8831 §6.6 requires a `WebRTC String` to be
     * UTF-8 — still has to give its space back. This is the path with no application to notice, which
     * CLAUDE.md names as where a release goes missing.
     */
    @Test
    fun a_discarded_message_credits_its_space() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val (client, server) = stacks(pair)
            val channel = client.open(DataChannelConfig(label = "malformed")) as DataChannelConnection
            server.acceptBidirectional()
            settle()

            // A lone 0x80 continuation byte: a `WebRTC String` PPID over bytes that are not UTF-8, which is
            // unconstructible through the public API and is why `sendUnencoded` exists.
            val bad = BufferFactory.managed().allocate(1, ByteOrder.BIG_ENDIAN)
            bad.writeByte(0x80.toByte())
            bad.resetForRead()
            bad.setLimit(1)
            client.sendUnencoded(channel.streamId, PayloadProtocolId.WebRtcString, channel.config, bad)
            settle()

            assertTrue(server.discardedInbound > 0, "precondition: the message really was discarded")
            assertEquals(0L, server.outstandingReceiveBytes, "a discard gives the window space back with the buffer")

            client.shutdown()
        }

    /**
     * Data on a stream whose DCEP OPEN never arrives is held, bounded, and then dropped. Both the holding
     * and the dropping have to keep the window honest: held data is still charged (the memory is real),
     * and dropped data is not.
     */
    @Test
    fun data_held_for_an_unopened_stream_is_charged_and_released_with_the_stream() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val (client, server) = stacks(pair)
            val channel = client.open(DataChannelConfig(label = "orphan")) as DataChannelConnection
            server.acceptBidirectional()
            settle()

            // A message on a stream id the server has never seen an OPEN for: it lands in pendingInbound.
            val orphanStream = StreamId(channel.streamId.value + 4)
            client.sendUnencoded(orphanStream, PayloadProtocolId.WebRtcBinary, channel.config, payload(MESSAGE_BYTES))
            settle()
            assertEquals(
                MESSAGE_BYTES.toLong(),
                server.outstandingReceiveBytes,
                "data held for a stream with no channel is still occupying the buffer",
            )

            // Tearing the stack down drops it — and the charge with it.
            pair.cutWire()
            settle()
            assertEquals(0L, server.outstandingReceiveBytes, "teardown drops every outstanding charge whole")
        }
}

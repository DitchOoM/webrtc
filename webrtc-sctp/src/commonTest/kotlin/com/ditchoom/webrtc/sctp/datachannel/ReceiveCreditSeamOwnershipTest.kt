@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.LeakTrackingFactory
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.association.ReceiveMessageLimit
import com.ditchoom.webrtc.sctp.association.ReceiveOverrunWindows
import com.ditchoom.webrtc.sctp.association.SctpConfig
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **The credit seam gives every buffer back — on every path a message can take.**
 *
 * This is the fixture the `InboundDelivery` design is *for*. Fusing the buffer release with the window
 * credit was chosen so that forgetting the credit means forgetting the release, which turns an invisible
 * bug — a window that shrinks permanently, observable only after a long session stalls — into one an
 * existing gate catches. That argument is worth nothing unless a gate actually runs over the paths, so
 * this one drives all five in a single session: delivered and collected, decoded away for DCEP, decoded
 * away for the empty-message marker, discarded as malformed, and held for a stream that never opens and
 * then dropped at teardown.
 *
 * A tracker on `SctpConfig.bufferFactory` and nothing under it, one per peer, exactly as
 * `ReceiveLimitSeamOwnershipTest` — a shared tracker would let the sender's discipline mask the receiver's,
 * and the receiver is the whole point.
 *
 * `assertPoolDrained` is the gate; `assertNoLeaks` runs first only because it names *which* buffer. The
 * receive window's own books are checked beside them: a census that is clean while receipts are still
 * outstanding would mean the buffers came back by a path that did not credit, which is exactly the
 * separation the fused seam exists to make impossible.
 */
class ReceiveCreditSeamOwnershipTest {
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

    private fun config(factory: BufferFactory) =
        SctpConfig(
            receiveWindowBytes = WINDOW.toUInt(),
            receiveOverrun = ReceiveOverrunWindows(2),
            receiveMessageLimit = ReceiveMessageLimit.Bytes(WINDOW.toLong()),
            bufferFactory = factory,
        )

    @Test
    fun every_path_a_received_message_takes_returns_its_buffer_and_its_receipt() =
        runTest {
            val clientSctp = LeakTrackingFactory()
            val serverSctp = LeakTrackingFactory()
            val transports = MemoryTransportPair(backgroundScope, seed = 71)
            val client =
                SctpDataChannelStack(
                    transports.clientTransport,
                    backgroundScope,
                    clock(),
                    SctpRole.Client,
                    config(clientSctp),
                    Random(71),
                )
            val server =
                SctpDataChannelStack(
                    transports.serverTransport,
                    backgroundScope,
                    clock(),
                    SctpRole.Server,
                    config(serverSctp),
                    Random(72),
                )
            client.start()
            server.start()

            // (1) DCEP OPEN and ACK — decoded and released inside the drive loop, seen by no application.
            val channel = client.open(DataChannelConfig(label = "census")) as DataChannelConnection
            val incoming = server.acceptBidirectional()

            // (2) Ordinary messages, delivered and collected. (3) Both empty-message markers, whose byte is
            // released at decode. Collected together so the flow terminates on a known count.
            val sent = bytes(PAYLOAD)
            try {
                channel.send(DataChannelPayload.Binary(sent))
                channel.send(DataChannelPayload.Text("a string message"))
                channel.send(DataChannelPayload.Text(""))
                channel.send(DataChannelPayload.Binary(BufferFactory.managed().allocate(0, ByteOrder.BIG_ENDIAN)))
            } finally {
                sent.freeIfNeeded()
            }
            val collected = incoming.receive().take(4).toList()
            assertEquals(4, collected.size, "precondition: all four shapes arrived")
            for (message in collected) message.release()

            // (4) A `WebRTC String` whose bytes are not UTF-8: discarded, never delivered, no application
            // to notice — this repo's documented shape for a missing release.
            val malformed = BufferFactory.managed().allocate(1, ByteOrder.BIG_ENDIAN)
            malformed.writeByte(0x80.toByte())
            malformed.resetForRead()
            malformed.setLimit(1)
            try {
                client.sendUnencoded(channel.streamId, PayloadProtocolId.WebRtcString, channel.config, malformed)
            } finally {
                malformed.freeIfNeeded()
            }
            awaitTrue { server.discardedInbound > 0 }

            // (5) Data on a stream the peer never OPENs: held in `pendingInbound`, then dropped at teardown.
            val orphaned = bytes(PAYLOAD)
            try {
                client.sendUnencoded(
                    StreamId(channel.streamId.value + 4),
                    PayloadProtocolId.WebRtcBinary,
                    channel.config,
                    orphaned,
                )
            } finally {
                orphaned.freeIfNeeded()
            }
            awaitTrue { server.outstandingReceiveBytes > 0 }

            transports.cutWire()
            awaitTrue { server.isTornDown }
            awaitTrue { client.isTornDown }
            testScheduler.advanceUntilIdle()

            // The window's own books first: buffers coming back while receipts are still standing would mean
            // a release that did not credit, which is precisely what the fused seam forbids.
            assertEquals(0L, server.outstandingReceiveBytes, "every receipt the receiver was handed came back")
            assertEquals(0L, client.outstandingReceiveBytes, "…and every one the sender was handed for the ACK")

            // Both assertions carry their own anti-vacuity check, so a session that somehow never reached
            // its buffer factory cannot report a clean census.
            clientSctp.assertNoLeaks("the sender's SCTP seam")
            clientSctp.assertPoolDrained("the sender's SCTP seam")
            serverSctp.assertNoLeaks("the receiving peer's SCTP seam")
            serverSctp.assertPoolDrained("the receiving peer's SCTP seam")
        }

    /**
     * The same census with the receiver's window driven **shut** and then reopened, so the count includes
     * the refusal path and the window-reopening SACK. A refusal is the shape that leaks by construction —
     * a chunk examined and then taken by nobody — and it only happens once the window is genuinely full.
     */
    @Test
    fun a_session_that_closes_and_reopens_its_window_returns_every_buffer() =
        runTest {
            val clientSctp = LeakTrackingFactory()
            val serverSctp = LeakTrackingFactory()
            val transports = MemoryTransportPair(backgroundScope, seed = 73)
            val client =
                SctpDataChannelStack(
                    transports.clientTransport,
                    backgroundScope,
                    clock(),
                    SctpRole.Client,
                    config(clientSctp),
                    Random(73),
                )
            val server =
                SctpDataChannelStack(
                    transports.serverTransport,
                    backgroundScope,
                    clock(),
                    SctpRole.Server,
                    config(serverSctp),
                    Random(74),
                )
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "window"))
            val incoming = server.acceptBidirectional()

            // Enough to take the receiver past its advertised window while nothing is collecting.
            val messages = (3 * WINDOW) / PAYLOAD
            repeat(messages) {
                val buf = bytes(PAYLOAD)
                try {
                    channel.send(DataChannelPayload.Binary(buf))
                } finally {
                    buf.freeIfNeeded()
                }
            }
            awaitTrue { server.outstandingReceiveBytes > 0 }
            assertTrue(server.outstandingReceiveBytes > 0, "precondition: the receiver is holding unread data")

            // The application reads everything, which credits every receipt and reopens the window.
            val collected = incoming.receive().take(messages).toList()
            for (message in collected) message.release()
            awaitTrue { server.outstandingReceiveBytes == 0L }

            transports.cutWire()
            awaitTrue { server.isTornDown }
            awaitTrue { client.isTornDown }
            testScheduler.advanceUntilIdle()

            clientSctp.assertNoLeaks("the sender's SCTP seam")
            clientSctp.assertPoolDrained("the sender's SCTP seam")
            serverSctp.assertNoLeaks("the flow-controlled receiver's SCTP seam")
            serverSctp.assertPoolDrained("the flow-controlled receiver's SCTP seam")
        }

    private companion object {
        // Small enough that a handful of unread messages closes the window and the refusal path is reached.
        private const val WINDOW = 8_000
        private const val PAYLOAD = 1_000
    }
}

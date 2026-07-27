@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.StreamId
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
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

private val EPOCH = Instant.fromEpochSeconds(0)

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

/**
 * Per-channel close over a real association pair (RFC 8831 §6.7 on RFC 6525): closing one data channel
 * closes it at the peer without touching the others, both directions are reset, and only then is the
 * stream id handed out again.
 *
 * Everything is awaited on observable state under `runTest` virtual time — a channel's flow completing,
 * an id appearing in the recycle list — never a fixed sleep (directive #4).
 */
class DataChannelCloseTest {
    private fun TestScope.clock(): () -> Instant = { EPOCH + testScheduler.currentTime.milliseconds }

    // Advance virtual time until [condition] holds. The steps are what let the association's own timers
    // (delayed SACK, RTO) run; the timeout is a watchdog, never a budget the assertion depends on.
    private suspend fun awaitTrue(
        timeout: Duration = 60.seconds,
        condition: () -> Boolean,
    ) = withTimeout(timeout) {
        while (!condition()) delay(1.milliseconds)
    }

    // A data class so a fixture can destructure it; named for what it holds, not `Pair`, which would
    // shadow kotlin.Pair in every test below.
    private data class Stacks(
        val client: SctpDataChannelStack,
        val server: SctpDataChannelStack,
    )

    private fun TestScope.connectedPair(seed: Long): Stacks {
        val transports = MemoryTransportPair(backgroundScope)
        val client =
            SctpDataChannelStack(transports.clientTransport, backgroundScope, clock(), SctpRole.Client, random = Random(seed))
        val server =
            SctpDataChannelStack(transports.serverTransport, backgroundScope, clock(), SctpRole.Server, random = Random(seed + 1))
        client.start()
        server.start()
        return Stacks(client, server)
    }

    @Test
    fun closing_a_channel_closes_it_at_the_peer() =
        runTest {
            val (client, server) = connectedPair(11)
            val channel = client.open(DataChannelConfig(label = "chat"))
            val peer = server.acceptBidirectional()
            channel.send(textBuffer("hi"))
            assertEquals("hi", peer.receive().first().text())

            channel.close()

            // The peer's inbound flow COMPLETING is the close arriving: it is closed by the stream reset,
            // not by anything local. Collecting to a list would hang forever if the reset never landed.
            val remaining = withTimeout(30.seconds) { peer.receive().toList() }
            assertTrue(remaining.isEmpty(), "no phantom message on a closed channel")
        }

    @Test
    fun closing_one_channel_leaves_the_others_alone() =
        runTest {
            val (client, server) = connectedPair(21)
            val doomed = client.open(DataChannelConfig(label = "doomed"))
            val kept = client.open(DataChannelConfig(label = "kept"))
            val peerDoomed = server.acceptBidirectional()
            val peerKept = server.acceptBidirectional()

            doomed.close()
            withTimeout(30.seconds) { peerDoomed.receive().toList() }

            // The surviving channel still carries traffic in both directions after its neighbour's reset.
            kept.send(textBuffer("still here"))
            assertEquals("still here", peerKept.receive().first().text())
            peerKept.send(textBuffer("so am I"))
            assertEquals("so am I", kept.receive().first().text())
        }

    @Test
    fun a_stream_id_is_recycled_once_both_directions_have_been_reset() =
        runTest {
            val (client, server) = connectedPair(31)
            val first = client.open(DataChannelConfig(label = "first"))
            server.acceptBidirectional()
            assertEquals(0L, first.id, "an RFC 8832 §6 client opens on even ids")

            first.close()
            // Both halves: our reset acknowledged, AND the peer's reciprocal reset received. Only then is
            // the id safe to hand out — the peer's SSN state for it is gone on both sides.
            awaitTrue { client.recycledStreamIds == listOf(StreamId(0)) }

            val second = client.open(DataChannelConfig(label = "second"))
            val peerSecond = server.acceptBidirectional()
            assertEquals(0L, second.id, "the closed id is reused rather than burning a fresh one")
            assertTrue(client.recycledStreamIds.isEmpty(), "…and is no longer on offer once taken")

            // The reuse is real, not just bookkeeping: an ordered message on the recycled stream starts at
            // SSN 0 again, and is delivered rather than held as a duplicate of the closed channel's.
            second.send(textBuffer("reused"))
            assertEquals("reused", peerSecond.receive().first().text())
            assertEquals("second", (peerSecond as DataChannelConnection).config.label)
        }

    @Test
    fun an_id_is_not_recycled_until_the_peer_resets_its_half() =
        runTest {
            val (client, server) = connectedPair(41)
            val channel = client.open(DataChannelConfig(label = "one-sided"))
            server.acceptBidirectional()

            channel.close()
            awaitTrue { client.recycledStreamIds.isNotEmpty() }
            // Then a SECOND open must not collide with a channel the peer still has open elsewhere: the
            // recycle list is emptied by the open, so a third channel takes a fresh id.
            client.open(DataChannelConfig(label = "two"))
            val third = client.open(DataChannelConfig(label = "three"))
            assertEquals(2L, third.id, "with the recycle list spent, allocation resumes where it left off")
        }

    @Test
    fun the_peer_closing_closes_our_side_and_resets_our_half_in_return() =
        runTest {
            val (client, server) = connectedPair(51)
            val channel = client.open(DataChannelConfig(label = "peer-closes"))
            val peer = server.acceptBidirectional()

            // The SERVER closes this time, so the client's side is torn down by an inbound reset and the
            // client's own reciprocal reset (RFC 8831 §6.7) is what completes the exchange.
            peer.close()

            val remaining = withTimeout(30.seconds) { channel.receive().toList() }
            assertTrue(remaining.isEmpty(), "the client's channel closed on the peer's reset")
            awaitTrue { client.recycledStreamIds == listOf(StreamId(0)) }
            assertTrue(
                server.recycledStreamIds.isEmpty(),
                "an even id belongs to the client's half of the stream space — the server must not claim it",
            )
        }

    @Test
    fun a_second_close_of_the_same_channel_is_a_no_op() =
        runTest {
            val (client, server) = connectedPair(61)
            val channel = client.open(DataChannelConfig(label = "double"))
            server.acceptBidirectional()

            channel.close()
            channel.close()
            awaitTrue { client.recycledStreamIds == listOf(StreamId(0)) }

            // A duplicate close must not put a second reset request on the wire for an id already
            // recycled — which would reset a stream the NEXT channel is about to be opened on.
            val next = client.open(DataChannelConfig(label = "next"))
            val peerNext = server.acceptBidirectional()
            next.send(textBuffer("intact"))
            assertEquals("intact", peerNext.receive().first().text())
        }
}

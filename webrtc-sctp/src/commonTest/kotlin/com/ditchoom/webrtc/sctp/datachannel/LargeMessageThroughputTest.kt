@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.association.ReceiveMessageLimit
import com.ditchoom.webrtc.sctp.association.SctpConfig
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

private val EPOCH = Instant.fromEpochSeconds(0)

/**
 * Messages large enough to matter, sent back to back.
 *
 * The L2 `jvm-native` semantics lane sends **192 KiB** and expects it echoed. Nothing in the L1 corpus
 * carried a message anywhere near that size — the largest was a few KiB — so an entire class of defect
 * was reachable only from Docker: anything that accumulates per message, or per fragment, and is not
 * given back. A 192 KiB message is ~164 fragments at the default 1200-byte ceiling, which is where
 * per-fragment accounting errors stop rounding to zero.
 *
 * The second message is the load-bearing half. A receive window that is charged and never credited still
 * delivers the *first* message of any size that fits — it only stalls afterwards, which is precisely the
 * shape the L2 lane reported: `s1` timed out and every later phase then failed with "the association is
 * not delivering". One message proves nothing here; the sequence does.
 */
class LargeMessageThroughputTest {
    private fun TestScope.clock(): () -> Instant = { EPOCH + testScheduler.currentTime.milliseconds }

    private fun payload(size: Int): ReadBuffer {
        val buffer = BufferFactory.managed().allocate(size, ByteOrder.BIG_ENDIAN)
        for (i in 0 until size) buffer.writeByte((i and 0xFF).toByte())
        buffer.resetForRead()
        buffer.setLimit(size)
        return buffer
    }

    private fun ReadBuffer.checksum(): Int {
        var sum = 0
        for (i in position() until limit()) sum = (sum * 31 + (get(i).toInt() and 0xFF)) and 0x7FFFFFFF
        return sum
    }

    @Test
    fun a_192_kib_message_round_trips_and_so_does_the_one_after_it() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, random = Random(1))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, random = Random(2))
            client.start()
            server.start()

            client.setPeerMessageLimit(PeerMessageLimit.Unlimited)
            val channel = client.open(DataChannelConfig(label = "large"))
            val incoming = withTimeout(30.seconds) { server.acceptBidirectional() }

            val size = 192 * 1024
            repeat(2) { round ->
                val sent = payload(size)
                val expected = sent.checksum()
                channel.send(DataChannelPayload.Binary(sent))

                val received =
                    withTimeout(30.seconds) { incoming.receive().first() }.expectBinary()
                assertEquals(
                    size,
                    received.remaining(),
                    "round $round: a $size-byte message must arrive whole",
                )
                assertEquals(
                    expected,
                    received.checksum(),
                    "round $round: the bytes must survive fragmentation and reassembly",
                )
            }
        }

    /**
     * The echo shape: a large message travelling **both ways at once**.
     *
     * The unidirectional fixture above passes, and the L2 lane still failed — because an echo is not one
     * transfer, it is two overlapping ones. Each endpoint is simultaneously charging its own receive
     * window for the message arriving and filling its send queue with the message leaving, and the credit
     * that would reopen the first is only returned once the application has finished with it. That is the
     * classic shape for a credit deadlock, and it is invisible to any fixture that sends in one direction.
     */
    @Test
    fun a_large_message_crossing_in_both_directions_does_not_deadlock() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, random = Random(1))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, random = Random(2))
            client.start()
            server.start()
            client.setPeerMessageLimit(PeerMessageLimit.Unlimited)
            server.setPeerMessageLimit(PeerMessageLimit.Unlimited)

            val outbound = client.open(DataChannelConfig(label = "echo"))
            val inbound = withTimeout(30.seconds) { server.acceptBidirectional() }

            val size = 256 * 1024
            outbound.send(DataChannelPayload.Binary(payload(size)))

            // The reflector's shape: receive it whole, then send it straight back.
            val atServer = withTimeout(60.seconds) { inbound.receive().first() }.expectBinary()
            assertEquals(size, atServer.remaining(), "the reflector must receive the whole message")
            inbound.send(DataChannelPayload.Binary(payload(size)))

            val echoed = withTimeout(60.seconds) { outbound.receive().first() }.expectBinary()
            assertEquals(size, echoed.remaining(), "the echo must come back — this is where the L2 lane stalled")
        }

    /**
     * A message of **exactly** the advertised ceiling, which is the one size an endpoint has promised to
     * accept and therefore the one it must not refuse.
     *
     * This is the L2 `jvm-native` lane's boundary probe, brought down to L1. Both peers there advertise
     * 262144 and echo 192 KiB happily, and the run fails only on a message at exactly 262144 — with every
     * later phase then reporting "the association is not delivering", which is what an ABORT looks like
     * from the far side. A ceiling that refuses the value it names is worse than a lower ceiling honestly
     * advertised: the peer is doing precisely what was asked of it.
     */
    @Test
    fun a_message_at_exactly_the_advertised_ceiling_is_accepted() =
        runTest {
            val ceiling = ReceiveMessageLimit.Default
            val limitBytes = (ceiling as ReceiveMessageLimit.Bytes).value.toInt()
            val config = SctpConfig(receiveMessageLimit = ceiling)

            val pair = MemoryTransportPair(backgroundScope)
            val client =
                SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, config, random = Random(1))
            val server =
                SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, config, random = Random(2))
            client.start()
            server.start()
            client.setPeerMessageLimit(PeerMessageLimit.Unlimited)

            val channel = client.open(DataChannelConfig(label = "boundary"))
            val incoming = withTimeout(30.seconds) { server.acceptBidirectional() }

            channel.send(DataChannelPayload.Binary(payload(limitBytes)))

            val received = withTimeout(60.seconds) { incoming.receive().first() }.expectBinary()
            assertEquals(
                limitBytes,
                received.remaining(),
                "a message at exactly the ceiling this endpoint advertises must be delivered, not aborted",
            )
        }
}

@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.SctpDecodeResult
import com.ditchoom.webrtc.sctp.SctpPacket
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
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

/** One outbound DATA chunk as the peer would see it on the wire. */
private data class SentData(
    val streamId: Int,
    val ppid: PayloadProtocolId,
    val unordered: Boolean,
)

/**
 * A transport decorator that decodes every datagram the stack sends and records its DATA chunks. The
 * assertion here is about the WIRE, not about what the two stacks agree on — our own receiver tolerates
 * a payload arriving ahead of its DCEP OPEN (see pendingInbound), so a peer-to-peer test could never
 * catch this. The bug is only visible to a peer that reads the first message on a new stream as
 * necessarily DCEP.
 */
private class WireTap(
    private val delegate: SctpDatagramTransport,
) : SctpDatagramTransport {
    val sent = mutableListOf<SentData>()

    override suspend fun send(packet: ReadBuffer) {
        val view = packet.slice()
        view.position(0)
        when (val decoded = SctpPacket.decode(view)) {
            is SctpDecodeResult.Success ->
                decoded.packet.chunks.filterIsInstance<SctpChunk.Data>().forEach {
                    sent += SentData(it.streamId.value, it.payloadProtocolId, it.flags.unordered)
                }
            is SctpDecodeResult.Reject -> Unit // not our concern here; the codec suite covers rejects
        }
        delegate.send(packet)
    }

    override suspend fun receive(): ReadBuffer? = delegate.receive()

    override fun close() = delegate.close()
}

/**
 * RFC 8832 §6: "before the DATA_CHANNEL_ACK message or any other message has been received on a data
 * channel, all other messages containing user data and belonging to this data channel MUST be sent
 * ordered, no matter whether the data channel is ordered or not."
 *
 * Found at interop: an unordered first payload can be delivered AHEAD of the (ordered) DCEP OPEN, and a
 * peer that requires the first message on a new stream to be DCEP rejects it. Pion does, and its accept
 * loop terminates on the error — so a single unordered channel silently killed every channel opened
 * after it on the same association.
 */
class DcepOrderedBeforeAckTest {
    private fun TestScope.clock(): () -> Instant = { EPOCH + testScheduler.currentTime.milliseconds }

    @Test
    fun user_data_on_an_unordered_channel_is_sent_ordered_until_the_channel_is_confirmed() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val tap = WireTap(pair.clientTransport)
            val client = SctpDataChannelStack(tap, backgroundScope, clock(), SctpRole.Client, random = Random(1))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, random = Random(2))
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "unordered", ordered = false))
            val streamId = (channel as DataChannelConnection).streamId.value
            channel.send(textBuffer("first"))

            val incoming = server.acceptBidirectional()
            assertEquals("first", incoming.receive().first().let { buf -> buf.readString(buf.remaining()) })

            val onStream = tap.sent.filter { it.streamId == streamId }
            val dcep = onStream.filter { it.ppid == PayloadProtocolId.WebRtcDcep }
            val userData = onStream.filter { it.ppid != PayloadProtocolId.WebRtcDcep }

            assertTrue(dcep.isNotEmpty(), "the DCEP OPEN must reach the wire")
            assertTrue(userData.isNotEmpty(), "the user message must reach the wire")
            assertEquals(
                listOf(false),
                dcep.map { it.unordered }.distinct(),
                "RFC 8832 §6: all DCEP messages are sent ordered",
            )
            assertEquals(
                listOf(false),
                userData.map { it.unordered }.distinct(),
                "RFC 8832 §6: user data on an unconfirmed channel is sent ordered even though the channel is unordered",
            )
            // The OPEN must also be FIRST on the stream — ordered delivery only helps if it was sent first.
            assertEquals(
                PayloadProtocolId.WebRtcDcep,
                onStream.first().ppid,
                "the DCEP OPEN precedes any user data on the stream",
            )

            client.shutdown()
        }

    @Test
    fun the_channels_real_unordered_setting_takes_effect_once_the_peer_has_answered() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val tap = WireTap(pair.clientTransport)
            val client = SctpDataChannelStack(tap, backgroundScope, clock(), SctpRole.Client, random = Random(3))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, random = Random(4))
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "unordered", ordered = false))
            val streamId = (channel as DataChannelConnection).streamId.value

            // Let the server's DATA_CHANNEL_ACK land before sending anything: the channel is now confirmed,
            // so the configured unordered delivery must apply. acceptBidirectional() returning means the
            // server processed the OPEN and therefore emitted the ACK; a round trip of user data pins it.
            val incoming = server.acceptBidirectional()
            incoming.send(textBuffer("ack-and-hello"))
            channel.receive().first()

            tap.sent.clear()
            channel.send(textBuffer("now-unordered"))
            assertEquals("now-unordered", incoming.receive().first().let { buf -> buf.readString(buf.remaining()) })

            val userData = tap.sent.filter { it.streamId == streamId && it.ppid != PayloadProtocolId.WebRtcDcep }
            assertTrue(userData.isNotEmpty(), "the user message must reach the wire")
            assertEquals(
                listOf(true),
                userData.map { it.unordered }.distinct(),
                "once confirmed, an unordered channel sends unordered — the RFC 8832 §6 clamp is not permanent",
            )

            client.shutdown()
        }

    @Test
    fun an_ordered_channel_is_unaffected() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val tap = WireTap(pair.clientTransport)
            val client = SctpDataChannelStack(tap, backgroundScope, clock(), SctpRole.Client, random = Random(5))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, random = Random(6))
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "ordered"))
            channel.send(textBuffer("hello"))
            val incoming = server.acceptBidirectional()
            assertEquals("hello", incoming.receive().first().let { buf -> buf.readString(buf.remaining()) })

            assertTrue(
                tap.sent.none { it.unordered },
                "an ordered channel never sets the U bit, before or after confirmation",
            )

            client.shutdown()
        }
}

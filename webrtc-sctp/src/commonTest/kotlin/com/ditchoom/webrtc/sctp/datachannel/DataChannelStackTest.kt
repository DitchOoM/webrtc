@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.association.SctpReliability
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
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

// These fixtures ship readable bytes as BINARY messages, so `text()` on a payload asserts that variant
// first — a Text message reaching here means the PPID mapping changed and the fixture should say so.
private fun DataChannelPayload.text(): String = expectBinary().text()

class DataChannelStackTest {
    private fun TestScope.clock(): () -> Instant = { EPOCH + testScheduler.currentTime.milliseconds }

    @Test
    fun channel_opens_and_messages_flow_client_to_server() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, random = Random(1))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, random = Random(2))
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "chat"))
            val incoming = server.acceptBidirectional()
            assertEquals("chat", (incoming as DataChannelConnection).config.label, "label survives DCEP OPEN")

            channel.send(textBuffer("hello"))
            channel.send(textBuffer("world"))
            val received =
                incoming
                    .receive()
                    .take(2)
                    .toList()
                    .map { it.text() }
            assertEquals(listOf("hello", "world"), received)

            client.shutdown()
        }

    @Test
    fun bidirectional_data_channel() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, random = Random(3))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, random = Random(4))
            client.start()
            server.start()

            val clientChannel = client.open(DataChannelConfig(label = "duplex"))
            val serverChannel = server.acceptBidirectional()

            clientChannel.send(textBuffer("ping"))
            assertEquals("ping", serverChannel.receive().first().text())
            serverChannel.send(textBuffer("pong"))
            assertEquals("pong", clientChannel.receive().first().text())
        }

    @Test
    fun unreliable_channel_over_lossy_transport_stays_alive() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope, lossRate = 0.3, delay = 10.milliseconds, seed = 5)
            val config = SctpConfig()
            val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, config, Random(6))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, config, Random(7))
            client.start()
            server.start()

            // Reliable channel: every message must arrive despite 30% loss (the retransmit path end-to-end).
            val channel = client.open(DataChannelConfig(label = "reliable", reliability = SctpReliability.Reliable))
            val incoming = server.acceptBidirectional()

            val n = 15
            for (i in 0 until n) channel.send(textBuffer("m$i"))
            val received =
                incoming
                    .receive()
                    .take(n)
                    .toList()
                    .map { it.text() }
            assertEquals((0 until n).map { "m$it" }, received, "reliable channel delivers all, in order, through loss")
        }

    @Test
    fun open_after_transport_close_fails_fast_not_hangs() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, random = Random(10))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, random = Random(11))
            client.start()
            server.start()
            client.open(DataChannelConfig(label = "live")) // establish
            server.acceptBidirectional()

            // The transport dies (peer socket gone): the client's reader sees EOF → the stack tears down.
            pair.serverTransport.close()
            kotlinx.coroutines.delay(2.seconds) // virtual time: let the reader see EOF and the drive loop tear down
            assertEquals(true, client.isTornDown, "stack tore down after transport close (server=${server.isTornDown})")

            // R4-F2: a subsequent open() must throw the typed close exception, not suspend forever.
            val thrown =
                try {
                    withTimeout(30.seconds) { client.open(DataChannelConfig(label = "too-late")) }
                    null
                } catch (e: Throwable) {
                    e
                }
            assertEquals(
                SctpClosedException::class,
                thrown?.let { it::class },
                "open after teardown throws SctpClosedException, got $thrown",
            )
        }

    /**
     * A datagram that arrives AFTER the stack has torn down must not crash the process.
     *
     * The reader loop enqueues every inbound datagram onto the drive loop's inbox, and a teardown the
     * reader did not initiate (an association ABORT, or the far side's transport dying mid-read) closes
     * that inbox under it — so the next `send` throws `ClosedSendChannelException`. On Kotlin/Native an
     * uncaught throw in that launched coroutine takes the whole PROCESS down: the L2 interop harness saw
     * the answerer exit **rc=139** at teardown, with every data-channel semantics phase already green.
     *
     * Reproduced deterministically here: a client whose INIT is never answered aborts after its retransmit
     * budget (virtual time), which tears the stack down while the reader is still blocked on the transport;
     * a straggler datagram then arrives on the still-open receive path. `backgroundScope` reports an
     * uncaught child exception as a test failure, so this test fails without the fail-quiet guard.
     */
    @Test
    fun datagram_arriving_after_teardown_does_not_crash_the_reader() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val client =
                SctpDataChannelStack(
                    pair.clientTransport,
                    backgroundScope,
                    clock(),
                    SctpRole.Client,
                    // Nobody answers the INIT, so the association exhausts this budget and aborts —
                    // teardown arrives from the DRIVE loop, not from the reader.
                    SctpConfig(rtoInitial = 100.milliseconds, rtoMin = 100.milliseconds, maxInitRetransmits = 1),
                    Random(12),
                )
            client.start()
            kotlinx.coroutines.delay(10.seconds) // virtual time: let the INIT budget run out
            assertEquals(true, client.isTornDown, "an unanswered INIT aborts the association and tears the stack down")

            // The far side is still able to put a datagram on the wire (its send channel was never closed —
            // exactly the real case: the socket is torn down locally while packets are still in flight).
            pair.serverTransport.send(textBuffer("straggler"))
            kotlinx.coroutines.delay(1.seconds)
            assertEquals(true, client.isTornDown, "the stack stays torn down and the straggler is dropped, not fatal")
        }

    @Test
    fun empty_message_round_trips() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, random = Random(8))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, random = Random(9))
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "empty"))
            val incoming = server.acceptBidirectional()
            channel.send(BufferFactory.managed().allocate(0, ByteOrder.BIG_ENDIAN))
            channel.send(textBuffer("after"))

            val received = incoming.receive().take(2).toList()
            assertEquals(0, received[0].expectBinary().remaining(), "empty application message delivered as empty (RFC 8831 §6.6)")
            assertEquals("after", received[1].text())
        }
}

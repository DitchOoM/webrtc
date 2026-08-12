@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.LeakTrackingFactory
import com.ditchoom.webrtc.sctp.association.SctpAssociationState
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.association.SctpReliability
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **The SCTP send seam gives every buffer back.**
 *
 * A tracker on `SctpConfig.bufferFactory` and nothing else under it — no DTLS record layer, no ICE — so a
 * number this reports belongs to SCTP and cannot be attributed anywhere else. One tracker per peer, since
 * a shared one would let the client's discipline mask the server's.
 *
 * ## What it is actually measuring
 *
 * The seam allocates in four places, and the interesting thing is that they do not share one owner:
 *
 * - **Control packets** — encoded per transmission and retained by nobody, so the driver frees them
 *   (`SctpOutput.Transmit.Owned`).
 * - **DATA packets** — retained by the retransmission queue so a retransmit re-emits the same bytes, and
 *   handed to the driver as *views* (`SctpOutput.Transmit.Retained`). Every transmission is one more
 *   reference on a pooled chunk; the driver balances each, and the bytes themselves come back as
 *   `SctpOutput.ReclaimRetained` on ack or abandon.
 * - **Reassembly copies** — fragments copied out of the borrowed datagram, joined into the message the
 *   application receives. Delivered ones are the application's (this fixture releases them, as a consumer
 *   must); the ones a stream reset or FORWARD-TSN strands are the queue's.
 * - **The handshake artifacts** — the State Cookie the responder encodes, and the copy of it the
 *   initiator retains inside its COOKIE ECHO for handshake retransmits.
 *
 * `assertNoLeaks` runs first because it names *which* buffer; if it passes and `assertPoolDrained` fails,
 * the cause is an unreleased slice — a transmission view — rather than a missing free.
 */
class SctpSendSeamOwnershipTest {
    private val epoch = Instant.fromEpochSeconds(0)

    private fun TestScope.clock(): () -> Instant = { epoch + testScheduler.currentTime.milliseconds }

    // Advance virtual time until [condition] holds. The timeout is a watchdog, never a budget the
    // assertion depends on (directive #4).
    private suspend fun awaitTrue(
        timeout: Duration = 120.seconds,
        condition: () -> Boolean,
    ) = withTimeout(timeout) {
        while (!condition()) delay(1.milliseconds)
    }

    private class Peers(
        val client: SctpDataChannelStack,
        val server: SctpDataChannelStack,
        val transports: MemoryTransportPair,
    )

    private fun TestScope.peers(
        clientSctp: LeakTrackingFactory,
        serverSctp: LeakTrackingFactory,
        seed: Long,
        lossRate: Double = 0.0,
        delay: Duration = Duration.ZERO,
    ): Peers {
        val transports = MemoryTransportPair(backgroundScope, lossRate, delay, seed = seed)
        val client =
            SctpDataChannelStack(
                transports.clientTransport,
                backgroundScope,
                clock(),
                SctpRole.Client,
                SctpConfig(bufferFactory = clientSctp),
                Random(seed),
            )
        val server =
            SctpDataChannelStack(
                transports.serverTransport,
                backgroundScope,
                clock(),
                SctpRole.Server,
                SctpConfig(bufferFactory = serverSctp),
                Random(seed + 1),
            )
        client.start()
        server.start()
        return Peers(client, server, transports)
    }

    @Test
    fun a_clean_session_returns_every_sctp_buffer() =
        runTest {
            val clientSctp = LeakTrackingFactory()
            val serverSctp = LeakTrackingFactory()
            val p = peers(clientSctp, serverSctp, seed = 1)
            val client = p.client
            val server = p.server

            val channel = client.open(DataChannelConfig(label = "seams"))
            val peer = server.acceptBidirectional()
            channel.send(textBuffer("ping"))
            assertEquals("ping", peer.receive().first().consumeText())
            peer.send(textBuffer("pong"))
            assertEquals("pong", channel.receive().first().consumeText())

            // A fragmented message too: the multi-fragment path is the only one that allocates a join
            // buffer AND has fragment copies to release, and those are a different owner from either.
            val long = "x".repeat(SctpConfig().maxPayloadBytes * 3)
            channel.send(textBuffer(long))
            assertEquals(long, peer.receive().first().consumeText())

            // An empty message rides RFC 8831 §6.6's single 0x00 marker byte, which is a buffer at both
            // ends that no application ever sees — the sender's marker and the receiver's reassembly copy
            // of it, which delivery replaces with EMPTY_BUFFER. Nothing but the stack can free either.
            channel.send(ReadBuffer.EMPTY_BUFFER)
            assertEquals("", peer.receive().first().consumeText())

            // Closing one channel is an RFC 6525 reset in both directions — the DCEP-free close path, and
            // the one that empties `pendingInbound` and the reassembly queue's per-stream state.
            channel.close()
            awaitTrue { client.recycledStreamIds.isNotEmpty() }

            shutDown(client, server, p.transports)

            clientSctp.assertNoLeaks("the client's SCTP seam")
            clientSctp.assertPoolDrained("the client's SCTP seam")
            serverSctp.assertNoLeaks("the server's SCTP seam")
            serverSctp.assertPoolDrained("the server's SCTP seam")
        }

    /**
     * The same standard with the reliability machinery actually running. Loss forces retransmits — each
     * one a **second, third, …** view of a packet the queue already owns, which is precisely the shape
     * `assertNoLeaks` cannot see and `assertPoolDrained` can — and the unreliable channel drives RFC 3758
     * abandonment, whose FORWARD-TSN purge is a third removal site with an owner of its own.
     */
    @Test
    fun a_lossy_session_returns_every_sctp_buffer() =
        runTest {
            val clientSctp = LeakTrackingFactory()
            val serverSctp = LeakTrackingFactory()
            val p = peers(clientSctp, serverSctp, seed = 9, lossRate = 0.3, delay = 10.milliseconds)

            val reliable = p.client.open(DataChannelConfig(label = "reliable"))
            val unreliable =
                p.client.open(DataChannelConfig(label = "unreliable", reliability = SctpReliability.MaxRetransmits(0)))
            val delivered = ArrayList<String>()
            collectInto(p.server.acceptBidirectional(), delivered)
            collectInto(p.server.acceptBidirectional(), delivered)

            repeat(MESSAGES) { i ->
                reliable.send(textBuffer("reliable-$i"))
                unreliable.send(textBuffer("unreliable-$i"))
            }
            // Only the reliable channel is awaited: an abandoned message is *supposed* to go missing, so
            // asserting on the unreliable one's arrivals would be asserting on the loss model. What matters
            // is that both paths gave their buffers back — and the reliable stream reaching the end is what
            // proves the association stayed alive long enough for that to mean anything.
            awaitTrue { delivered.count { it.startsWith("reliable-") } == MESSAGES }

            // Torn down by losing the transport rather than by RFC 4960 §9.2 — which is how a lossy
            // session actually ends, and which leaves the queues non-empty on purpose. The graceful path
            // is the clean fixture's job; making this one wait for a SHUTDOWN exchange to survive 30% loss
            // would be testing the shutdown timer, not the ownership.
            p.transports.cutWire()
            awaitTrue { p.client.isTornDown && p.server.isTornDown }
            testScheduler.advanceUntilIdle()

            clientSctp.assertNoLeaks("the lossy client's SCTP seam")
            clientSctp.assertPoolDrained("the lossy client's SCTP seam")
            serverSctp.assertNoLeaks("the lossy server's SCTP seam")
            serverSctp.assertPoolDrained("the lossy server's SCTP seam")
        }

    /**
     * Teardown with the queues **not** empty: the transport dies while data is outstanding, so nothing is
     * acked, nothing is abandoned, and every removal site this fixture's siblings exercise is skipped.
     * What has to give the memory back instead is the association's own `close()` — the path that exists
     * because a session ending badly is a normal way for a session to end.
     */
    @Test
    fun a_session_torn_down_mid_flight_returns_what_the_association_still_held() =
        runTest {
            val clientSctp = LeakTrackingFactory()
            val serverSctp = LeakTrackingFactory()
            val p = peers(clientSctp, serverSctp, seed = 5)

            val channel = p.client.open(DataChannelConfig(label = "midflight"))
            val peer = p.server.acceptBidirectional()
            channel.send(textBuffer("established"))
            assertEquals("established", peer.receive().first().consumeText())

            // Cut the wire first, THEN send: the DATA is encoded and queued but can never be acked, so it
            // is still in the retransmission queue when the association is closed.
            p.transports.cutWire()
            launch { runCatching { channel.send(textBuffer("never-arrives")) } }
            awaitTrue { p.client.isTornDown && p.server.isTornDown }
            testScheduler.advanceUntilIdle()

            clientSctp.assertNoLeaks("the mid-flight client's SCTP seam")
            clientSctp.assertPoolDrained("the mid-flight client's SCTP seam")
            serverSctp.assertNoLeaks("the mid-flight server's SCTP seam")
            serverSctp.assertPoolDrained("the mid-flight server's SCTP seam")
        }

    // Graceful shutdown (RFC 4960 §9.2), then cut the transport so both stacks reach tearDown — the
    // association returning to Closed frees the TCB, but only tearDown drains the driver's own queues.
    // `advanceUntilIdle` is what lets the writer coroutine finish that drain before anything is counted:
    // the release is deliberately the writer's, so an assertion that ran ahead of it would be measuring a
    // half-finished teardown and blaming the code for it.
    private suspend fun TestScope.shutDown(
        client: SctpDataChannelStack,
        server: SctpDataChannelStack,
        transports: MemoryTransportPair,
    ) {
        client.shutdown()
        awaitTrue {
            client.state.value == SctpAssociationState.Closed && server.state.value == SctpAssociationState.Closed
        }
        transports.cutWire()
        awaitTrue { client.isTornDown && server.isTornDown }
        testScheduler.advanceUntilIdle()
    }

    // A background collector rather than `first()`: the unreliable channel has no message count to wait
    // for, so anything that suspends per message would hang on the ones that were correctly abandoned.
    private fun TestScope.collectInto(
        connection: Connection<DataChannelPayload>,
        into: MutableList<String>,
    ) {
        backgroundScope.launch { connection.receive().collect { into += it.consumeText() } }
    }

    private fun textBuffer(s: String): ReadBuffer {
        val bytes = s.encodeToByteArray()
        val buf = BufferFactory.managed().allocate(maxOf(1, bytes.size), ByteOrder.BIG_ENDIAN)
        for (b in bytes) buf.writeByte(b)
        buf.resetForRead()
        buf.setLimit(bytes.size)
        return buf
    }

    // Read a delivered message and release it. A consumer owns what `receive()` hands it (see
    // DataChannelConnection.receive) — including a fixture, which is the only reason these numbers can
    // reach zero. Reading and releasing in one helper is deliberate: a test that forgot the release would
    // report a leak that was its own.
    // Reads a received message and discharges its ownership in one step — the payload's `release()` is
    // now what hands the reassembly buffer back, so this fixture exercises that contract rather than
    // freeing a buffer it reached around the type to obtain.
    private fun DataChannelPayload.consumeText(): String {
        val out = StringBuilder()
        val buffer = expectBinary()
        for (i in buffer.position() until buffer.limit()) out.append((buffer.get(i).toInt() and 0xFF).toChar())
        release()
        return out.toString()
    }

    private companion object {
        private const val MESSAGES = 12
    }
}

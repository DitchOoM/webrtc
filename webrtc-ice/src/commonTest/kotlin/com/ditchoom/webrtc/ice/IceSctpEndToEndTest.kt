@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.sctp.association.SctpReliability
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConnection
import com.ditchoom.webrtc.sctp.datachannel.SctpDataChannelStack
import com.ditchoom.webrtc.sctp.datachannel.SctpRole
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

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
 * The **W5 composition proof**: the real sans-io [SctpDataChannelStack] runs over the actual W3
 * [IceAgent]'s nominated pair, across the vnet, entirely under `runTest` virtual time. This is the
 * ICE⇄SCTP seam — two peers establish ICE, then a DTLS-shaped plaintext transport ([IceDriver.sctpTransport])
 * carries a full SCTP association + DCEP + DataChannel, and data-channel messages cross end to end.
 * (The full ICE+**DTLS**+SCTP stack is W6's job once W4 lands; here DTLS is the plaintext stand-in.)
 */
@OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)
class IceSctpEndToEndTest {
    private val timeout = 60.seconds

    @Test
    fun data_channel_messages_flow_over_ice_and_sctp() =
        runTest {
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 11, vnet = vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 12, vnet = vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()
            alice.bindHost("10.0.0.1", 4000)
            bob.bindHost("10.0.0.2", 5000)
            alice.connectTo(bob)
            bob.connectTo(alice)
            assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice ICE connected")
            assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob ICE connected")

            // ICE is up; layer the SCTP data-channel stack over the nominated pair (DTLS slots in here at W4).
            val client = SctpDataChannelStack(alice.sctpTransport(), backgroundScope, clock, SctpRole.Client, random = Random(21))
            val server = SctpDataChannelStack(bob.sctpTransport(), backgroundScope, clock, SctpRole.Server, random = Random(22))
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "over-ice"))
            val incoming = withTimeoutOrNull(timeout) { server.acceptBidirectional() }
            assertEquals("over-ice", (incoming as DataChannelConnection).config.label)

            channel.send(textBuffer("ice+sctp"))
            channel.send(textBuffer("works"))
            val received =
                withTimeoutOrNull(timeout) {
                    incoming
                        .receive()
                        .take(2)
                        .toList()
                        .map { it.text() }
                }
            assertEquals(listOf("ice+sctp", "works"), received)

            // Reply on the same channel — proves the bidirectional path over ICE.
            incoming.send(textBuffer("ack"))
            assertEquals("ack", withTimeoutOrNull(timeout) { channel.receive().first().text() })
        }

    @Test
    fun unreliable_channel_over_ice() =
        runTest {
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 31, vnet = vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 32, vnet = vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()
            alice.bindHost("10.0.1.1", 4000)
            bob.bindHost("10.0.1.2", 5000)
            alice.connectTo(bob)
            bob.connectTo(alice)
            assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice ICE connected")
            assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob ICE connected")

            val client = SctpDataChannelStack(alice.sctpTransport(), backgroundScope, clock, SctpRole.Client, random = Random(41))
            val server = SctpDataChannelStack(bob.sctpTransport(), backgroundScope, clock, SctpRole.Server, random = Random(42))
            client.start()
            server.start()

            val channel =
                client.open(DataChannelConfig(label = "unordered", ordered = false, reliability = SctpReliability.MaxRetransmits(2)))
            val incoming = withTimeoutOrNull(timeout) { server.acceptBidirectional() }!!

            channel.send(textBuffer("u0"))
            channel.send(textBuffer("u1"))
            val received =
                withTimeoutOrNull(timeout) {
                    incoming
                        .receive()
                        .take(2)
                        .toList()
                        .map { it.text() }
                        .toSet()
                }
            assertEquals(setOf("u0", "u1"), received)
        }
}

@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConnection
import com.ditchoom.webrtc.sctp.datachannel.SctpDataChannelStack
import com.ditchoom.webrtc.sctp.datachannel.SctpDatagramTransport
import com.ditchoom.webrtc.sctp.datachannel.SctpRole
import kotlinx.coroutines.CoroutineScope
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
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Proves the **production** [IceAgentDriver] (webrtc-ice `commonMain`) — the promoted W5 composition —
 * establishes ICE over a [DatagramBinder] and carries a real [SctpDataChannelStack] over its
 * [IceAgentDriver.appDataTransport], entirely under `runTest` virtual time. This is the transport
 * `PeerConnection` (W6) composes; the existing `IceDriver`/`IceSctpEndToEndTest` prove the same wiring
 * with the test harness, and this proves the code that actually ships.
 */
class IceAgentDriverTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    // Adapt the ice-layer app-data seam to the sctp-layer transport interface (identical shapes; the
    // webrtc root owns this adapter in production — here it is inline so the ice module stays sctp-free).
    private fun com.ditchoom.webrtc.ice.IceDataTransport.asSctpTransport(): SctpDatagramTransport =
        object : SctpDatagramTransport {
            override suspend fun send(packet: ReadBuffer) = this@asSctpTransport.send(packet)

            override suspend fun receive(): ReadBuffer? = this@asSctpTransport.receive()

            override fun close() = this@asSctpTransport.close()
        }

    @Test
    fun ice_agent_driver_carries_a_data_channel_end_to_end() =
        runTest {
            val vnet = Vnets.flat()
            val binder = DatagramBinder { vnet.bind(it) }
            val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
            val alice = driver(IceRole.Controlling, seed = 101, binder, backgroundScope, clock)
            val bob = driver(IceRole.Controlled, seed = 102, binder, backgroundScope, clock)
            alice.start()
            bob.start()
            alice.gatherHost("10.0.0.1", 4000)
            bob.gatherHost("10.0.0.2", 5000)
            connect(alice, bob)
            connect(bob, alice)
            assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice ICE connected")
            assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob ICE connected")

            val client =
                SctpDataChannelStack(
                    alice.appDataTransport().asSctpTransport(),
                    backgroundScope,
                    clock,
                    SctpRole.Client,
                    random = Random(201),
                )
            val server =
                SctpDataChannelStack(
                    bob.appDataTransport().asSctpTransport(),
                    backgroundScope,
                    clock,
                    SctpRole.Server,
                    random = Random(202),
                )
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "prod-transport"))
            val incoming = withTimeoutOrNull(timeout) { server.acceptBidirectional() } as DataChannelConnection?
            assertEquals("prod-transport", assertNotNull(incoming).config.label)

            channel.send(textBuffer("hello"))
            channel.send(textBuffer("world"))
            val received =
                withTimeoutOrNull(timeout) {
                    incoming
                        .receive()
                        .take(2)
                        .toList()
                        .map { it.text() }
                }
            assertEquals(listOf("hello", "world"), received)

            incoming.send(textBuffer("ack"))
            assertEquals("ack", withTimeoutOrNull(timeout) { channel.receive().first().text() })
        }

    private fun driver(
        role: IceRole,
        seed: Long,
        binder: DatagramBinder,
        scope: CoroutineScope,
        clock: () -> Instant,
    ): IceAgentDriver = IceAgentDriver(role, Random(seed), binder, scope, clock)

    // Scripted signaling: hand [from]'s credentials + candidates to [to] (the trickle seam, direct).
    private fun connect(
        to: IceAgentDriver,
        from: IceAgentDriver,
    ) {
        to.setRemoteCredentials(from.localCredentials)
        from.localCandidates.forEach { to.addRemoteCandidate(it) }
    }

    private suspend fun IceAgentDriver.awaitConnected(): IceConnectionState =
        state.first {
            when (it) {
                is IceConnectionState.Connected, is IceConnectionState.Completed -> true
                is IceConnectionState.Failed -> error("expected a connection, but ICE failed: ${it.reason}")
                else -> false
            }
        }

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
}

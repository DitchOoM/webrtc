package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.vnet.CountingBufferFactory
import com.ditchoom.webrtc.ice.vnet.Vnet
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * **The W3 seam gate** (HANDOFF.md → EXECUTION_PLAN W3): before a line of ICE is written, prove that
 * two peers exchange datagrams over the in-memory [Vnet] — the buffer-flow [DatagramChannel] seam that
 * production rides via `socket-udp` — entirely under `runTest` **virtual time**, on every platform.
 *
 * This is the whole determinism thesis in miniature: no OS sockets, no wall-clock, no dispatcher; the
 * echo completes at zero simulated time and replays identically forever. The ICE agent, DTLS, and SCTP
 * all plug into this same [DatagramChannel] with no code change from production.
 *
 * Assertion discipline (standing directive #4): observable state + the `runTest` watchdog, never a
 * wall-clock budget. A hang (a lost datagram, a mis-keyed route) trips `runTest`'s timeout rather than
 * passing by luck.
 */
@OptIn(ExperimentalDatagramApi::class)
class VnetDatagramSeamTest {
    private val alice: SocketAddress = vnetAddress("10.0.0.1", 4000)
    private val bob: SocketAddress = vnetAddress("10.0.0.2", 5000)

    @Test
    fun two_peer_echo_over_vnet_under_virtual_time() =
        runTest {
            val factory = CountingBufferFactory(BufferFactory.Default)
            val vnet = Vnet(bufferFactory = factory)
            val aliceCh = vnet.bind(alice)
            val bobCh = vnet.bind(bob)

            // Bob echoes exactly one datagram straight back to whoever sent it, then stops.
            val bobJob =
                launch {
                    when (val r = bobCh.receive()) {
                        is DatagramReadResult.Received -> {
                            val d = r.datagram
                            bobCh.send(d.payload, to = d.peer)
                        }
                        is DatagramReadResult.Closed -> error("bob's channel closed before receiving")
                    }
                }

            aliceCh.send(payloadOf("ping over the vnet"), to = bob)

            val echo = aliceCh.receive()
            assertTrue(echo is DatagramReadResult.Received, "alice received no echo")
            val d = echo.datagram
            assertEquals("ping over the vnet", d.payload.readUtf8(), "echoed payload corrupted")
            assertEquals(bob, d.peer, "per-packet source address must be bob's local address")

            bobJob.join()
            aliceCh.close()
            bobCh.close()

            // Copy-on-send accounting: exactly two deliveries (alice→bob, bob→alice) ⇒ two allocations.
            assertEquals(2, factory.allocations, "vnet must copy each delivered datagram exactly once")
        }

    @Test
    fun two_peer_echo_over_ipv6_vnet_under_virtual_time() =
        runTest {
            // The v6 seam gate: the vnet keying + copy-on-deliver path is family-agnostic (no production
            // dependency beyond ofLiteral). Bare RFC 5952 literals, one canonical spelling per endpoint.
            val factory = CountingBufferFactory(BufferFactory.Default)
            val vnet = Vnet(bufferFactory = factory)
            val aliceV6: SocketAddress = vnetAddress("2001:db8::1", 4000)
            val bobV6: SocketAddress = vnetAddress("2001:db8::2", 5000)
            val aliceCh = vnet.bind(aliceV6)
            val bobCh = vnet.bind(bobV6)

            val bobJob =
                launch {
                    when (val r = bobCh.receive()) {
                        is DatagramReadResult.Received -> bobCh.send(r.datagram.payload, to = r.datagram.peer)
                        is DatagramReadResult.Closed -> error("bob's channel closed before receiving")
                    }
                }

            aliceCh.send(payloadOf("ping over the v6 vnet"), to = bobV6)

            val echo = aliceCh.receive()
            assertTrue(echo is DatagramReadResult.Received, "alice received no echo over v6")
            assertEquals("ping over the v6 vnet", echo.datagram.payload.readUtf8(), "echoed v6 payload corrupted")
            assertEquals(bobV6, echo.datagram.peer, "per-packet source is bob's v6 local address")

            bobJob.join()
            aliceCh.close()
            bobCh.close()
            assertEquals(2, factory.allocations, "family-independent copy path: one allocation per delivery")
        }

    @Test
    fun datagram_to_unbound_address_is_silently_dropped() =
        runTest {
            val vnet = Vnet()
            val aliceCh = vnet.bind(alice)
            // Nothing is bound at `bob`; an unreliable send into the void must not throw or hang.
            aliceCh.send(payloadOf("into the void"), to = bob)
            assertTrue(aliceCh.isOpen, "sending to an unbound address must not disturb the sender")
            aliceCh.close()
        }

    @Test
    fun boundaries_are_preserved_one_send_one_datagram() =
        runTest {
            val vnet = Vnet()
            val aliceCh = vnet.bind(alice)
            val bobCh = vnet.bind(bob)

            aliceCh.send(payloadOf("first"), to = bob)
            aliceCh.send(payloadOf("second"), to = bob)

            assertEquals("first", receiveUtf8(bobCh), "datagram boundaries must not be concatenated")
            assertEquals("second", receiveUtf8(bobCh), "second datagram must arrive whole and in order")

            aliceCh.close()
            bobCh.close()
        }

    private fun payloadOf(text: String): ReadBuffer {
        val buf = BufferFactory.Default.allocate(text.length)
        buf.writeString(text, Charset.UTF8)
        buf.resetForRead()
        return buf
    }

    private fun ReadBuffer.readUtf8(): String = readString(remaining(), Charset.UTF8)

    @OptIn(ExperimentalDatagramApi::class)
    private suspend fun receiveUtf8(ch: DatagramChannel): String =
        when (val r = ch.receive()) {
            is DatagramReadResult.Received -> r.datagram.payload.readUtf8()
            is DatagramReadResult.Closed -> error("channel closed before a datagram arrived")
        }
}

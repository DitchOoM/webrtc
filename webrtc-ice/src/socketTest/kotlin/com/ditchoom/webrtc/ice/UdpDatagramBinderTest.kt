@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.deterministic
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.time.Duration.Companion.seconds

/**
 * [udpDatagramBinder] against a **real kernel, on more than one platform** — a datagram out and the same
 * datagram back, plus the ephemeral-port property gathering depends on.
 *
 * The multi-platform part is the point, and it is not symmetry for its own sake. There is one seam here
 * but **three implementations** behind it — NIO on the JVM/Android, io_uring `recvmsg` on Linux,
 * `NWConnection` on Apple — and they do not agree on what memory a received datagram may be written
 * into: the latter two require **raw native memory**, which `BufferFactory.Default` is not on those
 * targets. socket-udp resolves that per platform behind an `expect val`, and anything that overrides it
 * from `commonMain` breaks receive everywhere except the JVM.
 *
 * That is not a hypothetical either. The first draft of [udpDatagramBinder] took
 * `bufferFactory: BufferFactory = BufferFactory.Default` — a helpful-looking default that is correct on
 * the JVM and fatal on Linux and Apple. A JVM-only version of this test passed; the L2 harness went red
 * across every native lane, with host candidates present (they are synthesized from the bind address and
 * never received) and server-reflexive and relay candidates silently absent. **This test is the shape
 * that catches that class of defect, and running it on one platform is what fails to.**
 *
 * Real sockets, so real time and a real dispatcher: the watchdog is a `withTimeout` on observable state,
 * never a wall-clock budget (directive 4). socket-udp ships no wasm/browser actual and
 * [udpDatagramBinder] does not exist there, so there is nothing to run.
 */
class UdpDatagramBinderTest {
    @Test
    fun a_datagram_round_trips_through_a_binder_bound_socket() =
        runBlocking {
            withTimeout(WATCHDOG) {
                val net = BufferFactory.deterministic()
                val binder = udpDatagramBinder()
                val bob = binder.bind(SocketAddress.ofLiteral(LOOPBACK, 0))
                val alice = binder.bind(SocketAddress.ofLiteral(LOOPBACK, 0))
                try {
                    // Ephemeral binding is what a production gathering policy uses (a pinned port cannot
                    // be re-bound across an ICE restart), and `gatherHost` reads the port back off exactly
                    // this property to build the candidate — so a platform that mis-reports it publishes
                    // an unreachable candidate.
                    assertNotEquals(0, bob.localAddress.port, "a zero bind must report the port it received")
                    assertNotEquals(alice.localAddress.port, bob.localAddress.port, "two binds, two ports")

                    val echoing =
                        launch {
                            when (val received = bob.receive()) {
                                is DatagramReadResult.Received ->
                                    bob.send(received.datagram.payload, to = received.datagram.peer)
                                is DatagramReadResult.Closed -> error("bob's channel closed before receiving")
                            }
                        }

                    val payload = net.allocate(PAYLOAD.size)
                    for (byte in PAYLOAD) payload.writeByte(byte)
                    payload.resetForRead()
                    alice.send(payload, to = bob.localAddress)

                    val echo = alice.receive()
                    check(echo is DatagramReadResult.Received) { "alice received no echo" }
                    assertEquals(PAYLOAD.size, echo.datagram.payload.remaining(), "the echo came back whole")
                    for (expected in PAYLOAD) {
                        assertEquals(expected, echo.datagram.payload.readByte(), "payload corrupted over the seam")
                    }
                    echoing.join()
                } finally {
                    alice.close()
                    bob.close()
                }
            }
        }

    private companion object {
        private val WATCHDOG = 10.seconds
        private const val LOOPBACK = "127.0.0.1"
        private val PAYLOAD = listOf<Byte>(0x1f, 0x2e, 0x3d, 0x4c)
    }
}

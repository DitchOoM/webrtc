package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.socket.udp.UdpSocket
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds

/**
 * Resolution + parity smoke test for the **real** `socket-udp` actual (the production seam webrtc's
 * gathering drivers bind for host/srflx/relay candidates). It binds two loopback [UdpSocket] channels
 * and echoes a datagram between them over the *same* buffer-flow `DatagramChannel` interface the
 * virtual [com.ditchoom.webrtc.ice.vnet.Vnet] implements — so the ICE code that passes over the vnet
 * runs unchanged over a real socket. Its real job is to prove `socket-udp` (3.11.0, Maven Central)
 * **resolves** (KMP metadata + JVM actual) and honors the seam contract.
 *
 * JVM-only and **not** virtual-time: real sockets need a real dispatcher and real time, so this uses
 * `runBlocking` + `withTimeout` (the watchdog, directive #4), not `runTest`. socket-udp has no
 * wasm/browser target (RFC §1.1), so there is nothing to run there.
 */
@OptIn(ExperimentalDatagramApi::class)
class RealUdpSocketSeamTest {
    @Test
    fun real_loopback_udp_echo_over_the_datagram_seam() =
        runBlocking {
            withTimeout(10.seconds) {
                val bob = UdpSocket.bind(localHost = "127.0.0.1", localPort = 0)
                val alice = UdpSocket.bind(localHost = "127.0.0.1", localPort = 0)
                try {
                    val bobAddr = assertNotNull(bob.localAddress, "bob must expose its bound local address")

                    val bobJob =
                        launch {
                            when (val r = bob.receive()) {
                                is DatagramReadResult.Received -> bob.send(r.datagram.payload, to = r.datagram.peer)
                                is DatagramReadResult.Closed -> error("bob closed before receiving")
                            }
                        }

                    val payload = "real udp over the seam"
                    val out = BufferFactory.Default.allocate(payload.length)
                    out.writeString(payload, Charset.UTF8)
                    out.resetForRead()
                    alice.send(out, to = bobAddr)

                    val echo = alice.receive()
                    check(echo is DatagramReadResult.Received) { "alice received no echo" }
                    val text = echo.datagram.payload.readString(echo.datagram.payload.remaining(), Charset.UTF8)
                    assertEquals(payload, text, "echoed payload corrupted over real loopback UDP")

                    bobJob.join()
                } finally {
                    alice.close()
                    bob.close()
                }
            }
        }
}

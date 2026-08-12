@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.deterministic
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.ice.IceConfig
import com.ditchoom.webrtc.ice.udpDatagramBinder
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sctp.datachannel.send
import com.ditchoom.webrtc.sdp.SdpType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **The real-socket proof, on every platform that has a socket.** Two [NativePeerConnection]s — the
 * production stack, over `socket-udp`'s own [udpDatagramBinder] — establish a full data channel across
 * real loopback UDP and echo ping/pong.
 *
 * This exists because of a coverage inversion. The stack is proven on real wire by the Docker L2 harness
 * and by `webrtc-harness-endpoint`'s `JvmRealUdpLoopbackTest`, and **both are Linux/JVM only** — that
 * module targets jvm + linuxX64 + linuxArm64 and deliberately does not apply the library convention, so it
 * structurally cannot reach Apple. `build-apple.yaml` has run `macosArm64Test iosSimulatorArm64Test` all
 * along, but every test they could reach was `commonTest`, which runs on the in-memory vnet. So on Apple
 * the pieces that only exist where real UDP does were compiled and never executed:
 *
 * - [udpDatagramBinder] and the `TypedSendChannel` classification wrapped around it,
 * - the Apple datagram send path, which reads `position()`/`remaining()` off the buffer directly rather
 *   than slicing (see CLAUDE.md's "`send` does not consume" — the four backends do not agree in shape,
 *   only in contract),
 * - and the `requiresNativeMemoryBuffers` probe, whose whole job is to refuse an unsendable factory at the
 *   bind rather than at the first silent drop.
 *
 * A single fixture in a source set paired with `socketMain` closes all of that, and costs no new CI: the
 * Apple job already runs these test tasks.
 *
 * Real I/O, so real wall-clock and a real dispatcher (`runBlocking`, not `runTest`). The assertions are on
 * observable state — [PeerConnectionState.Connected] and the echoed bytes — bounded by a [withTimeout]
 * watchdog, never on a wall-clock budget (directive #4). On loopback this settles well under a second.
 */
class RealUdpLoopbackTest {
    @Test
    fun two_peers_establish_over_real_udp_loopback_and_echo() =
        runBlocking {
            withTimeout(WATCHDOG) {
                // A native, refcounted factory into every layer's seam — the shape CLAUDE.md recommends to
                // consumers, and the one the real send paths require on Linux and Apple. Passing it here
                // rather than taking the default is also what puts the `requiresNativeMemoryBuffers` bind
                // check on the executed path.
                val net = BufferFactory.deterministic()

                // Driver edge: the injected clock's production value is genuinely the wall clock (directive
                // #2 — the seam is honored, its default supplied here). Not grepped in *Test sources.
                val clock: () -> Instant = { Clock.System.now() }
                val scope = CoroutineScope(coroutineContext + Job())

                fun peer(seed: Long): NativePeerConnection =
                    NativePeerConnection(
                        scope = scope,
                        clock = clock,
                        random = Random(seed),
                        binder = udpDatagramBinder(net),
                        // Host candidates on loopback only — no STUN, no TURN, so the fixture needs no
                        // network beyond the machine it runs on and cannot flake on a blocked egress.
                        // Port 0 is load-bearing: an ephemeral port is what a real gathering policy must
                        // use (a pinned one cannot be re-bound across an ICE restart), and it removes the
                        // only cross-run collision hazard on a shared runner.
                        gathering = IceGatheringPolicy { it.gatherHost(LOOPBACK, port = 0) },
                        dtls = PureKotlinDtls(scope, clock, DtlsConfig(bufferFactory = net)),
                        config =
                            PeerConnectionConfig(
                                iceConfig = IceConfig(bufferFactory = net),
                                sctpConfig = SctpConfig(bufferFactory = net),
                            ),
                    )

                val offerer = peer(seed = 1L)
                val answerer = peer(seed = 2L)

                // In-process trickle — a same-process loopback pair needs no rendezvous.
                scope.launch { offerer.localIceCandidates.collect { answerer.addIceCandidate(it) } }
                scope.launch { answerer.localIceCandidates.collect { offerer.addIceCandidate(it) } }

                val channel = offerer.createDataChannel(DataChannelConfig(label = "loopback"))

                val offer = offerer.createOffer()
                offerer.setLocalDescription(SdpType.Offer, offer)
                answerer.setRemoteDescription(SdpType.Offer, offer)
                val answer = answerer.createAnswer()
                answerer.setLocalDescription(SdpType.Answer, answer)
                offerer.setRemoteDescription(SdpType.Answer, answer)

                assertConnected(offerer, "offerer")
                assertConnected(answerer, "answerer")

                val incoming = answerer.incomingDataChannels.first()
                channel.send(textBuffer("ping"))
                assertEquals("ping", incoming.receive().first().contentAsString(), "answerer received the ping over the encrypted channel")
                incoming.send(textBuffer("pong"))
                assertEquals("pong", channel.receive().first().contentAsString(), "offerer received the echoed pong")

                scope.cancel()
                offerer.close()
                answerer.close()
            }
        }

    private suspend fun assertConnected(
        pc: NativePeerConnection,
        who: String,
    ) {
        val terminal =
            pc.connectionState.first {
                it is PeerConnectionState.Connected || it is PeerConnectionState.Failed
            }
        if (terminal is PeerConnectionState.Failed) error("$who failed to connect: ${terminal.reason}")
    }

    private fun textBuffer(s: String): ReadBuffer {
        val bytes = s.encodeToByteArray()
        val buf = BufferFactory.deterministic().allocate(maxOf(1, bytes.size), ByteOrder.BIG_ENDIAN)
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

    private companion object {
        private val WATCHDOG = 60.seconds
        private const val LOOPBACK = "127.0.0.1"
    }
}

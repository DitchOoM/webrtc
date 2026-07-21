@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.deterministic
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.IceGatheringPolicy
import com.ditchoom.webrtc.NativePeerConnection
import com.ditchoom.webrtc.PeerConnectionConfig
import com.ditchoom.webrtc.PeerConnectionState
import com.ditchoom.webrtc.PureKotlinDtls
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.ice.IceConfig
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
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
 * **The JVM real-wire proof.** Two [NativePeerConnection]s — the exact production stack the harness peer
 * composes ([PureKotlinDtls] + socket-udp's NIO datapath) — establish a full WebRTC data channel over
 * **real loopback UDP** on the JVM and echo ping/pong. Until the W4b flip DTLS was native-only, so "we
 * support JVM" rested on unit tests + compile alone; this is a live ICE → **pure-Kotlin DTLS 1.3 (X25519)**
 * → SCTP → data-channel establishment on the JVM, over real sockets, with no Docker and no vnet — the
 * deterministic sibling of the L2 harness's JVM interop lane. (The L2 lane adds real NAT kernels + real
 * independent engines; this proves the JVM datapath itself in the ordinary build.)
 *
 * Real I/O, so real wall-clock and a real dispatcher (`runBlocking`, not `runTest`): the assertions are on
 * observable state ([PeerConnectionState.Connected] / the echoed bytes) bounded by a [withTimeout] watchdog
 * — never a wall-clock budget (directive #4). On loopback this settles in well under a second.
 */
class JvmRealUdpLoopbackTest {
    @Test
    fun two_jvm_peers_establish_over_real_udp_loopback_and_echo() =
        runBlocking {
            withTimeout(WATCHDOG) {
                // Native (DirectByteBuffer) factory into every layer's seam — the same injection the harness
                // peer uses, so the JVM NIO send path never needs to copy a heap buffer.
                val net = BufferFactory.deterministic()

                // Driver edge: the injected clock's production value is genuinely the wall clock (directive
                // #2 — the seam is honored, its default supplied here). Not grepped in *Test sources.
                val clock: () -> Instant = { Clock.System.now() }
                val scope = CoroutineScope(coroutineContext + Job())

                fun peer(
                    seed: Long,
                    port: Int,
                ): NativePeerConnection =
                    NativePeerConnection(
                        scope = scope,
                        clock = clock,
                        random = Random(seed),
                        binder = realUdpBinder(),
                        // Host candidates only — direct loopback, no coturn.
                        gathering = IceGatheringPolicy { it.gatherHost("127.0.0.1", port) },
                        dtls = PureKotlinDtls(scope, clock, DtlsConfig(bufferFactory = net)),
                        config =
                            PeerConnectionConfig(
                                iceConfig = IceConfig(bufferFactory = net),
                                sctpConfig = SctpConfig(bufferFactory = net),
                            ),
                    )

                val offerer = peer(seed = 1L, port = OFFERER_PORT)
                val answerer = peer(seed = 2L, port = ANSWERER_PORT)

                // In-process trickle — no rendezvous needed for a same-JVM loopback pair.
                scope.launch { offerer.localIceCandidates.collect { answerer.addIceCandidate(it) } }
                scope.launch { answerer.localIceCandidates.collect { offerer.addIceCandidate(it) } }

                val channel = offerer.createDataChannel(DataChannelConfig(label = "harness"))

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
                assertEquals("ping", incoming.receive().first().text(), "answerer received the ping over the encrypted channel")
                incoming.send(textBuffer("pong"))
                assertEquals("pong", channel.receive().first().text(), "offerer received the echoed pong")

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

    private companion object {
        private val WATCHDOG = 60.seconds

        // Fixed loopback ports (gatherHost advertises the literal port, so these must be concrete). Chosen
        // high + uncommon to avoid collisions on a clean CI runner.
        private const val OFFERER_PORT = 45011
        private const val ANSWERER_PORT = 45012
    }
}

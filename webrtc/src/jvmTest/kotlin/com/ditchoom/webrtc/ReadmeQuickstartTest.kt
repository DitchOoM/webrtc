@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.InterfaceSnapshot
import com.ditchoom.webrtc.ice.systemInterfaceEnumerator
import com.ditchoom.webrtc.ice.udpDatagramBinder
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sdp.SdpType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.io.File
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **The README's quickstart, compiled and run.**
 *
 * The wiring block in `README.md` — `peerConnection(...)` below — is this code verbatim, so a reader
 * copying it gets something that establishes rather than something that used to. A README snippet nobody
 * compiles is a snippet that rots at the first signature change, and this library's entry point is a
 * six-seam constructor: exactly the shape that drifts silently.
 *
 * The **only** difference between this and what a real app runs is that `stunServer` is left null — two
 * peers in one process on loopback need no reflexive candidate. Everything else is identical: the binder,
 * the interface enumeration, ephemeral binding, `PureKotlinDtls`, the offer/answer order, the trickle
 * wiring. If the README block and this one ever diverge, fix the README — this is the one that runs.
 *
 * Real sockets mean a real dispatcher and real time, so the watchdog is a [withTimeout] on observable
 * state, never a wall-clock budget (directive 4).
 */
class ReadmeQuickstartTest {
    // ── README: "Quickstart" ─────────────────────────────────────────────────────────────────────
    private fun peerConnection(
        scope: CoroutineScope,
        clock: () -> Instant, // Clock.System::now in production
        seed: Long,
        stunServer: SocketAddress? = null, // SocketAddress.resolve("stun.example.org", 3478)
    ) = NativePeerConnection(
        scope = scope,
        clock = clock,
        random = Random(seed),
        // The one seam between a virtual-time test and a real kernel.
        binder = udpDatagramBinder(),
        // Which sockets to bind. Port 0 asks the OS for an ephemeral one — a pinned port cannot
        // survive an ICE restart, which re-gathers while the old sockets are still bound.
        gathering =
            IceGatheringPolicy { driver ->
                val snapshot = systemInterfaceEnumerator().enumerate()
                val interfaces = (snapshot as? InterfaceSnapshot.Enumerated)?.interfaces.orEmpty()
                for (local in interfaces) {
                    driver.gatherHost(local.address.host, port = 0, stunServer = stunServer)
                }
            },
        // One factory is one endpoint identity: its certificate is the a=fingerprint we offer.
        dtls = PureKotlinDtls(scope, clock),
    )

    @Test
    fun the_readme_quickstart_establishes_and_echoes() =
        runBlocking {
            withTimeout(WATCHDOG) {
                val scope = CoroutineScope(coroutineContext + Job())

                @Suppress("UnseamedEntropy") // the production default for the injected seam; not a core
                val clock: () -> Instant = { Clock.System.now() }

                val offerer = peerConnection(scope, clock, seed = 1L)
                val answerer = peerConnection(scope, clock, seed = 2L)

                // ── README: "Signaling is yours" — here the two peers share a process, so the
                // "signaling channel" is a pair of collectors. In an app these cross your transport.
                scope.launch { offerer.localIceCandidates.collect { answerer.addIceCandidate(it) } }
                scope.launch { answerer.localIceCandidates.collect { offerer.addIceCandidate(it) } }

                val chat = offerer.createDataChannel(DataChannelConfig(label = "chat"))

                val offer = offerer.createOffer()
                offerer.setLocalDescription(SdpType.Offer, offer)
                answerer.setRemoteDescription(SdpType.Offer, offer)
                val answer = answerer.createAnswer()
                answerer.setLocalDescription(SdpType.Answer, answer)
                offerer.setRemoteDescription(SdpType.Answer, answer)

                awaitConnected(offerer, "offerer")
                awaitConnected(answerer, "answerer")

                // ── README: "A data channel is a buffer-flow Connection<ReadBuffer>"
                val incoming: Connection<ReadBuffer> = answerer.incomingDataChannels.first()
                chat.send(utf8("ping"))
                assertEquals("ping", incoming.receive().first().utf8(), "the answerer read the offerer's message")
                incoming.send(utf8("pong"))
                assertEquals("pong", chat.receive().first().utf8(), "the offerer read the reply")

                scope.cancel()
                offerer.close()
                answerer.close()
            }
        }

    /**
     * …and the README really does show *this* code. Compiling the snippet is only half the guarantee: the
     * half that actually rots is the copy in the markdown, which nothing compiles and everyone edits. So
     * the two are compared character for character, and drift is a build failure rather than a discovery
     * made by the first person who pasted it.
     */
    @Test
    fun the_readme_shows_exactly_this_wiring() {
        val readme = readmeOrNull() ?: error("README.md not found above ${File("").absolutePath}")
        val documented =
            readme
                .substringAfter("```kotlin\nfun peerConnection(", missingDelimiterValue = "")
                .substringBefore("\n```")
                .let { "fun peerConnection($it" }
        check(documented.isNotBlank()) { "README.md has no `fun peerConnection(` kotlin block to check" }
        assertEquals(
            documented.trimEnd(),
            wiringSource().trimEnd(),
            "README.md's quickstart has drifted from ReadmeQuickstartTest.peerConnection — update the README",
        )
    }

    // This test's own `peerConnection`, read back from source and normalised to top-level form: the four
    // leading spaces of a class member, and the `private` a README would not carry.
    private fun wiringSource(): String {
        val source = sourceFile().readText()
        val body =
            source
                .substringAfter("    private fun peerConnection(")
                .substringBefore("\n    )\n")
        return ("fun peerConnection(" + body + "\n)")
            .lines()
            .joinToString("\n") { it.removePrefix("    ") }
    }

    private fun sourceFile(): File =
        generateSequence(File("").absoluteFile) { it.parentFile }
            .map { File(it, "webrtc/src/jvmTest/kotlin/com/ditchoom/webrtc/ReadmeQuickstartTest.kt") }
            .first { it.isFile }

    private fun readmeOrNull(): String? =
        generateSequence(File("").absoluteFile) { it.parentFile }
            .map { File(it, "README.md") }
            .firstOrNull { it.isFile }
            ?.readText()

    private suspend fun awaitConnected(
        pc: RtcPeerConnection,
        who: String,
    ) {
        val terminal = pc.connectionState.first { it is PeerConnectionState.Connected || it is PeerConnectionState.Failed }
        if (terminal is PeerConnectionState.Failed) error("$who failed to connect: ${terminal.reason}")
    }

    private fun utf8(text: String): ReadBuffer {
        val buffer = BufferFactory.Default.allocate(text.length, ByteOrder.BIG_ENDIAN)
        buffer.writeString(text, Charset.UTF8)
        buffer.resetForRead()
        return buffer
    }

    private fun ReadBuffer.utf8(): String = readString(remaining(), Charset.UTF8)

    private companion object {
        private val WATCHDOG = 60.seconds
    }
}

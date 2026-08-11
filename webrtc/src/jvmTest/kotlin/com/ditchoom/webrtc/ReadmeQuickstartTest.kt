@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.udpDatagramBinder
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sctp.datachannel.DataChannelPayload
import com.ditchoom.webrtc.sctp.datachannel.send
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
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * **The README's quickstart, compiled and run.**
 *
 * The wiring block in `README.md` — `peerConnection(...)` below — is this code verbatim, so a reader
 * copying it gets something that establishes rather than something that used to. A README snippet nobody
 * compiles is a snippet that rots at the first signature change.
 *
 * Two differences from what a real app runs, both because the two peers share one process: `iceServers`
 * is empty (loopback needs no reflexive or relayed candidate) and `mdns` is off (a `<uuid>.local` name
 * would have to resolve over real multicast). Everything else is what `nativePeerConnection` defaults —
 * interface enumeration, ephemeral binding, `PureKotlinDtls`, the offer/answer order, the trickle
 * wiring. If the README block and this one ever diverge, fix the README — this is the one that runs.
 *
 * Real sockets mean a real dispatcher and real time, so the watchdog is a [withTimeout] on observable
 * state, never a wall-clock budget (directive 4).
 */
class ReadmeQuickstartTest {
    // ── README: "Quickstart" ─────────────────────────────────────────────────────────────────────
    private fun peerConnection(
        scope: CoroutineScope,
        seed: Long,
        iceServers: List<IceServer> = emptyList(), // listOf(IceServer("stun:stun.example.org"))
    ) = nativePeerConnection(
        scope = scope,
        // The one seam between a virtual-time test and a real kernel — and a *parameter*, never
        // something the factory binds for itself, so one demuxed UDP socket can carry more than
        // this session.
        binder = udpDatagramBinder(),
        // `stun:` / `turn:` URLs. Parsed, resolved, and gathered on per address family; whatever is
        // unusable (a `turns:` URL, a TURN server with no credential) is reported, never dropped.
        iceServers = iceServers,
        // Off here ONLY because both peers share this process: mDNS publishes host candidates as a
        // `<uuid>.local` name the peer must resolve over real multicast. Leave it on in an app —
        // that is the default, and what a browser does unconditionally.
        mdns = false,
        random = Random(seed),
    )

    @Test
    fun the_readme_quickstart_establishes_and_echoes() =
        runBlocking {
            withTimeout(WATCHDOG) {
                val scope = CoroutineScope(coroutineContext + Job())

                val offerer = peerConnection(scope, seed = 1L)
                val answerer = peerConnection(scope, seed = 2L)

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

                // ── README: "A data channel is a buffer-flow Connection<DataChannelPayload>"
                val incoming: Connection<DataChannelPayload> = answerer.incomingDataChannels.first()
                chat.send(DataChannelPayload.Text("ping"))
                assertEquals("ping", incoming.receive().first().utf8(), "the answerer read the offerer's message")
                incoming.send(DataChannelPayload.Text("pong"))
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

    private fun DataChannelPayload.utf8(): String =
        when (this) {
            is DataChannelPayload.Text -> text.toString()
            is DataChannelPayload.Binary -> bytes.readString(bytes.remaining(), Charset.UTF8)
        }

    private companion object {
        private val WATCHDOG = 60.seconds
    }
}

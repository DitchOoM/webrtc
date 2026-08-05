@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sdp.SdpType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
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
 * **The real-DTLS half of [SessionBufferOwnershipTest]**, and the one that covers the pump.
 *
 * The `commonTest` sibling runs the plaintext seam, so its datagrams go ICE → SCTP and the DTLS record
 * layer is never in the chain. This one puts a genuine [PureKotlinDtls] handshake in the middle, which
 * adds the two release sites that only exist there: the pump releasing an inbound record after applying
 * its step, and the decrypted application data it hands on to SCTP.
 *
 * It sits in `linuxTest` for the same reason [PeerConnectionDtlsEndToEndTest] does — `commonTest`
 * includes js/wasmJs, where the engine is deliberately never driven — and Kotlin/Native Linux happens to
 * be the exact target this bug is real on, since it is the only one whose receive factory is a raw
 * `malloc` rather than something the collector reclaims.
 *
 * ## What it asserts, and the seam it deliberately does not
 *
 * The tracker goes on **[TestNet]'s factory** — the copy-on-receive seam, standing in for the socket's
 * receive buffer, which is the thing that travels ICE → DTLS → SCTP and was released by nobody. That is
 * this fixture's invariant and it holds.
 *
 * It does **not** assert on [DtlsConfig.bufferFactory], the DTLS *record* seam, because that one is still
 * unowned and is a separate piece of work. Measured while writing this: a session of this size ends with
 * **262 of 262** record buffers live. The dominant term is the send side — every record `encode`s into a
 * fresh buffer from that factory and goes to `IceDataTransport.send`, which explicitly does *not* take
 * ownership, so nothing ever frees it — with `HandshakeReassembler`'s per-message assembly buffers behind
 * it. Neither is on the path this change is about, and folding a send-side fix into a receive-side one
 * would make both harder to review. The two trackers must stay separate whoever does it: pointing one
 * factory at both seams produces a number that cannot be attributed to either.
 */
class DtlsSessionBufferOwnershipTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun a_real_dtls_session_releases_every_datagram_and_every_record_it_received() =
        runTest {
            val received = LeakTrackingFactory()
            val net = TestNet(bufferFactory = received)
            val binder = DatagramBinder { net.bind(it) }
            val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }

            val aliceDtls = PureKotlinDtls(backgroundScope, clock)
            val bobDtls = PureKotlinDtls(backgroundScope, clock)

            val alice =
                NativePeerConnection(
                    scope = backgroundScope,
                    clock = clock,
                    random = Random(1),
                    binder = binder,
                    gathering = { it.gatherHost("10.0.0.1", 4000) },
                    dtls = aliceDtls,
                )
            val bob =
                NativePeerConnection(
                    scope = backgroundScope,
                    clock = clock,
                    random = Random(2),
                    binder = binder,
                    gathering = { it.gatherHost("10.0.0.2", 5000) },
                    dtls = bobDtls,
                )

            trickle(backgroundScope, from = alice, to = bob)
            trickle(backgroundScope, from = bob, to = alice)

            val channel = alice.createDataChannel(DataChannelConfig(label = "ownership"))

            val offer = alice.createOffer()
            alice.setLocalDescription(SdpType.Offer, offer)
            bob.setRemoteDescription(SdpType.Offer, offer)
            val answer = bob.createAnswer()
            bob.setLocalDescription(SdpType.Answer, answer)
            alice.setRemoteDescription(SdpType.Answer, answer)

            assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice connected")
            assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob connected")

            val incoming = withTimeoutOrNull(timeout) { bob.incomingDataChannels.first() }
            assertNotNull(incoming, "bob received the data channel")

            // Both directions: each peer must be a releasing receiver of encrypted records, not just a
            // sender of them.
            channel.send(textBuffer("ping"))
            assertEquals("ping", withTimeoutOrNull(timeout) { incoming.receive().first().text() })
            incoming.send(textBuffer("pong"))
            assertEquals("pong", withTimeoutOrNull(timeout) { channel.receive().first().text() })

            alice.close()
            bob.close()

            received.assertNoLeaks("a real-DTLS session's received datagrams")
        }

    private fun trickle(
        scope: CoroutineScope,
        from: NativePeerConnection,
        to: NativePeerConnection,
    ) {
        scope.launch {
            from.localIceCandidates.collect { to.addIceCandidate(it) }
        }
    }

    private suspend fun NativePeerConnection.awaitConnected(): PeerConnectionState =
        connectionState.first {
            when (it) {
                is PeerConnectionState.Connected -> true
                is PeerConnectionState.Failed -> error("expected a connection, but PeerConnection failed: ${it.reason}")
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

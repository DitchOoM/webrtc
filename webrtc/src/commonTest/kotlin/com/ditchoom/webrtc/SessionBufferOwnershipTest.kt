@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sctp.datachannel.send
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
 * **The receive side above ICE gives its datagrams back.** The sibling of `webrtc-ice`'s
 * `ReceivedDatagramOwnershipTest`, one layer up: that fixture proved the ICE driver releases what it
 * receives, and left the seam above it — [com.ditchoom.webrtc.ice.IceDataTransport.receive], which
 * *transfers* ownership to its caller — explicitly unowned. This crosses that split.
 *
 * ## Why the tracker goes on [TestNet]
 *
 * The buffer that leaks is the **channel's** receive copy, not anything `IceConfig.bufferFactory`
 * allocated — which is exactly why `BufferLifecycleTest`, pointed at the latter, could never see this
 * class of bug. [TestNet]'s factory is the copy-on-receive seam, standing in for `socket-udp`'s receive
 * factory: `BufferFactory.deterministic()` on Kotlin/Native Linux, a raw `malloc` whose buffers buffer's
 * own KDoc says "must be explicitly closed". Every unreleased datagram there is permanently lost.
 *
 * Pointing it at [TestNet] is safe here in a way it is *not* on `webrtc-ice`'s richer vnet: this link
 * carries two peers and nothing else, so every buffer on it belongs to production code. The ICE vnet also
 * hosts STUN and TURN servers, which release nothing because nothing asks them to, and a tracker there
 * reports harness scenery as a production leak.
 *
 * ## What this proves and what it deliberately does not
 *
 * The plaintext path — ICE → [PlaintextDtls] → SCTP — is the whole receive chain minus the DTLS record
 * layer, and it runs on **every** target. The real-DTLS pump has its own fixture in `linuxTest`
 * (`DtlsSessionBufferOwnershipTest`), where `PureKotlinDtls` can actually generate a certificate, and
 * which is the target this bug is real on anyway.
 */
class SessionBufferOwnershipTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    /**
     * A full session — establish, exchange data both ways, close — releases every datagram it received.
     *
     * Verified red-then-green by stashing the production change rather than by reasoning about it: before
     * the fix this reported **every** received datagram of the session still live, because nothing above
     * `IceAgentDriver`'s app-data seam had ever released one.
     */
    @Test
    fun a_plaintext_session_releases_every_datagram_it_received() =
        runTest {
            val received = LeakTrackingFactory()
            val net = TestNet(bufferFactory = received)
            val binder = DatagramBinder { net.bind(it) }
            val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }

            val alice =
                NativePeerConnection(
                    scope = backgroundScope,
                    clock = clock,
                    random = Random(1),
                    binder = binder,
                    gathering = { it.gatherHost("10.0.0.1", 4000) },
                    dtls = PlaintextDtls,
                )
            val bob =
                NativePeerConnection(
                    scope = backgroundScope,
                    clock = clock,
                    random = Random(2),
                    binder = binder,
                    gathering = { it.gatherHost("10.0.0.2", 5000) },
                    dtls = PlaintextDtls,
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

            // Traffic in BOTH directions: each peer must be a releasing *receiver*, and a one-way exchange
            // would leave one of the two receive paths unexercised while still reporting a clean number.
            channel.send(textBuffer("ping"))
            assertEquals("ping", withTimeoutOrNull(timeout) { incoming.receive().first().contentAsString() })
            incoming.send(textBuffer("pong"))
            assertEquals("pong", withTimeoutOrNull(timeout) { channel.receive().first().contentAsString() })

            // Close BEFORE asserting: teardown is a release site of its own — a channel closed with
            // transfers still queued has readers that will never run, and closing does not free what is
            // queued. A fixture that asserted while the session was live could not see that half.
            alice.close()
            bob.close()

            received.assertNoLeaks("a plaintext session's received datagrams")
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

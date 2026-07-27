@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sdp.SdpType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The W6 exit fixture: a **full PeerConnection API round-trip** with scripted signaling, over the vnet,
 * under `runTest` virtual time. Two [NativePeerConnection]s negotiate offer/answer, trickle candidates,
 * establish ICE + (plaintext) DTLS + SCTP, and exchange data-channel messages both ways — exercising the
 * whole consumer API (RFC §3.1) end to end. The real-DTLS end-to-end is the exit gate once W4 lands.
 */
class PeerConnectionRoundTripTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun full_offer_answer_data_channel_round_trip() =
        runTest {
            val net = TestNet()
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

            // Trickle: pipe each peer's local candidates into the other (the app's signaling channel).
            trickle(backgroundScope, from = alice, to = bob)
            trickle(backgroundScope, from = bob, to = alice)

            // The offerer creates a data channel before negotiating (the common browser pattern).
            val channel = alice.createDataChannel(DataChannelConfig(label = "chat"))

            // Scripted offer/answer over the app's signaling seam.
            val offer = alice.createOffer()
            alice.setLocalDescription(SdpType.Offer, offer)
            bob.setRemoteDescription(SdpType.Offer, offer)
            val answer = bob.createAnswer()
            bob.setLocalDescription(SdpType.Answer, answer)
            alice.setRemoteDescription(SdpType.Answer, answer)

            assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice connected")
            assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob connected")

            // Bob receives the data channel the offerer opened.
            val incoming = withTimeoutOrNull(timeout) { bob.incomingDataChannels.first() }
            assertNotNull(incoming, "bob received the data channel")

            channel.send(textBuffer("ping"))
            channel.send(textBuffer("from-alice"))
            val received =
                withTimeoutOrNull(timeout) {
                    incoming
                        .receive()
                        .take(2)
                        .toList()
                        .map { it.text() }
                }
            assertEquals(listOf("ping", "from-alice"), received)

            incoming.send(textBuffer("pong"))
            assertEquals("pong", withTimeoutOrNull(timeout) { channel.receive().first().text() })

            assertTrue(alice.signalingState.value is com.ditchoom.webrtc.sdp.SignalingState.Stable)
        }

    /**
     * The deterministic sibling of the L2 harness's `s7/close-one` phase (`Semantics.kt`): ONE data
     * channel is closed mid-session while the association keeps running — RFC 8831 §6.7's close, which is
     * an RFC 6525 stream reset, not a shutdown. `DataChannelCloseTest` proves the same three properties on
     * a bare [com.ditchoom.webrtc.sctp.datachannel.SctpDataChannelStack] pair; this one proves them
     * through the WHOLE stack (ICE + DTLS seam + SCTP + DCEP + the PeerConnection API) over the vnet, with
     * the far side running exactly the dumb universal reflector every interop answerer runs.
     */
    @Test
    fun closing_one_channel_keeps_its_neighbour_and_recycles_the_stream_id() =
        runTest {
            val (alice, bob) = connectedPeers()

            // The far side is the harness reflector, not a cooperating test peer: for every channel it is
            // offered, echo every message back on that channel. It has no idea a close is coming.
            backgroundScope.launch {
                bob.incomingDataChannels.collect { channel ->
                    launch { channel.receive().collect { channel.send(it) } }
                }
            }

            val victim = alice.createDataChannel(DataChannelConfig(label = "s7/victim"))
            val keep = alice.createDataChannel(DataChannelConfig(label = "s7/keep"))
            val victimId = victim.id
            assertEquals("v0", echo(victim, "v0"), "the victim channel is live before the close")
            assertEquals("k0", echo(keep, "k0"), "its neighbour is live before the close")

            victim.close()

            // (1) The reset took exactly one stream: the neighbour still round-trips.
            assertEquals("k1", echo(keep, "k1"), "the neighbour survived its sibling's close")

            // (2) The peer closed its half too — the only offerer-side evidence of that is the id coming
            // back, since our stack recycles one only after BOTH directions have been reset.
            val reopened = alice.createDataChannel(DataChannelConfig(label = "s7/reopen"))
            assertEquals(victimId, reopened.id, "the closed stream id was handed back, so the peer reset its half")

            // (3) …and the recycled id works on the wire: the peer accepted a fresh DCEP OPEN on it and
            // delivered its first ordered message rather than dropping SSN 0 as a duplicate of the old one.
            assertEquals("r0", echo(reopened, "r0"), "the recycled stream carries traffic again")
        }

    /** Send [text] and return what came back on the same channel — the harness's `echoesBack`, asserted. */
    private suspend fun echo(
        channel: Connection<ReadBuffer>,
        text: String,
    ): String? {
        channel.send(textBuffer(text))
        return withTimeoutOrNull(timeout) { channel.receive().first().text() }
    }

    /** Two peers, negotiated over scripted signaling and both [PeerConnectionState.Connected], on the vnet. */
    private suspend fun TestScope.connectedPeers(): Pair<NativePeerConnection, NativePeerConnection> {
        val net = TestNet()
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

        val offer = alice.createOffer()
        alice.setLocalDescription(SdpType.Offer, offer)
        bob.setRemoteDescription(SdpType.Offer, offer)
        val answer = bob.createAnswer()
        bob.setLocalDescription(SdpType.Answer, answer)
        alice.setRemoteDescription(SdpType.Answer, answer)

        assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice connected")
        assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob connected")
        return alice to bob
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

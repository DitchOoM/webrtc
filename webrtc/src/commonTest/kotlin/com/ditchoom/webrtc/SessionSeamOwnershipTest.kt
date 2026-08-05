@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.ice.IceConfig
import com.ditchoom.webrtc.sctp.association.SctpConfig
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
 * **Every seam of a session returns its memory, not just the receive side.**
 *
 * `PooledReceiveChunkTest` covers the datagrams a session *receives*. This one puts a separate tracker on
 * each factory a session is built from, so the **send** seams are held to the same standard:
 *
 * - `IceConfig.bufferFactory` — every STUN request, response, consent check and TURN message.
 * - `SctpConfig.bufferFactory` — every encoded SCTP packet, reassembly copy and DCEP message.
 *
 * One tracker per seam, never one shared: a single factory across two seams produces a number that
 * cannot be attributed to either, which is the mistake that made an earlier relay fixture report "2 of 4
 * leaked" where two were harness scenery.
 *
 * Each peer gets its own trackers too. Alice and Bob are separate endpoints with separate lifetimes, and
 * a shared tracker would let one peer's discipline mask the other's leak.
 */
class SessionSeamOwnershipTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun a_session_returns_every_buffer_from_every_seam() =
        runTest {
            val aliceIce = LeakTrackingFactory()
            val aliceSctp = LeakTrackingFactory()
            val bobIce = LeakTrackingFactory()
            val bobSctp = LeakTrackingFactory()

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
                    config =
                        PeerConnectionConfig(
                            iceConfig = IceConfig(bufferFactory = aliceIce),
                            sctpConfig = SctpConfig(bufferFactory = aliceSctp),
                        ),
                )
            val bob =
                NativePeerConnection(
                    scope = backgroundScope,
                    clock = clock,
                    random = Random(2),
                    binder = binder,
                    gathering = { it.gatherHost("10.0.0.2", 5000) },
                    dtls = PlaintextDtls,
                    config =
                        PeerConnectionConfig(
                            iceConfig = IceConfig(bufferFactory = bobIce),
                            sctpConfig = SctpConfig(bufferFactory = bobSctp),
                        ),
                )

            trickle(backgroundScope, from = alice, to = bob)
            trickle(backgroundScope, from = bob, to = alice)

            val channel = alice.createDataChannel(DataChannelConfig(label = "seams"))
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
            channel.send(textBuffer("ping"))
            assertEquals("ping", withTimeoutOrNull(timeout) { incoming.receive().first().text() })
            incoming.send(textBuffer("pong"))
            assertEquals("pong", withTimeoutOrNull(timeout) { channel.receive().first().text() })

            alice.close()
            bob.close()

            // `assertNoLeaks` first: it names WHICH buffer was never freed, which the chunk count cannot.
            // If it passes and the chunk probe fails, the cause is an unreleased slice instead.
            aliceIce.assertNoLeaks("alice's ICE seam")
            aliceIce.assertPoolDrained("alice's ICE seam")
            bobIce.assertPoolDrained("bob's ICE seam")
            // The SCTP seam is NOT asserted yet, and the number is recorded rather than hidden: a session
            // of this size ends with **15 of 15** chunks still referenced there. Two things block it, and
            // both are decisions rather than oversights:
            //
            //  1. `SctpOutput.Transmit`'s KDoc already assigns the packet to the association ("the
            //     association frees it when the chunk is acked or abandoned") — but `RetransmissionQueue`
            //     removes entries on cumulative ack, gap ack and PR-SCTP abandon without freeing any of
            //     them, and a CONTROL packet never enters that queue, so nothing owns it at all. The
            //     contract is stated and unimplemented.
            //  2. It cannot simply be freed at emit time: `apply` hands a *slice* to `outbound`, which
            //     `writerLoop` sends asynchronously, so the parent must outlive the send. Splitting
            //     "driver frees after send" from "retransmission queue frees on ack" needs a discriminant
            //     on `Transmit` — the sealed type carries none today.
            //
            // Tracked separately so this fixture stays a gate for the seams that ARE clean.
            assertEquals(true, aliceSctp.outstandingChunks > 0, "the SCTP seam gap is expected to still be open")
        }

    private fun trickle(
        scope: CoroutineScope,
        from: NativePeerConnection,
        to: NativePeerConnection,
    ) {
        scope.launch { from.localIceCandidates.collect { to.addIceCandidate(it) } }
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

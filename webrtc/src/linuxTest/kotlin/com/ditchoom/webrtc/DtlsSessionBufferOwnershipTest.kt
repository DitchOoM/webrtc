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
import com.ditchoom.webrtc.sctp.datachannel.send
import com.ditchoom.webrtc.sdp.SdpType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
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
 * ## Three trackers, one per seam
 *
 * One goes on **[TestNet]'s factory** — the copy-on-receive seam, standing in for the socket's receive
 * buffer, which is the thing that travels ICE → DTLS → SCTP. The other two go on each peer's
 * [DtlsConfig.bufferFactory], the DTLS **record** seam: every record `Dtls13Handshake.encode`s comes from
 * there and goes to `IceDataTransport.send`, which explicitly does not take ownership, so the pump owes
 * the release (`PureKotlinDtls.apply`).
 *
 * They must stay separate. A single tracker pointed at two seams produces a number that cannot be
 * attributed to either, which is the whole reason this file exists beside the `commonTest` sibling.
 *
 * ## Why [LeakTrackingFactory.assertPoolDrained] and not just `assertNoLeaks`
 *
 * `assertNoLeaks` proves `freeNativeMemory()` was called on every buffer. It is structurally **blind** to
 * a borrow: `freed` is set by the first free whatever the refcount does, so an unreleased `sliceOf` taken
 * while decoding is invisible to it. Both are asserted, weaker first, because `assertNoLeaks` is the one
 * that names *which* buffer.
 *
 * A session of this size used to end with **262 of 262** record buffers live. The per-version breakdown
 * — and DTLS 1.2, which two of our own peers never negotiate — is
 * `webrtc-dtls`' own `DtlsRecordSeamOwnershipTest`; this one proves the same property through the pump,
 * the ICE transport and a real `PeerConnection` teardown, which that one cannot reach.
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

            val aliceRecords = LeakTrackingFactory()
            val bobRecords = LeakTrackingFactory()
            val aliceDtls = PureKotlinDtls(backgroundScope, clock, DtlsConfig(bufferFactory = aliceRecords))
            val bobDtls = PureKotlinDtls(backgroundScope, clock, DtlsConfig(bufferFactory = bobRecords))

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
            assertEquals("ping", withTimeoutOrNull(timeout) { incoming.receive().first().contentAsString() })
            incoming.send(textBuffer("pong"))
            assertEquals("pong", withTimeoutOrNull(timeout) { channel.receive().first().contentAsString() })

            alice.close()
            bob.close()
            // Let both DTLS pumps finish tearing down before anything is counted. `close()` cancels a pump
            // that is parked in `select`; its `finally` — which frees the engine, its certificate identity
            // and its traffic keys — needs a dispatch to run, and `advanceUntilIdle()` alone does not give
            // a cancelled background coroutine one. Measuring first reported a confident 28-buffer "leak"
            // that was entirely this.
            delay(1.seconds)
            testScheduler.advanceUntilIdle()

            // `assertNoLeaks` first: it names WHICH buffer was never freed. `assertPoolDrained` is the
            // stronger claim and the one an unreleased *slice* shows up in — a borrow taken while decoding
            // a record costs a reference on a pooled chunk however diligently its owner freed it.
            received.assertNoLeaks("a real-DTLS session's received datagrams")
            aliceRecords.assertNoLeaks("alice's DTLS record seam")
            bobRecords.assertNoLeaks("bob's DTLS record seam")
            received.assertPoolDrained("a real-DTLS session's received datagrams")
            aliceRecords.assertPoolDrained("alice's DTLS record seam")
            bobRecords.assertPoolDrained("bob's DTLS record seam")
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

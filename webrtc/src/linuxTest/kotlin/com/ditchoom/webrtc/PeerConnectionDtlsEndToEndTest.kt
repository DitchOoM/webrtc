@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.dtls.DtlsFailureReason
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
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **The real-crypto session fixture:** two [NativePeerConnection]s complete a full session over the vnet
 * with a genuine [PureKotlinDtls] handshake in the seam — ICE nomination → DTLS → SCTP association →
 * data channels — under `runTest` virtual time, at zero wall-clock. The `commonTest` siblings run the
 * same shapes over the plaintext stand-in, which proves the composition but never the handshake.
 *
 * It sits in `linuxTest` for historical reasons rather than technical ones: when it was written, Linux
 * was the only target with a DTLS backend. The engine is `commonMain` now and this would run on every
 * non-browser target — but `commonTest` includes js/wasmJs, where the engine is deliberately never
 * driven (ARCHITECTURE §1.1), and there is no shared "every target except the browsers" test source set
 * to hold it. Widening it needs that source set, not a code change.
 *
 * Determinism note: there is no RNG residue to bound — every source of entropy is injected, so the
 * handshake is byte-identical from its seed. Assertions are still on observable state with a watchdog,
 * never on a datagram count or a wall-clock budget (directive #4).
 */
class PeerConnectionDtlsEndToEndTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun two_peers_complete_ice_dtls_sctp_and_exchange_data_channel_messages() =
        runTest {
            val net = TestNet()
            val binder = DatagramBinder { net.bind(it) }
            val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }

            val aliceDtls = PureKotlinDtls(backgroundScope, clock)
            val bobDtls = PureKotlinDtls(backgroundScope, clock)

            // Two independently generated self-signed certificates — the peers are strangers, exactly as
            // in the field. Each verifies the other purely by the digest its SDP carried.
            assertTrue(
                aliceDtls.localFingerprint != bobDtls.localFingerprint,
                "each endpoint generates its own certificate",
            )

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

            val channel = alice.createDataChannel(DataChannelConfig(label = "chat"))

            val offer = alice.createOffer()
            // The offer advertises the digest of the certificate alice will actually present — not a
            // placeholder. This is the binding between signaling and the data path (RFC 8827).
            assertTrue(
                offer.contains("a=fingerprint:sha-256 ${aliceDtls.localFingerprint.value}"),
                "the offer carries alice's real certificate fingerprint",
            )
            alice.setLocalDescription(SdpType.Offer, offer)
            bob.setRemoteDescription(SdpType.Offer, offer)
            val answer = bob.createAnswer()
            bob.setLocalDescription(SdpType.Answer, answer)
            alice.setRemoteDescription(SdpType.Answer, answer)

            assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice connected")
            assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob connected")

            // Data now crosses a real encrypted DTLS record layer, not a passthrough.
            val incoming = withTimeoutOrNull(timeout) { bob.incomingDataChannels.first() }
            assertNotNull(incoming, "bob received the data channel")

            channel.send(textBuffer("ping"))
            assertEquals("ping", withTimeoutOrNull(timeout) { incoming.receive().first().contentAsString() })

            incoming.send(textBuffer("pong"))
            assertEquals("pong", withTimeoutOrNull(timeout) { channel.receive().first().contentAsString() })
        }

    /**
     * The security-critical negative: if the certificate the peer presents is not the one its SDP
     * advertised, the session **fails typed** rather than connecting. Without this check DTLS would
     * authenticate an anonymous self-signed certificate — i.e. nothing — and an on-path attacker who can
     * answer the ICE checks could take over the session (RFC 8827 §6.5).
     *
     * The tamper models exactly that: bob's answer reaches alice with a fingerprint that is well-formed
     * but belongs to some other certificate.
     */
    @Test
    fun a_peer_whose_certificate_does_not_match_its_advertised_fingerprint_is_rejected() =
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
                    dtls = PureKotlinDtls(backgroundScope, clock),
                )
            val bob =
                NativePeerConnection(
                    scope = backgroundScope,
                    clock = clock,
                    random = Random(2),
                    binder = binder,
                    gathering = { it.gatherHost("10.0.0.2", 5000) },
                    dtls = PureKotlinDtls(backgroundScope, clock),
                )

            trickle(backgroundScope, from = alice, to = bob)
            trickle(backgroundScope, from = bob, to = alice)

            val offer = alice.createOffer()
            alice.setLocalDescription(SdpType.Offer, offer)
            bob.setRemoteDescription(SdpType.Offer, offer)
            val answer = bob.createAnswer()
            bob.setLocalDescription(SdpType.Answer, answer)

            // Swap in a syntactically valid digest of a certificate that isn't bob's.
            val tampered = answer.replaceFingerprint(List(32) { "AA" }.joinToString(":"))
            alice.setRemoteDescription(SdpType.Answer, tampered)

            val failure =
                withTimeoutOrNull(timeout) {
                    alice.connectionState.first { it is PeerConnectionState.Failed }
                }
            assertNotNull(failure, "alice reached a terminal failure rather than hanging")
            val reason = (failure as PeerConnectionState.Failed).reason
            assertIs<PeerConnectionFailureReason.Dtls>(reason, "failed for a DTLS reason, was $reason")
            assertEquals(DtlsFailureReason.FingerprintMismatch, reason.reason)
        }

    /**
     * A peer that advertises no `a=fingerprint` at all cannot be verified, so it is refused with a typed
     * reason (RFC 8827 requires one) — the absent-digest sibling of the mismatch case above.
     */
    @Test
    fun a_peer_that_advertises_no_fingerprint_is_refused() =
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
                    dtls = PureKotlinDtls(backgroundScope, clock),
                )
            val bob =
                NativePeerConnection(
                    scope = backgroundScope,
                    clock = clock,
                    random = Random(2),
                    binder = binder,
                    gathering = { it.gatherHost("10.0.0.2", 5000) },
                    dtls = PureKotlinDtls(backgroundScope, clock),
                )

            trickle(backgroundScope, from = alice, to = bob)
            trickle(backgroundScope, from = bob, to = alice)

            val offer = alice.createOffer()
            alice.setLocalDescription(SdpType.Offer, offer)
            bob.setRemoteDescription(SdpType.Offer, offer)
            val answer = bob.createAnswer()
            bob.setLocalDescription(SdpType.Answer, answer)

            val stripped = answer.lines().filterNot { it.startsWith("a=fingerprint:") }.joinToString("\r\n")
            alice.setRemoteDescription(SdpType.Answer, stripped)

            val failure =
                withTimeoutOrNull(timeout) {
                    alice.connectionState.first { it is PeerConnectionState.Failed }
                }
            assertNotNull(failure, "alice reached a terminal failure rather than hanging")
            val reason = (failure as PeerConnectionState.Failed).reason
            assertIs<PeerConnectionFailureReason.Dtls>(reason, "failed for a DTLS reason, was $reason")
            assertEquals(DtlsFailureReason.FingerprintMissing, reason.reason)
        }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────────

    private fun String.replaceFingerprint(value: String): String =
        lines().joinToString("\r\n") { line ->
            if (line.startsWith("a=fingerprint:")) "a=fingerprint:sha-256 $value" else line
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

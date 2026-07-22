@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.crypto.CryptoCapabilities
import com.ditchoom.buffer.crypto.SignatureScheme
import com.ditchoom.buffer.crypto.SignatureSupport
import com.ditchoom.buffer.crypto.signatures
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
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
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **The full-stack loss gate (WS-1).** [PeerConnectionRoundTripTest] proves the whole consumer API over a
 * *lossless* link with the plaintext DTLS stand-in; this drives the **real** [PureKotlinDtls] engine over a
 * **lossy** [TestNet] across a seed sweep at 5/10/20 % per-datagram loss, asserting both peers reach
 * [PeerConnectionState.Connected] and the offered data channel is received on the far side.
 *
 * This is the fixture the "storm" class of bug (#28) demanded: that regression lived in the **interaction**
 * of the DTLS and SCTP retransmission timers over a shared lossy transport, and slipped every single-layer
 * loss gate — [com.ditchoom.webrtc.dtls] alone and [com.ditchoom.webrtc.sctp] alone are each loss-robust.
 * Only the combined ICE→DTLS→SCTP→DCEP establishment, over one lossy link, across many seeds, exercises the
 * regime where the storm/deadlock appears. Loss is seeded per datagram (directive #2), so a given seed is a
 * bit-for-bit replayable scenario a shrinker could bisect. Everything runs under `runTest` virtual time, so
 * a 20 %-loss establishment with real ECDSA/ECDH costs zero wall-clock beyond the crypto itself.
 *
 * Browsers delegate to `RTCPeerConnection` and have no blocking engine here, so the whole gate is guarded
 * on [engineCryptoAvailable] exactly as [DtlsSctpLossReproductionTest] is.
 */
class PeerConnectionLossRoundTripTest {
    // Generous virtual-time watchdog: virtual time is free, so this only has to be larger than the slowest
    // legitimately-converging run (retransmit backoff at 20 % loss), NOT a wall-clock budget (directive #4).
    private val timeout = 180.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun full_stack_establishment_survives_loss_across_seeds() {
        if (!engineCryptoAvailable()) return // browsers have no blocking DTLS engine — see class doc
        for (loss in listOf(0.05, 0.10, 0.20)) {
            for (seed in 0 until SEEDS_PER_RATE) {
                runOne(loss = loss, seed = seed.toLong())
            }
        }
    }

    private fun runOne(
        loss: Double,
        seed: Long,
    ) = runTest {
        val net = TestNet(loss = loss, seed = seed)
        val binder = DatagramBinder { net.bind(it) }
        val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }

        // One PureKotlinDtls per peer — one factory is one certificate identity. Seed each engine's entropy
        // off the run seed so the whole scenario (keys included) is deterministic.
        val aliceDtls = PureKotlinDtls(backgroundScope, clock, DtlsConfig(random = Random(seed xor 0xA11CE)))
        val bobDtls = PureKotlinDtls(backgroundScope, clock, DtlsConfig(random = Random(seed xor 0xB0B)))

        val alice =
            NativePeerConnection(
                scope = backgroundScope,
                clock = clock,
                random = Random(seed xor 0x1111),
                binder = binder,
                gathering = { it.gatherHost("10.0.0.1", 4000) },
                dtls = aliceDtls,
            )
        val bob =
            NativePeerConnection(
                scope = backgroundScope,
                clock = clock,
                random = Random(seed xor 0x2222),
                binder = binder,
                gathering = { it.gatherHost("10.0.0.2", 5000) },
                dtls = bobDtls,
            )

        trickle(backgroundScope, from = alice, to = bob)
        trickle(backgroundScope, from = bob, to = alice)

        // The offerer opens a channel before negotiating (the common browser pattern); its arrival on the
        // far side is the observable that proves SCTP + DCEP completed under loss.
        alice.createDataChannel(DataChannelConfig(label = "chat"))

        val offer = alice.createOffer()
        alice.setLocalDescription(SdpType.Offer, offer)
        bob.setRemoteDescription(SdpType.Offer, offer)
        val answer = bob.createAnswer()
        bob.setLocalDescription(SdpType.Answer, answer)
        alice.setRemoteDescription(SdpType.Answer, answer)

        val diag = "loss=$loss seed=$seed"
        assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice reached Connected ($diag)")
        assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob reached Connected ($diag)")

        // The offered channel arriving on the far side proves the SCTP association + DCEP OPEN/ACK also
        // survived the loss — the full ICE→DTLS→SCTP→DCEP path, not just the transport handshake.
        assertNotNull(
            withTimeoutOrNull(timeout) { bob.incomingDataChannels.first() },
            "bob received the data channel over the lossy link ($diag)",
        )
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

    private fun engineCryptoAvailable(): Boolean = CryptoCapabilities.signatures(SignatureScheme.EcdsaP256) is SignatureSupport.Blocking

    private companion object {
        // "Dozens of seeds" across the three rates; each run is a full real-crypto establishment under
        // virtual time, so this is sized to stay a fast always-on gate rather than a deep campaign.
        const val SEEDS_PER_RATE = 12
    }
}

@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.dtls.DtlsFailureReason
import com.ditchoom.webrtc.ice.IceDataTransport
import com.ditchoom.webrtc.sdp.Fingerprint
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Regression fixture for the adversarial-gate liveness criterion (RFC §5.3 #5, EXECUTION_PLAN W4 exit):
 * DTLS retransmits a lost flight with exponential backoff and **never gives up on its own**, so a peer
 * that vanishes mid-handshake would hang the session forever without a driver-enforced budget. The
 * sans-io engine has no clock; [PureKotlinDtls] owns [DtlsConfig.handshakeTimeout] and must turn a silent
 * peer into a typed [DtlsFailureReason.HandshakeTimeout], not a hang — proven here under virtual time.
 */
class DtlsHandshakeTimeoutTest {
    @Test
    fun a_silent_peer_fails_the_handshake_with_a_typed_timeout_rather_than_hanging() =
        runTest {
            val epoch = Instant.fromEpochSeconds(0)
            val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
            val dtls = PureKotlinDtls(backgroundScope, clock, DtlsConfig(handshakeTimeout = 5.seconds))

            // A transport that swallows every outbound record and never delivers an inbound one — a peer
            // that went silent after ICE nominated the pair. receive() suspends forever (an uncompleted
            // deferred), exactly what would hang the handshake if the budget were missing.
            val silentPeer =
                object : IceDataTransport {
                    override suspend fun send(packet: ReadBuffer) = Unit

                    override suspend fun receive(): ReadBuffer? = CompletableDeferred<ReadBuffer?>().await()

                    override fun close() = Unit
                }

            // A well-formed (if unmatchable) peer digest, so verification is not what fails — the
            // handshake never even completes.
            val peerFingerprint = Fingerprint("sha-256", List(32) { "AA" }.joinToString(":"))

            val thrown =
                assertFailsWith<WebRtcException> {
                    dtls.secure(silentPeer, DtlsRole.Client, peerFingerprint)
                }
            val reason = thrown.failure
            assertIs<PeerConnectionFailureReason.Dtls>(reason, "failed for a DTLS reason, was $reason")
            assertEquals(DtlsFailureReason.HandshakeTimeout, reason.reason)
        }
}

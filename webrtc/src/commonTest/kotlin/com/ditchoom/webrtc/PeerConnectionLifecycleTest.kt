@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sctp.datachannel.SctpClosedException
import com.ditchoom.webrtc.sdp.SdpType
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Regression fixtures (directive #5) for the W6 adversarial-review gate: lifecycle liveness (close before
 * ICE nomination must terminate, not hang — DEF-4) and the typed signaling-error surface (malformed SDP /
 * illegal transition carry their typed reason — the A5 API finding).
 */
class PeerConnectionLifecycleTest {
    private val epoch = Instant.fromEpochSeconds(0)

    private fun peer(scope: kotlinx.coroutines.CoroutineScope) =
        NativePeerConnection(
            scope = scope,
            clock = { epoch },
            random = Random(7),
            binder = DatagramBinder { TestNet().bind(it) },
            gathering = { it.gatherHost("10.0.0.1", 4000) },
            dtls = PlaintextDtls,
        )

    @Test
    fun close_before_connect_terminates_and_fails_pending_sends() =
        runTest {
            val net = TestNet()
            val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
            val pc =
                NativePeerConnection(
                    scope = backgroundScope,
                    clock = clock,
                    random = Random(7),
                    binder = DatagramBinder { net.bind(it) },
                    gathering = { it.gatherHost("10.0.0.9", 4000) },
                    dtls = PlaintextDtls,
                )
            val channel = pc.createDataChannel(DataChannelConfig(label = "early"))
            pc.createOffer() // starts ICE; never connected (no peer)
            pc.close()

            // Liveness: connectionState reaches Closed (does not hang at Connecting) — DEF-4.
            assertEquals(
                PeerConnectionState.Closed,
                withTimeoutOrNull(5.seconds) { pc.connectionState.first { it is PeerConnectionState.Closed } },
            )
            // A pending channel's send fails fast with the typed close vocabulary, never suspends forever.
            assertFailsWith<SctpClosedException> {
                withTimeout(5.seconds) { channel.send(textBuffer("nope")) }
            }
        }

    @Test
    fun malformed_sdp_is_a_typed_SdpFormatException() =
        runTest {
            val pc = peer(backgroundScope)
            val e = assertFailsWith<SdpFormatException> { pc.setLocalDescription(SdpType.Offer, "this is not sdp") }
            assertIs<com.ditchoom.webrtc.sdp.SdpRejectReason>(e.reason) // typed discriminant, not a string
            pc.close()
        }

    @Test
    fun illegal_transition_is_a_typed_JsepStateException() =
        runTest {
            val pc = peer(backgroundScope)
            val offer = pc.createOffer() // valid, parseable SDP; signaling stays Stable (pure generator)
            // Applying an Answer from Stable is not a legal edge (RFC 8829 §3.5.1) → typed reject.
            val e = assertFailsWith<JsepStateException> { pc.setLocalDescription(SdpType.Answer, offer) }
            assertNotNull(e.error)
            pc.close()
        }

    private fun textBuffer(s: String): ReadBuffer {
        val bytes = s.encodeToByteArray()
        val buf = BufferFactory.managed().allocate(maxOf(1, bytes.size), ByteOrder.BIG_ENDIAN)
        for (b in bytes) buf.writeByte(b)
        buf.resetForRead()
        buf.setLimit(bytes.size)
        return buf
    }
}

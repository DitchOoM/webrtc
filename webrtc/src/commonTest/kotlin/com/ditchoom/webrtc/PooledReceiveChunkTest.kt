@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.managed
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
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **A pooled receive factory never gets its chunks back.** Measured, currently red, deliberately
 * `@Ignore`d — this is an executable record of a known gap, not a gate.
 *
 * ## What it measures, and why it is not the same question [SessionBufferOwnershipTest] answers
 *
 * That fixture proves `freeNativeMemory()` is *called* on every received datagram, and it passes. This
 * one asks whether the memory actually came **back**, and it does not: a full plaintext session creates
 * **23 chunks and returns 0**.
 *
 * The two disagree because `PooledBuffer` sets its `freed` flag on the first `freeNativeMemory()` and
 * refuses `slice()` from then on **regardless of the refcount** — so the buffer-level probe reads
 * "released" while the chunk is still pinned. `PoolDrainedProbeTest` pins that exact divergence.
 *
 * ## Why 0 of 23, when the driver does release
 *
 * Zero-copy decode takes a **reference**, not a borrow. `PooledBuffer.slice()` is `addRef()` +
 * `TrackedSlice`, and the decode paths slice the datagram repeatedly:
 *
 * - `StunMessage.decode` slices once per attribute, and `RawAttribute`'s constructor slices *that* again
 *   (`value = paddedValue.sliceOf(0, length)`) — so 2 refs per attribute;
 * - `verifyMessageIntegrity` adds 3 more per authenticated check;
 * - `SctpWire.sliceOf` slices once per chunk, parameter and error cause.
 *
 * So a datagram accumulates `1 + 2N` references while the owner's `releaseReceived()` returns exactly
 * one. The receive-side ownership work is correct and is *not* what is broken here — it simply cannot
 * balance N releases with one.
 *
 * ## Why it is invisible in production today
 *
 * On Kotlin/Native Linux the shipped receive factory is a bare `BufferFactory.deterministic()`, not a
 * pool, and `NativeBufferSlice` does not override `freeNativeMemory()` — so slices are free no-ops and
 * the parent `malloc` is still released exactly once. The pin only bites under
 * `BufferPool(factory = BufferFactory.deterministic())`, which is the configuration `CLAUDE.md`
 * recommends to consumers as the workaround. That is what makes it worth a standing fixture.
 *
 * ## What would make it green
 *
 * A borrow must not take a reference. `buffer` currently offers no non-owning sub-view — `slice()` is the
 * only mechanism and it always `addRef`s on a pooled parent — so closing this needs either a
 * non-refcounting view upstream in `buffer`, or an explicit release lifecycle on decoded messages in
 * `webrtc-stun`/`webrtc-sctp`. Un-`@Ignore` this the moment either lands.
 */
@Ignore
class PooledReceiveChunkTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun a_pooled_receive_factory_gets_every_chunk_back() =
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

            val channel = alice.createDataChannel(DataChannelConfig(label = "pooled"))
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

            alice.close()
            bob.close()

            received.assertPoolDrained("a plaintext session's received datagrams")
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

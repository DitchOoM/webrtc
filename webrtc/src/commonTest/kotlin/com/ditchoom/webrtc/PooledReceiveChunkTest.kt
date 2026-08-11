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
 * **A pooled receive factory gets every chunk back.** The invariant `SessionBufferOwnershipTest` cannot
 * state, on the configuration `CLAUDE.md` recommends to consumers.
 *
 * ## Why this is a different question
 *
 * That fixture proves `freeNativeMemory()` was *called* on every received datagram. This one asks whether
 * the memory actually came **back**, and for a long time it did not: a full session created 23 chunks and
 * returned 0. The two disagree because `PooledBuffer` sets its `freed` flag on the first
 * `freeNativeMemory()` and refuses `slice()` from then on **regardless of the refcount** — so the
 * buffer-level probe reads "released" while the chunk is still pinned.
 *
 * ## What was pinning it
 *
 * Zero-copy decode takes a **reference**, not a borrow: `PooledBuffer.slice()` is `addRef()`, and
 * `TrackedSlice` re-parents to the root chunk. `StunMessage.decode` slices once per attribute and
 * `RawAttribute`'s constructor slices that again; `verifyMessageIntegrity` added three more per
 * authenticated check; `SctpWire.sliceOf` slices per chunk, parameter and cause. So a datagram
 * accumulated `1 + 2N` references while its owner returned exactly one. The receive-side ownership work
 * was never wrong — one release simply cannot balance N. `StunMessage.release()` and
 * `SctpPacket.release()` are the other half, and `CodecReleaseTest` pins each codec on its own.
 *
 * ## Why it is worth a standing fixture even though production does not hit it
 *
 * The shipped Kotlin/Native Linux receive factory is a *bare* `deterministic()`, not a pool, and
 * `NativeBufferSlice` does not override `freeNativeMemory()` — so slices are no-ops there and the parent
 * `malloc` is freed exactly once either way. The pin bites only under
 * `BufferPool(factory = BufferFactory.deterministic())`, which is precisely what the docs tell consumers
 * to use. This fixture is the reason that advice is now safe to follow.
 */
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
            assertEquals("ping", withTimeoutOrNull(timeout) { incoming.receive().first().contentAsString() })

            alice.close()
            bob.close()

            // Both probes, in this order, because together they NAME the failure: assertNoLeaks passing
            // while assertPoolDrained fails means an unreleased slice (a pin); assertNoLeaks failing means
            // a datagram nobody freed at all. Diagnosing from one of them alone is guesswork.
            received.assertNoLeaks("a plaintext session's received datagrams")
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

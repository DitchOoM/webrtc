@file:OptIn(ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Regression fixture for the **refused signaling send** that killed a peer process outright.
 *
 * `UdpSignaling` binds its own ephemeral socket at start-up, so the `interface-swap` topologies
 * (`auto-restart-native` and the rest of the `s8`/`s10`/`s11` carrier-switch family) move the route to the
 * rendezvous out from under it mid-run and the kernel answers `ENETUNREACH` (errno 101). `put`/`poll` sent
 * with no catch, and both are driven from `bg.launch { for (r in outbox) sigOut.put(...) }` in `Main.kt` —
 * an unhandled throw in a launched coroutine terminates a Kotlin/Native process, so the offerer exited
 * `rc=139` and the lane went red *while the WebRTC stack underneath it was establishing correctly*. That
 * is the "deterministic flake" shape: peer logs full of success, next to a dead process.
 *
 * Three things are pinned here, and the second is the one that is easy to get wrong.
 */
class SignalingSendFailureTest {
    /**
     * A refused send must degrade to "not acked", never propagate. Pre-fix this test does not fail — it
     * *throws out of* `put`, which is precisely the production symptom.
     */
    @Test
    fun put_returns_false_when_every_send_is_refused() =
        runTest {
            val channel = RefusingChannel()
            val signaling = signalingOver(channel)

            val acked = signaling.put(Slot.Offer, RecordId(0), "the-offer-sdp")

            assertEquals(false, acked, "a PUT whose every send was refused is not acked")
        }

    /**
     * **The retransmit budget must still be spent as retransmits.** A refused send is paced by an explicit
     * `delay(RETRANSMIT)` rather than by the reply wait, because on a dead socket `awaitReply`'s
     * `receive()` answers `Closed` *immediately* — so `withTimeoutOrNull(RETRANSMIT)` returns null having
     * spent no time at all, and the retry loop spins at full tilt for the entire 15s budget without ever
     * suspending. Under `runTest` that is not merely wasteful: with no suspension point the virtual clock
     * never advances, the outer `withTimeoutOrNull` can never fire, and the loop is genuinely infinite.
     *
     * So the assertion is on the *count*: a 15s budget at a 500ms interval is ~30 attempts. A spin would
     * hang this test rather than fail it, which is why the bound is checked explicitly instead of being
     * left implied by the test simply passing — and why the timeout is set short and explicitly rather
     * than left to `runTest`'s 60s default. **Verified by removing the `delay` and watching this hang.**
     */
    @Test
    fun a_refused_put_retransmits_on_the_interval_instead_of_spinning() =
        runTest(timeout = 10.seconds) {
            val channel = RefusingChannel()
            val signaling = signalingOver(channel)

            signaling.put(Slot.Offer, RecordId(0), "the-offer-sdp")

            assertTrue(
                channel.attempts in 25..31,
                "expected ~30 paced retransmits over the 15s budget, got ${channel.attempts} — " +
                    "a count far above this means the refused-send path stopped pacing itself",
            )
        }

    /** A refused GET is indistinguishable from a lost one: empty, and the caller polls again. */
    @Test
    fun poll_returns_empty_when_the_send_is_refused() =
        runTest {
            val signaling = signalingOver(RefusingChannel())

            val records = signaling.poll(Slot.Answer, RecordId(0))

            assertEquals(emptyList(), records, "a refused GET yields no records rather than raising")
        }

    /**
     * Cancellation is not a socket condition. The watchdog cancelling this peer has to keep unwinding —
     * absorbing it here would leave the retransmit loop running after its scope died, which is the bug the
     * guard is meant to prevent rather than cause.
     */
    @Test
    fun cancellation_still_unwinds_through_the_guard() =
        runTest {
            val signaling = signalingOver(CancellingChannel())

            assertFailsWith<CancellationException> {
                signaling.put(Slot.Offer, RecordId(0), "the-offer-sdp")
            }
        }

    private fun signalingOver(channel: AddressedDatagramChannel): UdpSignaling =
        UdpSignaling(
            channel = channel,
            rendezvous = SocketAddress.ofLiteral("127.0.0.1", 9999),
            session = "sess",
            // The fake channel is not io_uring, so no native buffer is required and freeNativeMemory() is
            // a no-op on a heap buffer.
            factory = BufferFactory.Default,
        )
}

/**
 * A channel whose every send is refused the way the kernel refuses one after the interface swap, and whose
 * `receive` answers `Closed` at once — the dead-socket pairing that makes the spin reachable. Counts
 * attempts so the pacing can be asserted rather than assumed.
 */
private class RefusingChannel : FakeChannel() {
    var attempts: Int = 0
        private set

    override suspend fun send(
        payload: ReadBuffer,
        to: SocketAddress,
        options: DatagramSendOptions,
    ) {
        attempts++
        // Stands in for socket-udp's `DatagramSendException: destination unreachable (errno=101)`. The
        // concrete type is deliberately not named: the guard is on the failure, not on socket's taxonomy,
        // and this module must not depend on that type to state the invariant.
        throw IllegalStateException("destination unreachable (errno=101)")
    }

    override suspend fun receive(): DatagramReadResult = DatagramReadResult.Closed()
}

/** A channel that cancels rather than fails, to pin the [CancellationException] arm of the guard. */
private class CancellingChannel : FakeChannel() {
    override suspend fun send(
        payload: ReadBuffer,
        to: SocketAddress,
        options: DatagramSendOptions,
    ): Unit = throw CancellationException("watchdog cancelled the peer")

    override suspend fun receive(): DatagramReadResult = DatagramReadResult.Closed()
}

/** The inert half of [AddressedDatagramChannel] both fakes share; neither ever touches a socket. */
private abstract class FakeChannel : AddressedDatagramChannel {
    private var closed = false

    override val localAddress: SocketAddress = SocketAddress.ofLiteral("127.0.0.1", 0)
    override val isOpen: Boolean get() = !closed
    override val maxWritableSize: Int = 65507
    override val capabilities: DatagramCapabilities =
        DatagramCapabilities(
            ecnSend = true,
            ecnReceive = true,
            dscpSend = true,
            dontFragment = true,
            hopLimitSend = true,
            hopLimitReceive = true,
            localAddressReceive = true,
            sourceAddressSelect = true,
            multicast = false,
        )

    override fun close() {
        closed = true
    }
}

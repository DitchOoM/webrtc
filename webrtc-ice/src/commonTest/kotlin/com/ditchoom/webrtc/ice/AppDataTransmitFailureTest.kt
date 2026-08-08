@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.ice.vnet.Vnets
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Pins the **application-data** send path's diagnostic, which was the one send path in the driver that
 * could not reach [IceAgentDriver.transmitFailed].
 *
 * `apply()` has reported a refused transmit since #142, but that path only carries what the *core* emits —
 * connectivity checks, nomination, keep-alives. Application data does not go through it: DTLS records ride
 * [IceAgentDriver.appDataTransport], whose `send` deliberately raises instead of absorbing, so DTLS is
 * never told a record went out when it did not.
 *
 * The gap was what happened next. `PureKotlinDtls`'s pump correctly *absorbs* that throw — DTLS's own
 * retransmit timer is the recovery path for a record that did not go out, and on Kotlin/Native letting it
 * escape a launched pump kills the process. Absorbed there and unreported here, a local send path
 * refusing every DTLS record was invisible on **every** surface: the session ends at
 * `IceFailureReason.ConsentExpired` or `.NoCandidatePairs`, both of which name the symptom and point at
 * the peer, while the cause was local and already known inside the driver. That is precisely the silent
 * failure `SessionDiagnostic` exists to prevent, and it is the shape CLAUDE.md warns costs an
 * investigation every time it is met in the wild.
 *
 * Both halves are asserted, because either alone would be a bug: the diagnostic must be emitted, **and**
 * the throw must still reach the caller.
 */
class AppDataTransmitFailureTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun a_refused_app_data_send_is_reported_and_still_raised() =
        runTest {
            val vnet = Vnets.flat()
            // Refusals start disabled: ICE has to establish over a working fabric first, because the seam
            // under test only exists once a pair is nominated.
            val refusals = SendRefusal()
            val binder = DatagramBinder { RefusableChannel(vnet.bind(it), refusals) }
            val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
            val alice = IceAgentDriver(IceRole.Controlling, Random(101), binder, backgroundScope, clock)
            val bob = IceAgentDriver(IceRole.Controlled, Random(102), binder, backgroundScope, clock)
            alice.start()
            bob.start()
            alice.gatherHost("10.0.0.1", 4000)
            bob.gatherHost("10.0.0.2", 5000)
            connect(alice, bob)
            connect(bob, alice)
            assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice ICE connected")
            assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob ICE connected")

            // Refuse **application data only**, leaving connectivity checks working.
            //
            // This isolation is the whole fixture, and its absence made the first version of this test
            // vacuous — it passed against the unfixed driver. Refusing every send also breaks the checks,
            // and those already report through `apply()`; `transmitFailed.first()` then returned a *check*
            // failure and the assertion held whether or not the app-data seam reported anything at all.
            // Keeping the checks alive means the only thing that can ever emit here is the seam under test.
            refusals.enabled = true

            // Half one: the caller still learns its record did not go out. Absorbing here would tell DTLS
            // to advance a retransmission policy on a lie.
            assertFailsWith<IllegalStateException> {
                alice.appDataTransport().send(textBuffer("a DTLS record"))
            }

            // Half two — the half that did not exist. Reported, classified, and attributed to the remote
            // it was headed for.
            val failure = assertNotNull(withTimeoutOrNull(timeout) { alice.transmitFailed.first() }, "transmitFailed emitted")
            assertEquals(
                IceTransmitFailureReason.Unknown,
                failure.reason,
                "an untranslated binder classifies as Unknown, which is retryable",
            )
            assertEquals(SendRefusal.MESSAGE, failure.cause.message, "the diagnostic carries what the socket actually raised")
        }

    // Scripted signaling: hand [from]'s credentials + candidates to [to] (the trickle seam, direct).
    private fun connect(
        to: IceAgentDriver,
        from: IceAgentDriver,
    ) {
        to.setRemoteCredentials(from.localCredentials)
        from.localCandidates.forEach { to.addRemoteCandidate(it) }
    }

    private suspend fun IceAgentDriver.awaitConnected(): IceConnectionState =
        state.first {
            when (it) {
                is IceConnectionState.Connected, is IceConnectionState.Completed -> true
                is IceConnectionState.Failed -> error("expected a connection, but ICE failed: ${it.reason}")
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
}

/** Shared switch so every channel this binder hands out starts refusing at the same instant. */
private class SendRefusal {
    var enabled: Boolean = false

    companion object {
        const val MESSAGE = "destination unreachable (errno=101)"
    }
}

private const val STUN_MAGIC_COOKIE = 0x2112A442
private const val STUN_HEADER_BYTES = 20

/**
 * A vnet channel that, once [refusal] is armed, refuses every **non-STUN** send — the reduced form of an
 * interface being swapped out from under a nominated pair, narrowed to application data so the
 * connectivity checks sharing this socket keep working (see the call site for why that isolation is what
 * makes the assertion mean anything).
 *
 * The refusal is a plain exception rather than an [IceTransmitException]: this stands in for an
 * **untranslated** binder (the vnet itself, or an app sharing a demuxed socket with QUIC-P2P), which is
 * the case that must classify as [IceTransmitFailureReason.Unknown] and stay retryable. A binder that
 * does translate is the socketMain path, unreachable from `commonTest`.
 */
private class RefusableChannel(
    private val delegate: AddressedDatagramChannel,
    private val refusal: SendRefusal,
) : AddressedDatagramChannel by delegate {
    override suspend fun send(
        payload: ReadBuffer,
        to: SocketAddress,
        options: DatagramSendOptions,
    ) {
        if (refusal.enabled && !payload.looksLikeStun()) throw IllegalStateException(SendRefusal.MESSAGE)
        delegate.send(payload, to, options)
    }

    // The RFC 7983 demux test, on the send side: a STUN message carries the magic cookie at bytes 4..8.
    // Same discriminant the driver's own receive path uses, restated here rather than reached for, so the
    // fixture does not depend on an internal.
    private fun ReadBuffer.looksLikeStun(): Boolean {
        val start = position()
        if (limit() - start < STUN_HEADER_BYTES) return false
        var cookie = 0
        for (i in 4 until 8) cookie = (cookie shl 8) or (get(start + i).toInt() and 0xFF)
        return cookie == STUN_MAGIC_COOKIE
    }

    // Delegation covers the rest, but these are re-stated because `by` captures the delegate's values at
    // construction and these are the ones the driver reads per-send.
    override val localAddress: SocketAddress get() = delegate.localAddress
    override val isOpen: Boolean get() = delegate.isOpen
    override val maxWritableSize: Int get() = delegate.maxWritableSize
    override val capabilities: DatagramCapabilities get() = delegate.capabilities

    override suspend fun receive(): DatagramReadResult = delegate.receive()

    override fun close() = delegate.close()
}

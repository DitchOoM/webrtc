@file:OptIn(ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.Datagram
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.Ecn
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.vnet.NatProfile
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.stun.RawAttribute
import com.ditchoom.webrtc.stun.StunClass
import com.ditchoom.webrtc.stun.StunDecodeResult
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.StunMessageBuilder
import com.ditchoom.webrtc.stun.StunMethod
import com.ditchoom.webrtc.stun.TransportAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Regression fixture for the **W7 real-network gathering-factory bug** (HANDOFF W7 Phase 1): the srflx
 * (and relay) gathering drivers built their STUN datagrams with the ambient `BufferFactory.Default` —
 * a **GC-heap** buffer on native — instead of the injected [IceConfig.bufferFactory]. On the in-memory
 * vnet that was invisible (a lossless channel copies any buffer), so this bug shipped through W3. But a
 * real `socket-udp` send is io_uring, and io_uring **rejects a heap buffer** ("send requires a
 * native-memory buffer") — so on a real network `gatherServerReflexive` crashed before it ever sent a
 * Binding, and no srflx/relay candidate was gathered.
 *
 * The vnet couldn't catch it because it accepts any buffer. This fixture makes the bug deterministic by
 * modeling io_uring's requirement at the seam: [NativeOnlyChannel.send] rejects any datagram that was
 * **not** allocated by the injected [TaggingBufferFactory]. That turns "used the wrong factory" from a
 * silent, real-network-only crash into a failing common test that runs on every platform under `runTest`.
 */
class GatheringBufferFactoryTest {
    private val stunServer = SocketAddress.ofLiteral("192.0.2.1", 3478)
    private val local = SocketAddress.ofLiteral("10.0.0.1", 5000)
    private val epoch = Instant.fromEpochSeconds(0)

    /** The fix: when the injected factory is threaded through, the datagram is native → send accepted →
     *  the srflx round-trip completes. This assertion FAILS against the pre-fix `.encode()` (heap factory). */
    @Test
    fun srflx_gathering_builds_its_stun_datagram_from_the_injected_factory() =
        runTest {
            val factory = TaggingBufferFactory()
            val srflx = SocketAddress.ofLiteral("203.0.113.7", 55555).toTransportAddress()
            val channel = NativeOnlyChannel(local, factory, srflx)

            val result = gatherServerReflexive(channel, stunServer, Random(1), bufferFactory = factory)

            assertIs<ServerReflexiveResult.Discovered>(result, "srflx gathered over a native-only socket")
            assertEquals(srflx, result.address)
        }

    /**
     * The bug, pinned: omitting the factory (as the pre-fix code did via `.encode()`) builds the Binding
     * from `BufferFactory.Default`, which the native-only socket rejects exactly as real io_uring does.
     *
     * **This used to assert the raise itself** (`assertFailsWith<IllegalStateException>`). It cannot any
     * more, and the reason is the point of webrtc#143: an escaped throw from `send` was destroying far
     * more than the datagram, so the gathering loop now tolerates a refused transmission and retransmits,
     * exactly as it already tolerates a dropped one.
     *
     * Tolerating is not the same as hiding. A gather where **nothing ever left the socket** answers
     * [ServerReflexiveResult.Unavailable.SendFailed] rather than `NoResponse`, so a local misconfiguration
     * still names itself instead of presenting as an unreachable STUN server — and it now does so as a
     * typed result the caller can branch on rather than an `IllegalStateException` propagating out of a
     * gather. The original cause is carried through intact and asserted below, so nothing this fixture
     * used to prove has been given up.
     */
    @Test
    fun srflx_gathering_with_the_default_heap_factory_reports_that_it_never_sent() =
        runTest {
            val factory = TaggingBufferFactory()
            val srflx = SocketAddress.ofLiteral("203.0.113.7", 55555).toTransportAddress()
            val channel = NativeOnlyChannel(local, factory, srflx)

            val result = gatherServerReflexive(channel, stunServer, Random(1)) // default (heap) factory

            val failed =
                assertIs<ServerReflexiveResult.Unavailable.SendFailed>(
                    result,
                    "a heap factory on a native-only socket must report that nothing was transmitted, " +
                        "never NoResponse — the STUN server was never asked",
                )
            assertEquals("send requires a native-memory buffer", failed.cause.message)
        }

    /**
     * The anti-vacuity direction for the test above: a socket that accepts the datagram but whose server
     * never answers must still report [ServerReflexiveResult.Unavailable.NoResponse]. Without this,
     * `SendFailed` could be returned for every unsuccessful gather and the distinction it exists to draw
     * would be worthless.
     */
    @Test
    fun a_silent_server_is_still_no_response_not_a_send_failure() =
        runTest {
            val factory = TaggingBufferFactory()
            val channel = SilentChannel(local)

            val result = gatherServerReflexive(channel, stunServer, Random(1), bufferFactory = factory)

            assertIs<ServerReflexiveResult.Unavailable.NoResponse>(
                result,
                "the datagram went out and the server said nothing — that is the server's silence, not ours",
            )
        }

    /**
     * The DRIVER-level guard — this is the wiring that actually shipped the bug. The two functions above
     * are only reached correctly if [IceAgentDriver] threads its [IceConfig.bufferFactory] into
     * `gatherServerReflexive` (srflx) AND `TurnAllocation` (relay). Here the binder wraps the vnet in a
     * [FactoryAssertingChannel] that rejects any datagram not built from the injected factory (io_uring's
     * rule), and gathering runs against real vnet STUN + TURN servers. All three candidate types appear
     * ONLY if both wiring lines are present — reverting either (`IceAgentDriver` dropping the
     * `bufferFactory`/`config.bufferFactory` argument) drops srflx or relay and fails this test, which the
     * function-level tests above do not catch (they inject the factory themselves).
     */
    @Test
    fun the_driver_threads_the_injected_factory_into_srflx_and_relay_gathering() =
        runTest {
            val factory = TaggingBufferFactory()
            val meetup = Vnets.meetup(backgroundScope, profileA = NatProfile.FullCone, profileB = NatProfile.FullCone)
            val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
            val binder = DatagramBinder { FactoryAssertingChannel(meetup.vnet.bind(it), factory) }

            val driver =
                IceAgentDriver(
                    role = IceRole.Controlling,
                    random = Random(7),
                    binder = binder,
                    scope = backgroundScope,
                    clock = clock,
                    config = IceConfig(bufferFactory = factory),
                )
            driver.start()
            driver.gatherHost("10.0.0.2", 5000, stunServer = meetup.stunAddress)
            driver.gatherRelay(meetup.turnAddress, Vnets.TURN_USERNAME, Vnets.TURN_PASSWORD, "10.0.0.2", 6000)

            val candidates = driver.localCandidates
            assertTrue(candidates.any { it is IceCandidate.Host }, "host gathered")
            assertTrue(
                candidates.any { it is IceCandidate.ServerReflexive },
                "srflx gathered — driver threaded the factory into gatherServerReflexive (F1)",
            )
            assertTrue(
                candidates.any { it is IceCandidate.Relayed },
                "relay gathered — driver threaded the factory into TurnAllocation (F2)",
            )
        }
}

/**
 * A channel that accepts every datagram and never answers — the STUN server that is simply not there.
 * The counterweight to [NativeOnlyChannel]: it proves `NoResponse` and `SendFailed` are actually told
 * apart, rather than the latter being returned for every unsuccessful gather.
 */
private class SilentChannel(
    override val localAddress: SocketAddress,
) : AddressedDatagramChannel {
    private val inbound = Channel<Datagram>(Channel.UNLIMITED)
    private var closed = false

    override val isOpen: Boolean get() = !closed
    override val maxWritableSize: Int = 65507
    override val capabilities: DatagramCapabilities = DatagramCapabilities()

    override suspend fun receive(): DatagramReadResult {
        val datagram = inbound.receiveCatching().getOrNull()
        return if (datagram != null) DatagramReadResult.Received(datagram) else DatagramReadResult.Closed()
    }

    override suspend fun send(
        payload: ReadBuffer,
        to: SocketAddress,
        options: DatagramSendOptions,
    ) = Unit // accepted, and deliberately unanswered

    override fun close() {
        closed = true
        inbound.close()
    }
}

/**
 * Wraps a vnet [AddressedDatagramChannel] and rejects any `send` whose payload was NOT allocated by [factory] —
 * modeling io_uring's native-buffer requirement over the vnet's lossless channel. Only the driver's own
 * channels are wrapped (the binder), so the vnet's STUN/TURN servers reply normally; this asserts purely
 * that the DRIVER's outbound gathering datagrams came from the injected factory.
 */
private class FactoryAssertingChannel(
    private val inner: AddressedDatagramChannel,
    private val factory: TaggingBufferFactory,
) : AddressedDatagramChannel {
    override val localAddress: SocketAddress get() = inner.localAddress
    override val isOpen: Boolean get() = inner.isOpen
    override val maxWritableSize: Int get() = inner.maxWritableSize
    override val capabilities: DatagramCapabilities get() = inner.capabilities

    override suspend fun receive(): DatagramReadResult = inner.receive()

    override suspend fun send(
        payload: ReadBuffer,
        to: SocketAddress,
        options: DatagramSendOptions,
    ) {
        check(factory.owns(payload)) { "send requires a native-memory buffer" }
        inner.send(payload, to, options)
    }

    override fun close() = inner.close()
}

/**
 * A [BufferFactory] that stamps every buffer it allocates so a downstream channel can prove a datagram
 * was built from THIS factory — the deterministic stand-in for "native-backed" that a real io_uring send
 * requires. Delegates all allocation to [BufferFactory.Default]; only the provenance is tracked.
 */
private class TaggingBufferFactory(
    private val delegate: BufferFactory = BufferFactory.Default,
) : BufferFactory {
    private val mine = mutableListOf<PlatformBuffer>()

    override fun allocate(
        size: Int,
        byteOrder: ByteOrder,
    ): PlatformBuffer = tag(delegate.allocate(size, byteOrder))

    override fun wrap(
        array: ByteArray,
        byteOrder: ByteOrder,
    ): PlatformBuffer = tag(delegate.wrap(array, byteOrder))

    private fun tag(buffer: PlatformBuffer): PlatformBuffer = Tagged(buffer).also { mine += it }

    /** True iff [buffer] is one this factory allocated, or a [Tagged] slice of one. */
    fun owns(buffer: ReadBuffer): Boolean = mine.any { it === buffer }

    /**
     * Provenance has to survive `slice()`. A retransmitting sender hands the socket a **fresh read view**
     * of the same encoded request on every attempt (see `TurnAllocation.request` and `StunTransaction`),
     * and buffer's contract is that such a slice aliases the parent's storage — so a slice of a
     * native-backed buffer is itself native-backed and a perfectly legal io_uring send. Tracking
     * provenance by reference identity alone would call that slice a heap buffer and reject it, which is
     * a fact about this stand-in rather than about the code under test.
     */
    private inner class Tagged(
        private val inner: PlatformBuffer,
    ) : PlatformBuffer by inner {
        override fun slice(byteOrder: ByteOrder): PlatformBuffer = tag(inner.slice(byteOrder))
    }
}

/**
 * An in-memory [AddressedDatagramChannel] that rejects any datagram NOT allocated by [factory] — the exact
 * behavior of `socket-udp`'s io_uring `send` on a heap buffer, which the vnet's lossless channel does
 * not enforce. On an accepted Binding it answers as the STUN server would (XOR-MAPPED-ADDRESS = [srflx])
 * so the gather completes, proving the round-trip works when (and only when) the injected factory is used.
 */
private class NativeOnlyChannel(
    override val localAddress: SocketAddress,
    private val factory: TaggingBufferFactory,
    private val srflx: TransportAddress,
) : AddressedDatagramChannel {
    private val inbound = Channel<Datagram>(Channel.UNLIMITED)
    private var closed = false

    override val isOpen: Boolean get() = !closed
    override val maxWritableSize: Int = MAX_UDP_PAYLOAD
    override val capabilities: DatagramCapabilities = CAPABILITIES

    override suspend fun receive(): DatagramReadResult {
        val datagram = inbound.receiveCatching().getOrNull()
        return if (datagram != null) DatagramReadResult.Received(datagram) else DatagramReadResult.Closed()
    }

    override suspend fun send(
        payload: ReadBuffer,
        to: SocketAddress,
        options: DatagramSendOptions,
    ) {
        check(!closed) { "channel is closed" }
        // The whole point: a datagram not built from the injected (native) factory is rejected, exactly
        // as io_uring rejects a GC-heap buffer. Same message the real socket-udp send throws.
        check(factory.owns(payload)) { "send requires a native-memory buffer" }

        // Reply as the STUN server: reflect an XOR-MAPPED-ADDRESS so gatherServerReflexive → Discovered.
        val request = (StunMessage.decode(payload.slice()) as? StunDecodeResult.Success)?.message ?: return
        val response =
            StunMessageBuilder
                .of(StunClass.SuccessResponse, StunMethod.Binding, request.transactionId)
                .add(RawAttribute.ofXorMappedAddress(srflx, request.transactionId))
                .addFingerprint()
                .encode()
        inbound.trySend(Datagram(payload = response, peer = to, ecn = Ecn.Unknown))
    }

    override fun close() {
        closed = true
        inbound.close()
    }

    private companion object {
        const val MAX_UDP_PAYLOAD = 65507

        val CAPABILITIES =
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
    }
}

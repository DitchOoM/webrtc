@file:OptIn(ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.vnet.Meetup
import com.ditchoom.webrtc.ice.vnet.NatProfile
import com.ditchoom.webrtc.ice.vnet.Vnets
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Regression fixture for **#131**: an injected `bufferFactory` that the platform's send path cannot
 * transmit from must be refused at the bind that precedes the first send, not discovered on the first
 * connectivity check.
 *
 * The failure this replaces was not a crash-at-the-wrong-place so much as a crash *attributed* to the
 * wrong thing. `IoUringDatagramChannelCore` raising "send requires a native-memory buffer" after
 * gathering had already succeeded reads, to the application above, as a network that went away —
 * candidates were produced, the session looked live, and the thing that was actually wrong (a
 * constructor argument) is named nowhere in the trace.
 *
 * What made this fixable at all is that the requirement is now **answerable**: buffer #328 added
 * `DatagramCapabilities.requiresNativeMemoryBuffers` and socket #281 made every socket-udp actual
 * advertise it, so the question can be put to the channel instead of inferred from a platform table.
 * [NativeMemoryDemandingChannel] below is that advertisement, and nothing else — it is the vnet channel
 * with linux/Apple's answer to one field, which is why these cases run on every target under `runTest`
 * rather than only where io_uring does.
 */
class UnsendableBufferFactoryTest {
    private val epoch = Instant.fromEpochSeconds(0)

    /**
     * The premise every case here rests on, asserted rather than assumed.
     *
     * This assertion has already earned its place: the fixture first used `BufferFactory.managed()` as
     * the unsendable factory, on the reasonable-sounding grounds that it is documented as the GC-heap
     * one. On **JS `managed()` is an alias for `Default`**, whose buffers do carry a native address, so
     * the three refusal cases were passing vacuously there — and this assertion is what said so instead
     * of letting a green suite claim coverage it did not have. [NonNativeBufferFactory] replaced it
     * precisely because it answers the same on every target.
     */
    @Test
    fun the_two_factories_these_cases_rely_on_are_what_they_claim() {
        assertFalse(
            NonNativeBufferFactory().backsNativeMemory(),
            "the unsendable factory must have no native address anywhere, or the refusal cases are vacuous",
        )
        assertTrue(
            networkBuffer().backsNativeMemory(),
            "networkBuffer() promises a factory a real socket can send from; that is its whole contract",
        )
    }

    /** A heap factory on a channel that demands a raw address is refused at `gatherHost`'s bind. */
    @Test
    fun gather_host_refuses_a_factory_the_send_path_cannot_transmit() =
        runTest {
            val driver = driverOver(NonNativeBufferFactory(), demandsNativeMemory = true)

            val thrown =
                assertFailsWith<UnsendableBufferFactoryException> {
                    driver.gatherHost("10.0.0.2", 5000)
                }

            assertEquals(
                WireBufferSeam.IceBufferFactory,
                thrown.seam,
                "the exception must name the seam to change, which is the whole of #131",
            )
        }

    /**
     * The same refusal on the relay path, and it must arrive **before** `allocate()`.
     *
     * This is the case worth having separately: a TURN Allocate request is itself a send, so a check
     * deferred by even one statement would present this misconfiguration as an allocation that timed out
     * — [RelayGatheringResult.Unavailable] — which is a *returned value*, not a raise, and one that
     * points at the TURN server rather than at the caller's own config.
     */
    @Test
    fun gather_relay_refuses_before_the_allocate_request_can_look_like_a_turn_timeout() =
        runTest {
            val meetup = Vnets.meetup(backgroundScope, profileA = NatProfile.FullCone, profileB = NatProfile.FullCone)
            val driver = driverOver(NonNativeBufferFactory(), demandsNativeMemory = true, meetup = meetup)

            assertFailsWith<UnsendableBufferFactoryException>(
                "a refused relay gather must raise the configuration error, not return Unavailable",
            ) {
                driver.gatherRelay(meetup.turnAddress, Vnets.TURN_USERNAME, Vnets.TURN_PASSWORD, "10.0.0.2", 6000)
            }
        }

    /**
     * Anti-vacuity #1: the check must not fire on a channel that accepts heap buffers.
     *
     * Without this the check could be "reject a heap factory", which is the phrasing buffer's own KDoc
     * warns against — the JVM/NIO and Node send paths take a heap buffer quite happily, and so does every
     * in-memory endpoint, so that version would break three working configurations to fix one.
     */
    @Test
    fun a_channel_that_accepts_heap_buffers_is_never_probed_or_refused() =
        runTest {
            val driver = driverOver(NonNativeBufferFactory(), demandsNativeMemory = false)

            val host = driver.gatherHost("10.0.0.2", 5000)

            assertEquals(5000, host.address.port.toInt(), "the vnet bind stands — a heap factory is fine here")
        }

    /**
     * Anti-vacuity #2: a native-backed factory passes on a channel that demands one. Together with the
     * first case this pins both directions of the discriminant rather than one, so a check that simply
     * threw on every native-memory-demanding channel could not pass.
     */
    @Test
    fun a_native_backed_factory_is_accepted_by_a_channel_that_demands_one() =
        runTest {
            val driver = driverOver(networkBuffer(), demandsNativeMemory = true)

            val host = driver.gatherHost("10.0.0.2", 5000)

            assertEquals(5000, host.address.port.toInt(), "networkBuffer() is exactly what this channel asked for")
        }

    private fun kotlinx.coroutines.test.TestScope.driverOver(
        factory: BufferFactory,
        demandsNativeMemory: Boolean,
        meetup: Meetup = Vnets.meetup(backgroundScope, profileA = NatProfile.FullCone, profileB = NatProfile.FullCone),
    ): IceAgentDriver =
        IceAgentDriver(
            role = IceRole.Controlling,
            random = Random(7),
            binder = DatagramBinder { NativeMemoryDemandingChannel(meetup.vnet.bind(it), demandsNativeMemory) },
            scope = backgroundScope,
            clock = { epoch + testScheduler.currentTime.milliseconds },
            config = IceConfig(bufferFactory = factory),
        ).also { it.start() }
}

/**
 * The vnet channel with one field answered the way a real socket answers it — socket-udp's io_uring and
 * `NWConnection` actuals advertise `requiresNativeMemoryBuffers = true`, its NIO and Node actuals `false`
 * (socket #281). Everything else delegates, so these cases exercise the real gathering path.
 *
 * Deliberately NOT a channel that *rejects* heap sends (`GatheringBufferFactoryTest.NativeOnlyChannel` is
 * that, and models the same platform rule one layer lower). The point of #131 is that nothing should get
 * far enough to be rejected, so the fixture must prove the refusal happens with the send path untouched.
 */
private class NativeMemoryDemandingChannel(
    private val delegate: AddressedDatagramChannel,
    demandsNativeMemory: Boolean,
) : AddressedDatagramChannel by delegate {
    override val capabilities: DatagramCapabilities =
        DatagramCapabilities(requiresNativeMemoryBuffers = demandsNativeMemory)

    override suspend fun receive(): DatagramReadResult = delegate.receive()

    override suspend fun send(
        payload: ReadBuffer,
        to: SocketAddress,
        options: DatagramSendOptions,
    ): Unit = delegate.send(payload, to, options)
}

/**
 * A factory whose buffers carry **no native address on any target** — Kotlin/Native Linux's
 * `ByteArrayBuffer`, modelled portably.
 *
 * `BufferFactory.managed()` is the obvious candidate and is the wrong one: it is documented as the
 * GC-heap factory, but on JS it is an alias for `Default`, so the refusal cases would pass there without
 * testing anything. Hiding the address explicitly makes "unsendable" a property of the fixture rather
 * than of whichever platform happens to be running it.
 *
 * The mechanism is `nativeMemoryAccess`'s own resolution rule: it answers `this as? NativeMemoryAccess`,
 * else `unwrapFully()`'s. [AddressHidingBuffer] is not a `NativeMemoryAccess`, and pins `unwrap()` to
 * itself so the walk stops there instead of reaching the native buffer underneath.
 */
private class NonNativeBufferFactory(
    private val delegate: BufferFactory = BufferFactory.Default,
) : BufferFactory by delegate {
    override fun allocate(
        size: Int,
        byteOrder: ByteOrder,
    ): PlatformBuffer = AddressHidingBuffer(delegate.allocate(size, byteOrder))
}

private class AddressHidingBuffer(
    private val inner: PlatformBuffer,
) : PlatformBuffer by inner {
    @Deprecated("unwrap() only peels one layer", ReplaceWith("this"))
    override fun unwrap(): PlatformBuffer = this

    override fun slice(byteOrder: ByteOrder): PlatformBuffer = AddressHidingBuffer(inner.slice(byteOrder))
}

@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Directive #6: the [BufferFactory] is injected through the association's hot paths, and allocation is
 * **bounded** — proportional to real protocol work (packets, reassembly), never leaking per timer tick.
 * The SCTP core allocates every encoded packet and every reassembly/send copy via
 * [SctpConfig.bufferFactory]; injecting a [CountingBufferFactory] proves the seam is threaded end to end
 * and that an idle established association does not allocate on each tick (steady RSS, ARCHITECTURE §5.3 #1).
 */
class BufferLifecycleTest {
    private val stream = StreamId(0)
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun buffer_factory_is_injected_through_hot_paths() {
        val factory = CountingBufferFactory(BufferFactory.managed())
        val config = SctpConfig(bufferFactory = factory)
        val a = SctpAssociation(config, Random(1))
        val b = SctpAssociation(config, Random(2))
        val sim = SctpSimWith(a, b)

        sim.associateA()
        sim.run()
        val afterHandshake = factory.allocations
        assertTrue(afterHandshake > 0, "the injected factory encoded the handshake packets")

        for (i in 0 until 10) {
            sim.postA(SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(20, seed = i)))
        }
        sim.run()
        assertTrue(factory.allocations > afterHandshake, "data + SACK packets and reassembly copies used the factory")
        assertEquals(10, sim.inboxB.size, "all messages delivered")
    }

    @Test
    fun idle_established_association_does_not_allocate_per_tick() {
        val factory = CountingBufferFactory(BufferFactory.managed())
        val config = SctpConfig(bufferFactory = factory)
        val a = SctpAssociation(config, Random(3))
        val b = SctpAssociation(config, Random(4))
        val sim = SctpSimWith(a, b)
        sim.associateA()
        sim.run()

        val baseline = factory.allocations
        // Make the quiescence premise explicit (review finding R5-4): a drained, established association
        // arms no timer, so a driver would never even fire TimerFired here — and if it does, it must be a
        // pure no-op that allocates nothing (no re-arming timer silently allocating each period).
        var now = epoch
        assertEquals(null, a.nextDeadline(now), "idle association arms no timer")
        assertEquals(null, b.nextDeadline(now), "idle association arms no timer")
        repeat(1000) {
            now += kotlin.time.Duration.parse("1s")
            a.handle(SctpEvent.TimerFired, now)
            b.handle(SctpEvent.TimerFired, now)
        }
        assertEquals(baseline, factory.allocations, "an idle association allocates nothing per timer tick")
    }

    /**
     * Directive #6, the send path specifically: **one owned copy per fragment, not two.** The
     * retransmission queue must own bytes past `send()` (the caller's payload is borrowed for the
     * duration of the `handle` call), so one copy is architecturally required — and it is the encode into
     * the wire packet. `fragment()` therefore hands out zero-copy views, including the sub-MTU case where
     * it hands out the whole payload as one view.
     *
     * Counted on the sender alone (the event is fed to `a` directly, not through the sim) so no peer SACK
     * or reassembly allocation is included. The earlier two-copy path allocated `2 * fragments` here.
     */
    @Test
    fun send_allocates_one_buffer_per_fragment() {
        val factory = CountingBufferFactory(BufferFactory.managed())
        val config = SctpConfig(bufferFactory = factory)
        val a = SctpAssociation(config, Random(5))
        val b = SctpAssociation(config, Random(6))
        val sim = SctpSimWith(a, b)
        sim.associateA()
        sim.run()

        val beforeSmall = factory.allocations
        a.handle(
            SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(config.maxPayloadBytes)),
            epoch,
        )
        assertEquals(1, factory.allocations - beforeSmall, "a sub-MTU message costs exactly one buffer: its encoded packet")

        val fragments = 3
        val beforeLarge = factory.allocations
        a.handle(
            SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(config.maxPayloadBytes * fragments)),
            epoch,
        )
        assertEquals(
            fragments,
            factory.allocations - beforeLarge,
            "a fragmented message costs exactly one buffer per fragment — the fragments themselves are views",
        )
        // That those views carry the right regions is proven end to end by
        // SctpAssociationTest.large_message_is_fragmented_and_reassembled (11 fragments, byte-exact).
    }

    /**
     * A retransmit re-sends the *same* encoded packet (the queue holds the wire bytes, not the payload),
     * so it must still be byte-identical to the original transmission — the property the pre-encode
     * relies on. Drives one association's T3-rtx directly: send, let the timer expire with no SACK, and
     * compare the two datagrams byte for byte.
     */
    @Test
    fun retransmit_reemits_byte_identical_packet() {
        val config = SctpConfig()
        val a = SctpAssociation(config, Random(7))
        val b = SctpAssociation(config, Random(8))
        val sim = SctpSimWith(a, b)
        sim.associateA()
        sim.run()

        var now = epoch
        val first =
            a
                .handle(SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(64)), now)
                .filterIsInstance<SctpOutput.Transmit>()
                .single()
                .packet
                .bytes()

        // No SACK ever arrives: fire timers until the T3-rtx deadline puts the chunk back on the wire.
        now = assertNotNull(a.nextDeadline(now), "an outstanding chunk arms T3-rtx")
        val again =
            a
                .handle(SctpEvent.TimerFired, now)
                .filterIsInstance<SctpOutput.Transmit>()
                .single()
                .packet
                .bytes()

        assertEquals(first, again, "the retransmit is the same wire packet, CRC included")
    }
}

// A thin SctpSim variant that drives two caller-provided associations (so the test owns the injected
// factory). Reuses the conductor by delegating to a fresh SctpSim is not possible (it builds its own
// associations), so this mirrors its loop against the given pair.
@OptIn(ExperimentalTime::class)
internal class SctpSimWith(
    private val a: SctpAssociation,
    private val b: SctpAssociation,
) {
    private val epoch = Instant.fromEpochSeconds(0)
    private var now: Instant = epoch

    private class InFlight(
        val toB: Boolean,
        val payload: com.ditchoom.buffer.ReadBuffer,
        val at: Instant,
    )

    private val queue = ArrayList<InFlight>()
    val inboxB = ArrayList<SctpOutput.MessageReceived>()

    fun associateA() = apply(true, a.handle(SctpEvent.Associate, now))

    fun postA(event: SctpEvent) = apply(true, a.handle(event, now))

    fun run(maxSteps: Int = 200_000) {
        var steps = 0
        while (steps++ < maxSteps) {
            val ready = queue.filter { it.at <= now }
            if (ready.isNotEmpty()) {
                queue.removeAll(ready)
                for (p in ready) {
                    val assoc = if (p.toB) b else a
                    p.payload.position(0)
                    apply(!p.toB, assoc.handle(SctpEvent.DatagramReceived(p.payload.slice()), now))
                }
                continue
            }
            val aDl = a.nextDeadline(now)
            val bDl = b.nextDeadline(now)
            var fired = false
            if (aDl != null && aDl <= now) {
                apply(true, a.handle(SctpEvent.TimerFired, now))
                fired = true
            }
            if (bDl != null && bDl <= now) {
                apply(false, b.handle(SctpEvent.TimerFired, now))
                fired = true
            }
            if (fired) continue
            val next = listOfNotNull(queue.minOfOrNull { it.at }, aDl, bDl).minOrNull() ?: break
            if (next <= now) break
            now = next
        }
    }

    private fun apply(
        fromA: Boolean,
        outputs: List<SctpOutput>,
    ) {
        var consumed: ArrayList<DeliveryReceipt>? = null
        for (output in outputs) {
            when (output) {
                is SctpOutput.Transmit -> {
                    output.packet.position(0)
                    queue += InFlight(toB = fromA, payload = output.packet.slice(), at = now)
                }
                is SctpOutput.MessageReceived -> {
                    if (!fromA) inboxB += output
                    // Credited like [SctpSim] does, and for the same reason: this stand-in is the driver,
                    // and a driver that never returns a receipt shrinks its own a_rwnd to nothing.
                    val receipts = consumed ?: ArrayList<DeliveryReceipt>().also { consumed = it }
                    receipts += output.receipt
                }
                else -> Unit
            }
        }
        val receipts = consumed ?: return
        val endpoint = if (fromA) a else b
        for (receipt in receipts) apply(fromA, endpoint.handle(SctpEvent.MessageConsumed(receipt), now))
    }
}

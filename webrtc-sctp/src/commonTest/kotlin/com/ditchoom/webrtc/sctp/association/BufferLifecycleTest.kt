@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Directive #6: the [BufferFactory] is injected through the association's hot paths, and allocation is
 * **bounded** — proportional to real protocol work (packets, reassembly), never leaking per timer tick.
 * The SCTP core allocates every encoded packet and every reassembly/send copy via
 * [SctpConfig.bufferFactory]; injecting a [CountingBufferFactory] proves the seam is threaded end to end
 * and that an idle established association does not allocate on each tick (steady RSS, RFC §5.3 #1).
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
        // Fire many timer ticks with no application data: an established, drained association has no
        // armed timers, so this must not allocate at all (steady RSS — no per-tick leak).
        var now = epoch
        repeat(1000) {
            now += kotlin.time.Duration.parse("1s")
            a.handle(SctpEvent.TimerFired, now)
            b.handle(SctpEvent.TimerFired, now)
        }
        assertEquals(baseline, factory.allocations, "an idle association allocates nothing per timer tick")
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
        for (output in outputs) {
            when (output) {
                is SctpOutput.Transmit -> {
                    output.packet.position(0)
                    queue += InFlight(toB = fromA, payload = output.packet.slice(), at = now)
                }
                is SctpOutput.MessageReceived -> if (!fromA) inboxB += output
                else -> Unit
            }
        }
    }
}

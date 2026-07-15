@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime

/** A read-ready buffer of [n] deterministic bytes (a ramp so reassembly order is checkable). */
internal fun payload(
    n: Int,
    seed: Int = 0,
): PlatformBuffer {
    val buf = BufferFactory.managed().allocate(maxOf(1, n), ByteOrder.BIG_ENDIAN)
    for (i in 0 until n) buf.writeByte(((i + seed) and 0xFF).toByte())
    buf.resetForRead()
    buf.setLimit(n)
    return buf
}

internal fun ReadBuffer.bytes(): List<Int> {
    val out = ArrayList<Int>(remaining())
    for (i in position() until limit()) out += get(i).toInt() and 0xFF
    return out
}

private val STREAM0 = StreamId(0)

class SctpAssociationTest {
    @Test
    fun four_way_handshake_establishes_both_endpoints() {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        assertEquals(SctpAssociationState.Established, sim.a.state, "active opener reaches Established")
        assertEquals(SctpAssociationState.Established, sim.b.state, "passive responder reaches Established")
    }

    @Test
    fun ordered_reliable_message_delivered_intact() {
        val sim = SctpSim()
        sim.associateA()
        sim.run()

        val message = payload(200, seed = 7)
        sim.post(toA = true, SctpEvent.SendMessage(SctpSendOptions(STREAM0, PayloadProtocolId.WebRtcBinary), message))
        sim.run()

        assertEquals(1, sim.inboxB.size, "one message delivered to B")
        assertEquals(payload(200, seed = 7).bytes(), sim.inboxB.first().payload.bytes(), "payload intact")
        assertEquals(PayloadProtocolId.WebRtcBinary, sim.inboxB.first().payloadProtocolId)
        assertTrue(!sim.inboxB.first().unordered)
    }

    @Test
    fun large_message_is_fragmented_and_reassembled() {
        val sim = SctpSim(config = SctpConfig(maxPayloadBytes = 100))
        sim.associateA()
        sim.run()

        val big = payload(1050, seed = 3) // 11 fragments at MTU 100
        sim.post(toA = true, SctpEvent.SendMessage(SctpSendOptions(STREAM0, PayloadProtocolId.WebRtcBinary), big))
        sim.run()

        assertEquals(1, sim.inboxB.size)
        assertEquals(payload(1050, seed = 3).bytes(), sim.inboxB.first().payload.bytes(), "reassembled bytes match")
    }

    @Test
    fun bidirectional_exchange() {
        val sim = SctpSim()
        sim.associateA()
        sim.run()

        sim.post(toA = true, SctpEvent.SendMessage(SctpSendOptions(STREAM0, PayloadProtocolId.WebRtcString), payload(10, 1)))
        sim.post(toA = false, SctpEvent.SendMessage(SctpSendOptions(STREAM0, PayloadProtocolId.WebRtcString), payload(20, 2)))
        sim.run()

        assertEquals(payload(10, 1).bytes(), sim.inboxB.single().payload.bytes())
        assertEquals(payload(20, 2).bytes(), sim.inboxA.single().payload.bytes())
    }

    @Test
    fun handshake_survives_moderate_loss() {
        val sim = SctpSim(impairment = Impairment(lossRate = 0.2, delay = 20.milliseconds))
        sim.associateA()
        sim.run()
        assertEquals(SctpAssociationState.Established, sim.a.state, "the four-way handshake retransmits through 20% loss")
        assertEquals(SctpAssociationState.Established, sim.b.state)
    }

    @Test
    fun ordered_reliable_survives_heavy_loss_no_reorder() {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        assertEquals(SctpAssociationState.Established, sim.a.state)
        sim.impairment = Impairment(lossRate = 0.3, delay = 20.milliseconds, jitter = 10.milliseconds)

        val count = 40
        for (i in 0 until count) {
            sim.post(toA = true, SctpEvent.SendMessage(SctpSendOptions(STREAM0, PayloadProtocolId.WebRtcBinary), payload(30, seed = i)))
        }
        sim.run()

        assertEquals(count, sim.inboxB.size, "every reliable message is delivered despite 30% loss")
        // No intra-stream reorder (invariant #6): the ramp seeds must arrive strictly in send order.
        val seeds = sim.inboxB.map { it.payload.bytes().first() }
        assertEquals((0 until count).map { it and 0xFF }, seeds, "messages delivered in order, none dropped")
    }

    @Test
    fun unordered_messages_delivered() {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        sim.impairment = Impairment(lossRate = 0.2, delay = 15.milliseconds)

        val count = 20
        for (i in 0 until count) {
            sim.post(
                toA = true,
                SctpEvent.SendMessage(SctpSendOptions(STREAM0, PayloadProtocolId.WebRtcBinary, unordered = true), payload(30, seed = i)),
            )
        }
        sim.run()

        assertEquals(count, sim.inboxB.size, "all unordered messages arrive")
        assertTrue(sim.inboxB.all { it.unordered })
        assertEquals((0 until count).map { it and 0xFF }.toSet(), sim.inboxB.map { it.payload.bytes().first() }.toSet())
    }

    @Test
    fun partial_reliability_max_retransmits_zero_never_hangs() {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        sim.impairment = Impairment(lossRate = 0.5, delay = 20.milliseconds)

        val count = 15
        for (i in 0 until count) {
            sim.post(
                toA = true,
                SctpEvent.SendMessage(
                    SctpSendOptions(STREAM0, PayloadProtocolId.WebRtcBinary, unordered = true, reliability = SctpReliability.MaxRetransmits(0)),
                    payload(30, seed = i),
                ),
            )
        }
        val steps = sim.run()

        // Partial reliability: each message is either delivered or abandoned — the association never hangs
        // (liveness invariant #5) and stays alive, and no duplicate is delivered.
        assertTrue(steps < 200_000, "converges (no hang)")
        assertEquals(SctpAssociationState.Established, sim.a.state)
        assertEquals(SctpAssociationState.Established, sim.b.state)
        assertTrue(sim.inboxB.size <= count, "no more than sent")
        assertEquals(sim.inboxB.size, sim.inboxB.map { it.payload.bytes().first() }.toSet().size, "no duplicate delivery")
    }

    @Test
    fun graceful_shutdown_closes_both_sides() {
        val sim = SctpSim()
        sim.associateA()
        sim.run()

        sim.post(toA = true, SctpEvent.Shutdown)
        sim.run()

        assertEquals(SctpAssociationState.Closed, sim.a.state)
        assertEquals(SctpAssociationState.Closed, sim.b.state)
    }
}

@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime

/**
 * The **JVM-only deep run** of the W5 invariant campaign (TESTING §7: "timeline fuzz smoke on all
 * platforms + JVM deep-run with shrinker"). The all-platform smoke set lives in `SctpInvariantFuzzTest`
 * with a small seed count so the JS/wasm-node lanes stay well under their per-test wall-clock ceiling;
 * the exhaustive sweep — hundreds of seeds, plus the fragmentation-under-loss case the smoke set omits —
 * runs here where a heavy single-threaded loop is cheap. The `SctpSim` conductor throws on any
 * non-convergence, so a livelock in any seed is a hard failure with the offending state, not a silent pass.
 */
class SctpDeepFuzzTest {
    private val stream = StreamId(0)

    @Test
    fun reliable_no_reorder_no_drop_deep_sweep() {
        val messages = 25
        for (seed in 0L until 400L) {
            val sim = SctpSim(seedA = seed * 2 + 1, seedB = seed * 2 + 2)
            sim.associateA()
            sim.run()
            sim.impairment = impairmentForSeed(seed)
            for (i in 0 until messages) {
                sim.post(true, SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(24, seed = i)))
            }
            sim.run()
            assertEquals(
                (0 until messages).map { it and 0xFF },
                sim.inboxB.map { it.payload.bytes().first() },
                "seed $seed: reliable stream delivered all, in order",
            )
        }
    }

    @Test
    fun partial_reliability_no_dup_no_hang_deep_sweep() {
        val messages = 20
        for (seed in 0L until 300L) {
            val sim = SctpSim(seedA = seed * 3 + 7, seedB = seed * 3 + 8)
            sim.associateA()
            sim.run()
            sim.impairment =
                Impairment(lossRate = kotlin.random.Random(seed).nextDouble(0.2, 0.6), duplicateRate = 0.05, delay = 15.milliseconds)
            for (i in 0 until messages) {
                sim.post(
                    true,
                    SctpEvent.SendMessage(
                        SctpSendOptions(
                            stream,
                            PayloadProtocolId.WebRtcBinary,
                            unordered = true,
                            reliability = SctpReliability.MaxRetransmits(1),
                        ),
                        payload(24, seed = i),
                    ),
                )
            }
            sim.run()
            assertEquals(SctpAssociationState.Established, sim.a.state, "seed $seed sender alive")
            val delivered = sim.inboxB.map { it.payload.bytes().first() }
            assertEquals(delivered.size, delivered.toSet().size, "seed $seed no duplicate delivery")
        }
    }

    // R5-3: multi-FRAGMENT messages under loss/dup/reorder — the case the smoke set never reaches (its
    // payloads are all below the 1200-byte default MTU, so nothing fragments). Here a small MTU forces
    // every message into many DATA chunks, so a lost/reordered *fragment* (not just a whole message)
    // exercises the reassembly retransmit path.
    @Test
    fun fragmented_messages_reassemble_intact_under_loss() {
        for (seed in 0L until 120L) {
            val sim = SctpSim(seedA = seed * 7 + 1, seedB = seed * 7 + 2, config = SctpConfig(maxPayloadBytes = 80))
            sim.associateA()
            sim.run()
            sim.impairment =
                Impairment(lossRate = kotlin.random.Random(seed).nextDouble(0.0, 0.3), duplicateRate = 0.05, delay = 10.milliseconds)

            val messages = 8
            for (i in 0 until messages) {
                // ~10 fragments per message at MTU 80.
                sim.post(true, SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(760, seed = i)))
            }
            sim.run()

            assertEquals(messages, sim.inboxB.size, "seed $seed: every fragmented message reassembled")
            for (i in 0 until messages) {
                assertTrue(sim.inboxB[i].payload.bytes() == payload(760, seed = i).bytes(), "seed $seed msg $i reassembled byte-exact")
            }
        }
    }
}

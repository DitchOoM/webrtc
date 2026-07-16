@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime

/**
 * The W5 **loop-until-dry invariant campaign** (RFC §5.3 / TESTING §4): the sans-io association is run
 * across many seeds with randomized loss / duplication / delay / jitter, and every run must uphold the
 * SCTP standing invariants — no crash, liveness (never hangs — the `SctpSim` conductor throws on a
 * livelock), no intra-stream reorder, no unacked drop on a reliable stream, and no duplicate delivery.
 * Deterministic (seeded), so any failing seed becomes a committed regression fixture; the campaign only
 * grows.
 *
 * This is the **hermetic smoke set** run on every platform — a small pinned seed count so it never
 * approaches the per-test wall-clock ceiling on the JS/wasm-node lanes (the shape of the earlier STUN
 * flake). The exhaustive multi-hundred-seed deep sweep + fragmentation-under-loss lives in the JVM-only
 * `SctpDeepFuzzTest`, per the TESTING §7 "timeline fuzz smoke (all platforms) + JVM deep-run" split.
 */
class SctpInvariantFuzzTest {
    private val stream = StreamId(0)

    private fun impairmentFor(seed: Long): Impairment = impairmentForSeed(seed)

    // A control run proving the partial-reliability send path actually DELIVERS — the loss-based tests
    // below assert only "no duplicate / no more than sent / no hang", which "deliver nothing" satisfies
    // vacuously; this pins the positive-delivery floor (review finding R5-2).
    @Test
    fun partial_reliability_over_perfect_transport_delivers_everything() {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        val messages = 12
        for (i in 0 until messages) {
            sim.post(
                true,
                SctpEvent.SendMessage(
                    SctpSendOptions(
                        stream,
                        PayloadProtocolId.WebRtcBinary,
                        unordered = true,
                        reliability = SctpReliability.MaxRetransmits(0),
                    ),
                    payload(24, seed = i),
                ),
            )
        }
        sim.run()
        assertEquals(messages, sim.inboxB.size, "with no loss, a partially-reliable channel still delivers every message")
    }

    @Test
    fun reliable_stream_never_reorders_or_drops_across_seeds() {
        val messages = 25
        for (seed in 0L until SMOKE_SEEDS) {
            val sim = SctpSim(seedA = seed * 2 + 1, seedB = seed * 2 + 2)
            sim.associateA()
            sim.run()
            assertEquals(SctpAssociationState.Established, sim.a.state, "seed $seed established")

            sim.impairment = impairmentFor(seed)
            for (i in 0 until messages) {
                sim.post(true, SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(24, seed = i)))
            }
            val steps = sim.run()

            assertTrue(steps < 200_000, "seed $seed converged (liveness)")
            assertTrue(sim.abortsB.isEmpty(), "seed $seed: receiver never aborted")
            // No unacked drop: every reliable message arrives. No reorder: strictly in send order.
            assertEquals(
                (0 until messages).map { it and 0xFF },
                sim.inboxB.map { it.payload.bytes().first() },
                "seed $seed: reliable stream delivered all, in order, no reorder",
            )
        }
    }

    @Test
    fun partial_reliability_no_duplicate_no_hang_across_seeds() {
        val messages = 20
        for (seed in 0L until SMOKE_SEEDS) {
            val sim = SctpSim(seedA = seed * 3 + 7, seedB = seed * 3 + 8)
            sim.associateA()
            sim.run()

            sim.impairment =
                Impairment(lossRate = Random(seed).nextDouble(0.2, 0.6), duplicateRate = 0.05, delay = 15.milliseconds)
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
            val steps = sim.run()

            assertTrue(steps < 200_000, "seed $seed converged (liveness)")
            assertEquals(SctpAssociationState.Established, sim.a.state, "seed $seed: sender still alive")
            assertEquals(SctpAssociationState.Established, sim.b.state, "seed $seed: receiver still alive")
            // Partial reliability: delivered ⊆ sent, and never a duplicate (no double-delivery).
            val seeds = sim.inboxB.map { it.payload.bytes().first() }
            assertEquals(seeds.size, seeds.toSet().size, "seed $seed: no duplicate delivery")
            assertTrue(seeds.size <= messages, "seed $seed: never more than sent")
        }
    }

    @Test
    fun bidirectional_reliable_holds_under_loss_across_seeds() {
        val messages = 15
        for (seed in 0L until SMOKE_SEEDS) {
            val sim = SctpSim(seedA = seed * 5 + 3, seedB = seed * 5 + 4)
            sim.associateA()
            sim.run()
            sim.impairment = impairmentFor(seed + 1000)

            for (i in 0 until messages) {
                sim.post(true, SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcString), payload(16, seed = i)))
                sim.post(false, SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcString), payload(16, seed = 100 + i)))
            }
            sim.run()

            assertEquals((0 until messages).map { it and 0xFF }, sim.inboxB.map { it.payload.bytes().first() }, "seed $seed A→B in order")
            assertEquals(
                (0 until messages).map { (100 + it) and 0xFF },
                sim.inboxA.map { it.payload.bytes().first() },
                "seed $seed B→A in order",
            )
        }
    }
}

/** Seed count for the all-platform smoke set; the JVM deep-run (`SctpDeepFuzzTest`) uses far more. */
internal const val SMOKE_SEEDS = 12L

/** The randomized-but-seeded impairment for one campaign seed — shared by the smoke + deep-run lanes. */
internal fun impairmentForSeed(seed: Long): Impairment {
    val r = Random(seed)
    return Impairment(
        lossRate = r.nextDouble(0.0, 0.35),
        duplicateRate = r.nextDouble(0.0, 0.10),
        delay = r.nextInt(0, 40).milliseconds,
        jitter = r.nextInt(0, 30).milliseconds,
    )
}

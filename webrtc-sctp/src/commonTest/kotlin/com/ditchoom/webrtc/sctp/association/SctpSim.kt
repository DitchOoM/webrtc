@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.ReadBuffer
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * A deterministic two-endpoint conductor for the sans-io [SctpAssociation] (RFC §5.1 test discipline):
 * it steps two associations, routes [SctpOutput.Transmit] packets between them through an [Impairment]
 * pipe, fires [SctpEvent.TimerFired] when a [SctpAssociation.nextDeadline] comes due, and advances a
 * virtual clock with zero wall-clock. No coroutines, no sockets — the whole session (handshake,
 * retransmit, SACK, shutdown) replays as a pure event loop, exactly as the driver would over the vnet.
 */
internal class SctpSim(
    seedA: Long = 1L,
    seedB: Long = 2L,
    config: SctpConfig = SctpConfig(),
    var impairment: Impairment = Impairment.PERFECT,
) {
    val a: SctpAssociation = SctpAssociation(config, Random(seedA))
    val b: SctpAssociation = SctpAssociation(config, Random(seedB))

    private val epoch = Instant.fromEpochSeconds(0)
    var now: Instant = epoch
        private set

    // In-flight datagrams: (destination endpoint, snapshot payload, deliver-at time).
    private class InFlight(
        val toB: Boolean,
        val payload: ReadBuffer,
        val at: Instant,
    )

    private val queue = ArrayList<InFlight>()
    private val impairRandom = Random(seedA * 31 + seedB)

    /**
     * Test hook: when non-null, a datagram is dropped iff this returns true for its destination —
     * evaluated once per transmit, in send order, **before** the [Impairment]. Lets a fixture drop one
     * *specific* packet deterministically (e.g. the answerer's first echo DATA) rather than leaning on a
     * probabilistic loss rate. `toA` is true when the datagram is bound for endpoint A.
     */
    var dropFilter: ((toA: Boolean) -> Boolean)? = null

    /** Messages delivered up to each endpoint, in order (endpoint A's inbox, endpoint B's inbox). */
    val inboxA = ArrayList<SctpOutput.MessageReceived>()
    val inboxB = ArrayList<SctpOutput.MessageReceived>()
    val abortsA = ArrayList<SctpFailureReason>()
    val abortsB = ArrayList<SctpFailureReason>()

    fun post(
        toA: Boolean,
        event: SctpEvent,
    ) {
        val assoc = if (toA) a else b
        apply(toA, assoc.handle(event, now))
    }

    fun associateA() = post(toA = true, SctpEvent.Associate)

    /**
     * Run the event loop until both endpoints are quiescent (no packets, no armed timers). Returns the
     * step count. **Throws** if [maxSteps] is exhausted — a livelocked/hung association must never pass
     * silently regardless of what the caller asserts afterward (the liveness invariant, RFC §5.3 #5, is
     * enforced here in the conductor, not left to each test to remember).
     */
    fun run(maxSteps: Int = 200_000): Int = drive(deadline = null, maxSteps = maxSteps)

    /**
     * Step the event loop like [run], but never advance the virtual clock past [deadline]: process every
     * packet and timer due at or before [deadline], then stop (leaving [now] == deadline when work
     * remains beyond it). Lets a fixture assert **observable state at a bounded instant** — e.g. "the lost
     * echo was recovered within the budget" — which a run-to-quiescence, that always *eventually* delivers,
     * cannot express. Resumable: a later [runUntil]/[run] continues from where this stopped.
     */
    fun runUntil(
        deadline: Instant,
        maxSteps: Int = 200_000,
    ): Int = drive(deadline = deadline, maxSteps = maxSteps)

    private fun drive(
        deadline: Instant?,
        maxSteps: Int,
    ): Int {
        var steps = 0
        while (steps < maxSteps) {
            steps++
            val ready = queue.filter { it.at <= now }
            if (ready.isNotEmpty()) {
                queue.removeAll(ready)
                for (p in ready) {
                    val assoc = if (p.toB) b else a
                    // The endpoint that received (and produced these outputs) is A iff the datagram went to A.
                    apply(fromA = !p.toB, assoc.handle(SctpEvent.DatagramReceived(freshView(p.payload)), now))
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
            val next = listOfNotNull(queue.minOfOrNull { it.at }, aDl, bDl).minOrNull() ?: return steps
            if (next <= now) return steps
            // Bounded run: nothing is due at or before the deadline, so stop the clock there and return.
            if (deadline != null && next > deadline) {
                now = deadline
                return steps
            }
            now = next
        }
        error("SCTP sim did not converge in $maxSteps steps (livelock/hang): a=${a.state} b=${b.state}")
    }

    private fun apply(
        fromA: Boolean,
        outputs: List<SctpOutput>,
    ) {
        for (output in outputs) {
            when (output) {
                is SctpOutput.Transmit -> schedule(fromA, output.payloadView())
                is SctpOutput.MessageReceived -> (if (fromA) inboxA else inboxB) += output
                is SctpOutput.Aborted -> (if (fromA) abortsA else abortsB) += output.reason
                is SctpOutput.StateChanged -> Unit
            }
        }
    }

    private fun schedule(
        fromA: Boolean,
        payload: ReadBuffer,
    ) {
        // A datagram FROM A is bound for B and vice-versa; the targeted drop hook sees the destination.
        if (dropFilter?.invoke(!fromA) == true) return
        val decision = impairment.decide(impairRandom)
        for (copyDelay in decision.deliveries) {
            queue += InFlight(toB = fromA, payload = payload, at = now + copyDelay)
        }
    }

    private fun SctpOutput.Transmit.payloadView(): ReadBuffer {
        packet.position(0)
        return packet.slice()
    }

    private fun freshView(buf: ReadBuffer): ReadBuffer {
        buf.position(0)
        return buf.slice()
    }
}

/**
 * A seeded impairment model for [SctpSim] — each datagram is dropped, delivered once, or duplicated, and
 * each delivery may be delayed. Deterministic: one [Random] draw sequence per session so a scenario
 * replays bit-for-bit (RFC §5.3). Mirrors the ICE vnet's `Impairment` shape.
 */
internal class Impairment(
    private val lossRate: Double = 0.0,
    private val duplicateRate: Double = 0.0,
    private val delay: Duration = Duration.ZERO,
    private val jitter: Duration = Duration.ZERO,
) {
    class Decision(
        val deliveries: List<Duration>,
    )

    fun decide(random: Random): Decision {
        if (lossRate > 0.0 && random.nextDouble() < lossRate) return Decision(emptyList())
        val deliveries = ArrayList<Duration>(2)
        deliveries += sample(random)
        if (duplicateRate > 0.0 && random.nextDouble() < duplicateRate) deliveries += sample(random)
        return Decision(deliveries)
    }

    private fun sample(random: Random): Duration {
        if (jitter == Duration.ZERO) return delay
        val jitterMillis = (random.nextDouble() * jitter.inWholeMilliseconds).toLong()
        return delay + jitterMillis.milliseconds
    }

    companion object {
        val PERFECT = Impairment()
    }
}

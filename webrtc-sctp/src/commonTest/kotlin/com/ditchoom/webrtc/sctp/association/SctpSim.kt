@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.sctp.TransportErrorDetection
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * A deterministic two-endpoint conductor for the sans-io [SctpAssociation] (ARCHITECTURE §5.1 test discipline):
 * it steps two associations, routes [SctpOutput.Transmit] packets between them through an [Impairment]
 * pipe, fires [SctpEvent.TimerFired] when a [SctpAssociation.nextDeadline] comes due, and advances a
 * virtual clock with zero wall-clock. No coroutines, no sockets — the whole session (handshake,
 * retransmit, SACK, shutdown) replays as a pure event loop, exactly as the driver would over the vnet.
 */
internal class SctpSim(
    seedA: Long = 1L,
    seedB: Long = 2L,
    config: SctpConfig = SctpConfig(),
    // Endpoint B's configuration, when it must differ from A's. Defaults to the same value, so every
    // existing fixture is unchanged.
    //
    // A *symmetric* configuration is exactly what hides an asymmetric negotiation, and two separate pieces
    // of work needed this seam for the same underlying reason. RFC 4960 §5.1.1's two stream minima coincide
    // whenever OS equals MIS on both sides, so a symmetric fixture cannot see the outbound one at all; and
    // RFC 9653's negotiation is per direction, so its interesting cases are precisely the ones where the
    // peers disagree about policy or about what the transport beneath each of them guarantees.
    configB: SctpConfig = config,
    errorDetection: TransportErrorDetection = TransportErrorDetection.CrcOnly,
    errorDetectionB: TransportErrorDetection = errorDetection,
    var impairment: Impairment = Impairment.PERFECT,
) {
    val a: SctpAssociation = SctpAssociation(config, Random(seedA), errorDetection = errorDetection)
    val b: SctpAssociation = SctpAssociation(configB, Random(seedB), errorDetection = errorDetectionB)

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

    /**
     * A **constriction** in the modelled path: any datagram whose SCTP bytes exceed this is dropped
     * silently, in both directions, before the [Impairment].
     *
     * This is what a link narrower than the assumed MTU does — and on IPv6 it is *all* it does, since RFC
     * 8200 §5 forbids a router to fragment and the ICMPv6 Packet Too Big it would send back is not
     * something a UDP-encapsulated flow behind a NAT can rely on receiving. Which is why RFC 8899 exists,
     * and why a probe going unanswered is the only evidence the search ever gets.
     */
    var maxSctpDatagramBytes: Int = Int.MAX_VALUE

    /** Messages delivered up to each endpoint, in order (endpoint A's inbox, endpoint B's inbox). */
    val inboxA = ArrayList<SctpOutput.MessageReceived>()
    val inboxB = ArrayList<SctpOutput.MessageReceived>()

    /**
     * What each endpoint's stand-in application is doing about the messages it is handed — [InboxConsumer].
     * Both read promptly by default, which is what every fixture that is not about flow control assumes.
     */
    var consumerA: InboxConsumer = InboxConsumer.Prompt
    var consumerB: InboxConsumer = InboxConsumer.Prompt

    // Receipts a Stalled consumer has been handed and not returned — the memory a real application would be
    // sitting on, and the reason its endpoint's advertised window is shrinking.
    private val uncreditedA = ArrayList<DeliveryReceipt>()
    private val uncreditedB = ArrayList<DeliveryReceipt>()

    /**
     * The stalled application on one endpoint starts reading again: credit everything it was handed while
     * stalled, and keep crediting from here.
     *
     * The distinction this exists to draw is between a receiver that is **slow** and one that is **stuck**.
     * A closed window that never reopens is a deadlock however correct each side is; a closed window that
     * reopens when the application catches up is flow control working. Only running both halves tells them
     * apart, and the second half is the one a liveness assertion cannot express on its own.
     */
    fun resumeConsumer(toA: Boolean) {
        val pending = if (toA) uncreditedA else uncreditedB
        if (toA) consumerA = InboxConsumer.Prompt else consumerB = InboxConsumer.Prompt
        val drained = pending.toList()
        pending.clear()
        val endpoint = if (toA) a else b
        for (receipt in drained) apply(toA, endpoint.handle(SctpEvent.MessageConsumed(receipt), now))
    }

    /** RFC 4960 §5.2.4 action A notifications, one per peer restart the endpoint adopted. */
    val restartsA = ArrayList<Unit>()
    val restartsB = ArrayList<Unit>()
    val abortsA = ArrayList<SctpFailureReason>()
    val abortsB = ArrayList<SctpFailureReason>()

    /** RFC 8899 ceiling changes each endpoint published, in order. */
    val pathMtuA = ArrayList<SctpOutput.PathMtuChanged>()
    val pathMtuB = ArrayList<SctpOutput.PathMtuChanged>()

    /** RFC 6525 stream resets: the peer's resets each endpoint applied, and its own requests' outcomes. */
    val incomingResetsA = ArrayList<StreamResetScope>()
    val incomingResetsB = ArrayList<StreamResetScope>()
    val outgoingResetsA = ArrayList<SctpOutput.OutgoingStreamsReset>()
    val outgoingResetsB = ArrayList<SctpOutput.OutgoingStreamsReset>()

    /** Every RFC 4960 §5.1.1 / RFC 6525 §4.5 outgoing-capacity settlement each endpoint announced. */
    val capacitiesA = ArrayList<OutgoingStreamCapacity.Negotiated>()
    val capacitiesB = ArrayList<OutgoingStreamCapacity.Negotiated>()

    /** RFC 6525 §4.5 stream-count increases each endpoint originated, and how each was answered. */
    val streamsAddedA = ArrayList<SctpOutput.OutgoingStreamsAdded>()
    val streamsAddedB = ArrayList<SctpOutput.OutgoingStreamsAdded>()

    /**
     * Feed [event] to one endpoint and route its side effects. Returns those side effects as well, so a
     * fixture can assert on what a *single* event produced (e.g. "the second reset request emitted no
     * chunk, because one was already outstanding") without giving up the conductor's routing — which is
     * why this returns rather than the test calling `handle` directly and stranding the packets.
     */
    fun post(
        toA: Boolean,
        event: SctpEvent,
    ): List<SctpOutput> {
        val assoc = if (toA) a else b
        val outputs = assoc.handle(event, now)
        apply(toA, outputs)
        return outputs
    }

    fun associateA() = post(toA = true, SctpEvent.Associate)

    /**
     * Run the event loop until both endpoints are quiescent (no packets, no armed timers). Returns the
     * step count. **Throws** if [maxSteps] is exhausted — a livelocked/hung association must never pass
     * silently regardless of what the caller asserts afterward (the liveness invariant, ARCHITECTURE §5.3 #5, is
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

    /**
     * Apply one endpoint's side effects, then **credit every message it just filed**.
     *
     * The credit is neither optional nor a nicety. A [SctpOutput.MessageReceived] charges its bytes to the
     * receiving endpoint's a_rwnd (RFC 4960 §3.3.2) until the driver hands the receipt back, and this
     * conductor *is* the driver — so a conductor that files without crediting watches its own window shrink
     * by everything it has ever received and eventually stalls for a reason that has nothing to do with
     * what the fixture is about. Standing in for an application that reads promptly is what every fixture
     * here already assumes; this is where that assumption became something the code has to say.
     *
     * Credited **after** the loop rather than inside it, because a credit is itself an event whose outputs
     * (the window-reopening SACK) have to be routed, and re-entering mid-iteration would interleave those
     * packets with the ones still being scheduled.
     */
    private fun apply(
        fromA: Boolean,
        outputs: List<SctpOutput>,
    ) {
        var consumed: ArrayList<DeliveryReceipt>? = null
        for (output in outputs) {
            when (output) {
                is SctpOutput.Transmit -> schedule(fromA, output.payloadView())
                is SctpOutput.MessageReceived -> {
                    (if (fromA) inboxA else inboxB) += output
                    when (if (fromA) consumerA else consumerB) {
                        InboxConsumer.Prompt -> {
                            val receipts = consumed ?: ArrayList<DeliveryReceipt>().also { consumed = it }
                            receipts += output.receipt
                        }
                        // Held, not dropped: a stalled application still HAS the message, which is exactly
                        // why its endpoint's window stays charged for it.
                        InboxConsumer.Stalled -> (if (fromA) uncreditedA else uncreditedB) += output.receipt
                    }
                }
                is SctpOutput.Aborted -> (if (fromA) abortsA else abortsB) += output.reason
                SctpOutput.PeerRestarted -> (if (fromA) restartsA else restartsB).let { it.add(Unit) }
                is SctpOutput.IncomingStreamsReset -> (if (fromA) incomingResetsA else incomingResetsB) += output.scope
                is SctpOutput.OutgoingStreamsReset -> (if (fromA) outgoingResetsA else outgoingResetsB) += output
                is SctpOutput.StateChanged -> Unit
                is SctpOutput.PathMtuChanged -> (if (fromA) pathMtuA else pathMtuB) += output
                is SctpOutput.OutgoingCapacityChanged -> (if (fromA) capacitiesA else capacitiesB) += output.capacity
                is SctpOutput.OutgoingStreamsAdded -> (if (fromA) streamsAddedA else streamsAddedB) += output
                // Deliberately NOT released here, and the reason is worth stating rather than eliding: a
                // real driver frees these behind the sends it has queued, but this sim's in-flight queue
                // holds views for a modelled *delay*, so a reclaim applied inline could outrun a datagram
                // still on the wire. It runs on a GC-managed factory, so nothing is lost by declining. The
                // send seam's ownership is measured where the real driver runs it —
                // `SessionSeamOwnershipTest` and `SctpSendSeamOwnershipTest`.
                is SctpOutput.ReclaimRetained -> Unit
            }
        }
        val receipts = consumed ?: return
        val endpoint = if (fromA) a else b
        for (receipt in receipts) apply(fromA, endpoint.handle(SctpEvent.MessageConsumed(receipt), now))
    }

    private fun schedule(
        fromA: Boolean,
        payload: ReadBuffer,
    ) {
        // A datagram FROM A is bound for B and vice-versa; the targeted drop hook sees the destination.
        if (dropFilter?.invoke(!fromA) == true) return
        if (payload.remaining() > maxSctpDatagramBytes) return
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
 * What an endpoint's stand-in application does with the messages the conductor hands it.
 *
 * A named pair rather than a Boolean, because the two states are the whole of receive-side flow control's
 * subject matter and a `credits = false` at a call site says nothing about *why* the window is closing.
 */
internal sealed interface InboxConsumer {
    /** Reads and finishes with every message at once — the behaviour every other fixture assumes. */
    data object Prompt : InboxConsumer

    /**
     * Has stopped reading. Messages are still delivered and still filed in the inbox — the application has
     * them — but their receipts are never returned, so the endpoint's advertised a_rwnd shrinks by exactly
     * what it is holding. This is the only way to reach a closed receive window in a deterministic fixture:
     * no docker peer can be made to stop reading on cue (TESTING.md's argued L1-only exemption).
     */
    data object Stalled : InboxConsumer
}

/**
 * A seeded impairment model for [SctpSim] — each datagram is dropped, delivered once, or duplicated, and
 * each delivery may be delayed. Deterministic: one [Random] draw sequence per session so a scenario
 * replays bit-for-bit (ARCHITECTURE §5.3). Mirrors the ICE vnet's `Impairment` shape.
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

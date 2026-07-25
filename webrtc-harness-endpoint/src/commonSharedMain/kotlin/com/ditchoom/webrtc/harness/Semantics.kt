@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.webrtc.NativePeerConnection
import com.ditchoom.webrtc.sctp.DeliveryOrder
import com.ditchoom.webrtc.sctp.association.SctpReliability
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConnection
import com.ditchoom.webrtc.sdp.DataChannelParameters
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

// ─────────────────────────────────────────────────────────────────────────────────────────────────────
// Data-channel SEMANTICS interop (docs/DC_SEMANTICS_INTEROP_DESIGN.md, Phase-1 close-out item #2).
//
// Every interop lane used to prove exactly one thing: one reliable-ordered DCEP channel round-trips one
// 4-byte message. That proves ESTABLISHMENT (ICE + DTLS + SCTP INIT + one DCEP OPEN) — not the data-channel
// semantics the library actually implements. This file adds the phase sequence that does, run back-to-back
// over ONE long-lived association INSIDE the existing lanes (so every lane gains the whole matrix, and CI
// grows no new jobs):
//
//   s1/large      SCTP fragmentation + reassembly far past one MTU, byte-identity checked, sized against
//                 the peer's advertised `a=max-message-size` (RFC 8841 §6) + a probe AT that ceiling
//   s2/unordered  `ordered=false` — the DCEP channel type is honored end-to-end and still delivers
//   s3/partial    PR-SCTP (RFC 3758): MaxRetransmits(0) + MaxLifetime — the profiles are accepted, and an
//                 abandoned message does not WEDGE the stream (the peer processed our FORWARD-TSN)
//   s4/multiplex  three concurrent channels, mixed profiles — per-stream demux over one association
//   s5/reverse    the ANSWERER originates a channel (our lanes only — foreign peers stay dumb reflectors)
//   s6/close      the `DONE` handshake, then a graceful association SHUTDOWN (RFC 4960 §9.2)
//
// THE ONE ASYMMETRY THAT SHAPES ALL OF IT: our side is always the offerer, and the far side may be a
// browser — where we cannot inject behaviour beyond the W3C `RTCDataChannel` API. So the answerer is a
// dumb, scenario-agnostic REFLECTOR (echo every message back on the channel it arrived on) and EVERY
// scenario decision and assertion lives here, in our Kotlin. Channel labels are self-describing for logs,
// getStats and pcaps, but drive NO behaviour on the reflector.
//
// Per-channel close (RFC 6525 RE-CONFIG stream reset) is deliberately absent: `webrtc-sctp` does not
// implement it, so s6 proves the ASSOCIATION-level graceful shutdown that we do implement, and per-channel
// close stays a library follow-up rather than a harness fiction (decision D1a).
// ─────────────────────────────────────────────────────────────────────────────────────────────────────

/** The control channel's label — kept historical so every existing lane's logs read exactly as before. */
internal const val CTL_LABEL: String = "harness"

/** Both sides agree the run is over. Sent by the offerer on [CTL_LABEL], reflected verbatim. */
internal const val DONE_MARKER: String = "DONE"

/** The cue that tells our answerer to originate the reverse-direction channel (s5). Reflected verbatim. */
internal const val REVERSE_CUE: String = "REVERSE"

/** The label the ANSWERER opens for s5; the offerer waits for an incoming channel with exactly it. */
internal const val REVERSE_LABEL: String = "s5/reverse"

/** How many small messages a burst phase sends. */
private const val BURST = 50
private const val PR_BURST = 20

/** The largest payload a peek decodes as text — above it a message is binary and is echoed unread. */
private const val MAX_PEEK_BYTES = 64

/** Per-phase watchdog: bounds ONE phase so a wedged phase cannot eat the whole semantics budget. */
private val PHASE_TIMEOUT = 45.seconds

/** How long a single echo is waited for inside a phase (strictly under [PHASE_TIMEOUT]). */
private val ECHO_WAIT = 25.seconds

/** The `BEGIN`/`DONE` control round-trips — small, reliable-ordered, but crossing a real impaired path. */
private val CTL_TIMEOUT = 15.seconds

/** The window for an ADVISORY probe (an assumed, unadvertised ceiling) — "no echo" there is an expected
 *  answer, not a stall, so it must not cost every such lane a full echo window. */
private val ADVISORY_PROBE_WAIT = 8.seconds

/** How long a PR burst is watched. Short by design: what has not arrived is ABANDONED, not late. */
private val PR_COLLECT_WINDOW = 10.seconds

/** PR-SCTP lifetime for `s3/timed` — short enough that the impaired lane genuinely abandons messages. */
private val PR_LIFETIME = 200.milliseconds

/**
 * The `a=max-message-size` to assume when the peer advertises none. RFC 8841 §6 makes the attribute
 * optional and a receiver that omits it is only guaranteed to accept 64 KiB — so that is the conservative
 * floor. Sizing s1 above it would test our stack against a limit the peer never agreed to.
 */
private const val ASSUMED_REMOTE_MAX_MESSAGE_SIZE = 65536L

/** What s1 aims for when the negotiated ceiling allows it — ~167 SCTP fragments at a 1200-byte payload. */
private const val TARGET_LARGE_BYTES = 200 * 1024

/**
 * One phase's verdict. [detail] is a diagnostic string, never a discriminant — [passed] is the
 * discriminant (standing directive #3).
 */
internal data class PhaseOutcome(
    val id: String,
    val passed: Boolean,
    val detail: String,
    val took: Duration,
)

/**
 * Records phase verdicts and prints the machine-readable summary `run-interop.sh` greps. A failed phase is
 * RECORDED and the sequence CONTINUES (decision D2), so one CI run reports everything that is broken
 * instead of one bug per round-trip.
 */
internal class SemanticsReport {
    private val outcomes = mutableListOf<PhaseOutcome>()

    fun record(outcome: PhaseOutcome) {
        outcomes += outcome
        val verdict = if (outcome.passed) "PASS" else "FAIL"
        println("[harness] phase ${outcome.id}: $verdict (+${outcome.took.inWholeMilliseconds}ms) ${outcome.detail}")
    }

    val failed: List<String> get() = outcomes.filter { !it.passed }.map { it.id }

    /** True iff every phase that RAN passed. An empty sequence (all subset out) is vacuously a pass. */
    val allPassed: Boolean get() = outcomes.all { it.passed }

    /** The one greppable line: `run-interop.sh` parses it to warn (non-gating) or fail (gating). */
    fun printSummary() {
        println(
            "[harness] semantics-summary: total=${outcomes.size} passed=${outcomes.count { it.passed }} " +
                "failed=${failed.size} failed-phases=[${failed.joinToString(",")}]",
        )
    }
}

/**
 * The universal REFLECTOR both roles run over their INCOMING data channels: for every channel, echo every
 * message back on that same channel, verbatim. It is deliberately scenario-agnostic — it never reads a
 * label to decide behaviour — so the identical contract is implementable in Pion, in werift, and (the
 * binding constraint) in a browser page holding nothing but the W3C API.
 *
 * The single exception is the historical liveness ritual: the text `ping` is echoed as `pong`, exactly as
 * every lane has always done, so phase 0 is bit-for-bit the old test and existing logs still read the same.
 *
 * Small payloads are peeked as text and published to [events] so a role can act on the lifecycle words
 * (`DONE`, `REVERSE`); a large binary (s1) is never decoded, only echoed.
 */
internal class Reflector(
    private val scope: CoroutineScope,
) {
    /** One reflected message: the channel [label] it arrived on, its [text] (null when binary), its size. */
    internal data class Event(val label: String, val text: String?, val bytes: Int)

    private val _events = Channel<Event>(Channel.UNLIMITED)

    /** Every message this reflector echoed, in arrival order. */
    val events: Channel<Event> get() = _events

    /** Launch the pump-attacher over every channel the peer opens (the W3C `ondatachannel` equivalent). */
    fun start(pc: NativePeerConnection) {
        scope.launch { pc.incomingDataChannels.collect { attach(it) } }
    }

    /** Attach an echo pump to [channel]; it lives until the channel's inbound flow completes. */
    fun attach(channel: Connection<ReadBuffer>) {
        val label = channel.channelLabel()
        println("[harness] reflect: incoming data channel \"$label\" id=${channel.id}")
        scope.launch {
            var count = 0
            var bytes = 0L
            // Guarded: this pump is a child of the peer's one background Job, so an uncaught throw here
            // (a send on an association that just tore down) would cancel every sibling loop — signaling,
            // ICE trickle, the state trace — and the peer would report a cancellation instead of the
            // failure that actually happened.
            try {
                channel.receive().collect { message ->
                    val size = message.remaining()
                    count++
                    bytes += size
                    val text = message.peekText()
                    val rendered = if (text != null) "data=\"$text\"" else "data=<${size}B binary>"
                    println("[harness] reflect \"$label\": size=$size msg#$count rxBytes=$bytes $rendered")
                    // Verbatim echo — the whole reflector contract. `ping`→`pong` is the one historical
                    // exception (phase 0), kept so the establishment ritual is unchanged on every lane.
                    if (text == "ping") channel.send(textBuffer("pong")) else channel.send(message)
                    _events.trySend(Event(label, text, size))
                }
                println("[harness] reflect \"$label\": inbound closed after $count message(s), $bytes bytes")
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                println("[harness] reflect \"$label\": stopped after $count message(s) — ${e::class.simpleName}: ${e.message}")
            }
        }
    }

    /** Await a reflected message whose text is [expected], or null when [timeout] elapses first. */
    suspend fun awaitText(
        expected: String,
        timeout: Duration,
    ): Event? = awaitEvent(timeout) { it.text == expected }

    /** Await a reflected message matching [predicate], or null when [timeout] elapses first. */
    suspend fun awaitEvent(
        timeout: Duration,
        predicate: (Event) -> Boolean,
    ): Event? =
        withTimeoutOrNull(timeout) {
            var event = _events.receive()
            while (!predicate(event)) event = _events.receive()
            event
        }
}

/**
 * The offerer's control channel: phase 0's ping→pong plus the `BEGIN <phase>` / `DONE` lifecycle. Every
 * word is reflected verbatim by the far side, so each is a synchronous round-trip — which makes it both a
 * log-correlation marker (decision D3) and a liveness barrier between phases. The completion handshake
 * replaces the old teardown-timing race (`FLUSH_LINGER` racing `ECHO_TIMEOUT`) with an explicit, greppable
 * agreement that the run is over.
 */
internal class ControlChannel(
    private val channel: Connection<ReadBuffer>,
) {
    private val inbox = Channel<String>(Channel.UNLIMITED)

    /** Launch the single collector over the control channel's inbound flow. */
    fun start(scope: CoroutineScope) {
        scope.launch {
            // Guarded for the same reason as the reflector pump: a teardown mid-run must not cancel the
            // peer's sibling loops. A stopped collector simply makes the next exchange time out — which is
            // exactly the failure the phase should report.
            try {
                channel.receive().collect { message ->
                    inbox.trySend(message.peekText() ?: "<${message.remaining()}B binary>")
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                println("[harness] ctl: inbound stopped — ${e::class.simpleName}: ${e.message}")
            }
        }
    }

    /** Send [text] and return whatever came back, or null when [timeout] elapsed with no reply. */
    suspend fun roundTrip(
        text: String,
        timeout: Duration = CTL_TIMEOUT,
    ): String? {
        channel.send(textBuffer(text))
        return withTimeoutOrNull(timeout) { inbox.receive() }
    }

    /** Send [text] and require exactly [expect] back; false = the association is not delivering. */
    suspend fun exchange(
        text: String,
        expect: String,
        timeout: Duration = CTL_TIMEOUT,
    ): Boolean {
        val reply = roundTrip(text, timeout)
        if (reply != expect) println("[harness] ctl: sent \"$text\", expected \"$expect\", got ${reply?.let { "\"$it\"" } ?: "<timeout>"}")
        return reply == expect
    }

    /** Phase 0 — the liveness ritual every lane has always run; returns the reply for the historical log. */
    suspend fun pingPongReply(timeout: Duration): String? = roundTrip("ping", timeout)

    /** `BEGIN <id>` — the per-phase marker that makes every peer's log, pcap and getStats self-correlating. */
    suspend fun begin(id: String): Boolean = exchange("BEGIN $id", "BEGIN $id")

    /** `DONE` — both sides agree the run is over; the offerer then starts the graceful SHUTDOWN. */
    suspend fun done(): Boolean = exchange(DONE_MARKER, DONE_MARKER)
}

/** One entry of the offerer's compiled-in phase sequence. */
private class Phase(
    val id: String,
    val body: suspend () -> Verdict,
)

/** A phase result before it is stamped with its elapsed time. */
private class Verdict(
    val passed: Boolean,
    val detail: String,
)

/**
 * Run the semantics sequence over the live association (offerer only) and return the report. The list is
 * compiled in, not signalled: the reflector never needs to know which scenario is running, so there is
 * nothing to tell it. `WEBRTC_SCENARIOS` may SUBSET the list for debugging; by default all of it runs.
 *
 * [remoteMaxMessageSize] is the peer's advertised `a=max-message-size` (null when it advertised none).
 */
internal suspend fun runSemanticsPhases(
    bg: CoroutineScope,
    pc: NativePeerConnection,
    ctl: ControlChannel,
    reflector: Reflector,
    cfg: HarnessConfig,
    clock: () -> Instant,
    remoteMaxMessageSize: Long?,
): SemanticsReport {
    val report = SemanticsReport()
    val phases =
        buildList {
            add(Phase("s1") { phaseLarge(pc, remoteMaxMessageSize) })
            add(Phase("s2") { phaseUnordered(pc) })
            add(Phase("s3") { phasePartialReliable(pc, ctl) })
            add(Phase("s4") { phaseMultiplex(bg, pc) })
            if (cfg.reverseChannel) add(Phase("s5") { phaseReverse(ctl, reflector) })
        }

    for (phase in phases) {
        if (!cfg.runsScenario(phase.id)) {
            println("[harness] phase ${phase.id}: SKIPPED (not in WEBRTC_SCENARIOS)")
            continue
        }
        val startedAt = clock()
        // The BEGIN marker is itself the phase's first assertion: if the control round-trip does not come
        // back, the association is not delivering and the phase has failed before it began.
        //
        // A phase that THROWS (the association tore down mid-burst → SctpClosedException) is a recorded
        // failure like any other, never an escape from the sequence: decision D2 is record-and-continue,
        // and the remaining phases still carry diagnostic value (they will fail the same way, visibly).
        val verdict =
            try {
                if (!ctl.begin(phase.id)) {
                    Verdict(false, "the BEGIN marker never round-tripped — the association is not delivering")
                } else {
                    withTimeoutOrNull(PHASE_TIMEOUT) { phase.body() }
                        ?: Verdict(false, "phase watchdog fired after $PHASE_TIMEOUT")
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e // the semantics budget expired around us — structured cancellation, not a verdict
            } catch (e: Exception) {
                Verdict(false, "threw ${e::class.simpleName}: ${e.message}")
            }
        report.record(PhaseOutcome(phase.id, verdict.passed, verdict.detail, clock() - startedAt))
    }
    return report
}

// ── s1: fragmentation / reassembly of a message far past one MTU ─────────────────────────────────────

/**
 * The flagship proof: ONE message of ~200 KB (or the negotiated ceiling, whichever is smaller) must come
 * back byte-identical. At a 1200-byte SCTP payload that is ~167 DATA chunks carrying B/E bits — so a green
 * s1 means our fragmentation, the peer's reassembly, both receive windows and the congestion controller
 * all interoperated, in BOTH directions. It is the single highest-value true-semantics proof.
 *
 * The interop hazard is `a=max-message-size` (RFC 8841 §6): a peer only guarantees to RECEIVE what it
 * advertised, so the payload is clamped to `min(ours, theirs)` — and a second probe is sent AT exactly that
 * ceiling (decision D5), which is the only thing that proves we actually read and honour the peer's
 * advertisement rather than getting away with a number that happens to sit under every default.
 *
 * The two are separate verdicts on purpose. Pion advertises nothing (so the ceiling is our assumed 64 KiB)
 * and does not echo a message at exactly 65536 — with the payload clamped straight TO the ceiling that read
 * as "fragmentation is broken against Pion", which was false: at 48 KiB it reassembles perfectly.
 */
private suspend fun phaseLarge(
    pc: NativePeerConnection,
    remoteMaxMessageSize: Long?,
): Verdict {
    val ceiling = negotiatedMaxMessageSize(remoteMaxMessageSize)
    // The fragmentation proof deliberately sits BELOW the ceiling (three quarters of it), so that "can this
    // stack fragment and reassemble" and "does it accept a message at exactly the limit" are two separate
    // verdicts. Collapsing them hid the first behind the second on the Pion lane, where the ceiling is only
    // 64 KiB: one blunt failure instead of "fragmentation works, the exact-limit message does not".
    val largeSize = minOf(TARGET_LARGE_BYTES, ceiling / 4 * 3)
    val channel = pc.createDataChannel(DataChannelConfig(label = "s1/large"))

    val large = echoIsIdentical(channel, largeSize, seed = 0x5EED)
    if (!large.passed) return large

    // A peer that advertised its ceiling promised to receive it, so wait the full echo window for it; an
    // ASSUMED ceiling gets a short window, because "no echo" there is an expected outcome, not a stall.
    val advertised = remoteMaxMessageSize != null
    val boundary = echoIsIdentical(channel, ceiling, seed = 0x0B0E, wait = if (advertised) ECHO_WAIT else ADVISORY_PROBE_WAIT)
    if (boundary.passed) {
        return Verdict(true, "${largeSize}B echoed byte-identical, and so did a boundary probe at exactly the ${ceiling}B ceiling")
    }
    // A peer that ADVERTISED `a=max-message-size` promised to receive that much, so failing at exactly its
    // own number is a real interop defect and fails the phase. A peer that advertised NOTHING never made
    // that promise — the ceiling is our RFC 8841 §6 assumption — so the probe is reported as an observation
    // and the fragmentation proof stands on its own. (Pion v3 advertises none and does not take 65536.)
    return Verdict(
        passed = !advertised,
        detail =
            if (advertised) {
                "${largeSize}B echoed byte-identical, but the peer did NOT echo a message at the ${ceiling}B it advertised: ${boundary.detail}"
            } else {
                "${largeSize}B echoed byte-identical (fragmentation + reassembly proven); the peer advertised no " +
                    "max-message-size and did not echo one at the assumed ${ceiling}B ceiling — advisory, not a promise it broke"
            },
    )
}

/** min(what we advertise, what the peer advertised) — the largest message the peer agreed to receive. */
private fun negotiatedMaxMessageSize(remote: Long?): Int {
    val theirs = remote ?: ASSUMED_REMOTE_MAX_MESSAGE_SIZE
    val ours = DataChannelParameters.DEFAULT_MAX_MESSAGE_SIZE
    println("[harness] max-message-size: ours=$ours theirs=${remote ?: "<unadvertised — assuming $theirs>"} → ceiling=${minOf(ours, theirs)}")
    return minOf(ours, theirs).toInt()
}

/** Send a [size]-byte deterministic pattern and require the echo to be byte-identical. */
private suspend fun echoIsIdentical(
    channel: Connection<ReadBuffer>,
    size: Int,
    seed: Int,
    wait: Duration = ECHO_WAIT,
): Verdict {
    channel.send(patternBuffer(size, seed))
    val echo =
        withTimeoutOrNull(wait) { channel.receive().firstOrNull() }
            ?: return Verdict(false, "no echo of the ${size}B message within $wait")
    if (echo.remaining() != size) {
        return Verdict(false, "echo is ${echo.remaining()}B but ${size}B was sent — reassembly truncated or split the message")
    }
    val mismatch = echo.firstPatternMismatch(size, seed)
    return if (mismatch < 0) {
        Verdict(true, "${size}B echoed byte-identical")
    } else {
        Verdict(false, "echo differs from the sent pattern at byte $mismatch of $size — fragment reorder or corruption")
    }
}

// ── s2: unordered delivery ───────────────────────────────────────────────────────────────────────────

/**
 * `ordered=false` (DCEP channel type DATA_CHANNEL_RELIABLE_UNORDERED). A burst of index-tagged messages
 * must all come back — asserted as SET equality, never sequence: an unordered channel is *permitted* to
 * reorder, so asserting arrival order would be asserting the opposite of what we negotiated.
 *
 * Honest limit: a clean path rarely reorders, so here this proves the channel type is honored end-to-end
 * and still delivers reliably — not that reordering is TOLERATED. That is why the same phase also runs on
 * the impaired lane (decision D6), where netem's delay jitter produces real reordering, and why the
 * deterministic vnet suites remain the hard reordering gate.
 */
private suspend fun phaseUnordered(pc: NativePeerConnection): Verdict {
    val channel = pc.createDataChannel(DataChannelConfig(label = "s2/unordered", delivery = DeliveryOrder.Unordered))
    for (i in 0 until BURST) channel.send(textBuffer("s2#$i"))
    val seen = collectTagged(channel, "s2#", BURST, ECHO_WAIT)
    val missing = (0 until BURST).filterNot { it in seen }
    val reordered = seen.toList() != seen.sorted()
    return if (missing.isEmpty()) {
        val order = if (reordered) "arrival was REORDERED (the real proof — tolerated end-to-end)" else "arrival happened to be in order (clean path)"
        Verdict(true, "all $BURST unordered messages echoed; $order")
    } else {
        Verdict(false, "${missing.size}/$BURST unordered messages never echoed (first missing indices: ${missing.take(10)})")
    }
}

// ── s3: partial reliability (PR-SCTP) ────────────────────────────────────────────────────────────────

/**
 * Two PR profiles on two channels — `MaxRetransmits(0)` (RFC 3758 limited retransmission) and
 * `MaxLifetime` (timed reliability). Both are ORDERED, which is what makes the assertion sharp: if the far
 * side did not process our FORWARD-TSN after we abandoned a message, its cumulative TSN would never
 * advance and every later message on that stream would stall behind the hole. So "later messages still
 * arrive" and "the reliable control channel still round-trips" are the real interop proofs.
 *
 * Deliberately NOT asserted: that all N arrive. These channels are ALLOWED to lose messages — on the
 * impaired lane they must — so a count assertion would contradict the profile we negotiated.
 */
private suspend fun phasePartialReliable(
    pc: NativePeerConnection,
    ctl: ControlChannel,
): Verdict {
    val rexmit = pc.createDataChannel(DataChannelConfig(label = "s3/rexmit", reliability = SctpReliability.MaxRetransmits(0)))
    val timed = pc.createDataChannel(DataChannelConfig(label = "s3/timed", reliability = SctpReliability.MaxLifetime(PR_LIFETIME)))

    for (i in 0 until PR_BURST) rexmit.send(textBuffer("s3r#$i"))
    for (i in 0 until PR_BURST) timed.send(textBuffer("s3t#$i"))

    val gotRexmit = collectTagged(rexmit, "s3r#", PR_BURST, PR_COLLECT_WINDOW)
    val gotTimed = collectTagged(timed, "s3t#", PR_BURST, PR_COLLECT_WINDOW)

    // The no-wedge assertion: the reliable-ordered control channel must still round-trip after the
    // abandonments. Had the peer not processed our FORWARD-TSN, this is where we would be stuck.
    val alive = ctl.exchange("ALIVE s3", "ALIVE s3")

    val rexmitDetail = describePartial("s3/rexmit", gotRexmit)
    val timedDetail = describePartial("s3/timed", gotTimed)
    return when {
        !alive ->
            Verdict(false, "$rexmitDetail; $timedDetail; but the association WEDGED — the control channel stopped round-tripping after the PR bursts")
        gotRexmit.isEmpty() && gotTimed.isEmpty() ->
            Verdict(false, "the peer echoed NOTHING on either PR channel — the PR profiles were not usable end-to-end")
        else ->
            Verdict(true, "$rexmitDetail; $timedDetail; the association kept delivering afterwards (no wedge)")
    }
}

/**
 * Describe what came back on a PR channel. A GAP (a delivered index higher than the delivered count) is
 * the observable signature of a receiver that advanced past an abandoned TSN — i.e. it processed our
 * FORWARD-TSN. Reported as evidence, never gated on: on a clean path nothing is abandoned, so there is
 * legitimately no gap to observe.
 */
private fun describePartial(
    label: String,
    seen: Set<Int>,
): String {
    val gapped = seen.isNotEmpty() && seen.max() + 1 > seen.size
    val note = if (gapped) " WITH A GAP (the peer advanced past an abandoned TSN — FORWARD-TSN processed)" else " (nothing abandoned on this path)"
    return "$label delivered ${seen.size}/$PR_BURST$note"
}

// ── s4: multiple concurrent channels over one association ────────────────────────────────────────────

/**
 * Three channels opened back-to-back with mixed profiles, each carrying its own tagged message. The proof
 * is DEMUX: every echo must return on the channel it was sent on (RFC 8832 §6 stream-id assignment, RFC
 * 4960 per-stream delivery) — so a stack that collapsed streams or crossed ids fails here even though each
 * individual message round-trips fine.
 */
private suspend fun phaseMultiplex(
    bg: CoroutineScope,
    pc: NativePeerConnection,
): Verdict {
    val channels =
        listOf(
            pc.createDataChannel(DataChannelConfig(label = "s4/a")) to "s4a",
            pc.createDataChannel(DataChannelConfig(label = "s4/b", delivery = DeliveryOrder.Unordered)) to "s4b",
            pc.createDataChannel(DataChannelConfig(label = "s4/c", reliability = SctpReliability.MaxRetransmits(3))) to "s4c",
        )

    // Collectors first, then the sends: an unordered channel can deliver its echo before a later send
    // returns, and a collector attached afterwards would miss it.
    val collectors =
        channels.map { (channel, tag) ->
            bg.async {
                val echoed =
                    try {
                        withTimeoutOrNull(ECHO_WAIT) { channel.receive().firstOrNull()?.peekText() }
                    } catch (e: kotlinx.coroutines.CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        println("[harness] s4: collector for $tag stopped — ${e::class.simpleName}: ${e.message}")
                        null
                    }
                tag to echoed
            }
        }
    for ((channel, tag) in channels) channel.send(textBuffer(tag))

    val echoes = collectors.awaitAll().toMap()
    val wrong = echoes.filter { (tag, echoed) -> echoed != tag }.keys
    return if (wrong.isEmpty()) {
        Verdict(true, "3 concurrent channels (ordered / unordered / partial-reliable) each echoed on their OWN stream")
    } else {
        Verdict(false, "per-channel demux failed for ${wrong.sorted()} — echoes: $echoes")
    }
}

// ── s5: reverse direction (our lanes only) ───────────────────────────────────────────────────────────

/**
 * The one phase a foreign peer cannot play: the ANSWERER originates a channel and WE reflect it,
 * exercising our DCEP responder path (odd stream-id parity, RFC 8832 §6) over a real association rather
 * than only in the vnet. Enabled only when both endpoints are ours (`WEBRTC_REVERSE`, set by
 * `run-interop.sh` for the native⇄native / jvm⇄native lanes) so every foreign reflector stays dumb.
 *
 * The offerer's part: cue the phase on the control channel, then observe an INCOMING channel labelled
 * [REVERSE_LABEL] deliver a message that our own reflector echoed. The answerer asserts the echo itself.
 */
private suspend fun phaseReverse(
    ctl: ControlChannel,
    reflector: Reflector,
): Verdict {
    if (!ctl.exchange(REVERSE_CUE, REVERSE_CUE)) {
        return Verdict(false, "the reverse-phase cue never round-tripped on the control channel")
    }
    val event =
        reflector.awaitEvent(PHASE_TIMEOUT) { it.label == REVERSE_LABEL }
            ?: return Verdict(false, "the answerer never opened an incoming \"$REVERSE_LABEL\" channel within $PHASE_TIMEOUT")
    return Verdict(true, "reflected ${event.bytes}B on the answerer-originated \"$REVERSE_LABEL\" channel (our DCEP responder path)")
}

// ── shared helpers ───────────────────────────────────────────────────────────────────────────────────

/**
 * Collect echoes tagged `<prefix><index>` off [channel] until [want] distinct indices have arrived or
 * [timeout] elapses, returning the index SET that arrived (in arrival order). Always bounded — a
 * partial-reliable burst legitimately never reaches [want].
 */
private suspend fun collectTagged(
    channel: Connection<ReadBuffer>,
    prefix: String,
    want: Int,
    timeout: Duration,
): Set<Int> {
    val seen = LinkedHashSet<Int>()
    withTimeoutOrNull(timeout) {
        // `first { … }` collects until the predicate holds, then stops — leaving any later message queued
        // on the channel rather than draining it (the flow is a Channel, not a broadcast).
        channel.receive().first { message ->
            message.peekText()?.removePrefix(prefix)?.toIntOrNull()?.let { seen += it }
            seen.size >= want
        }
    }
    return seen
}

/**
 * Decode a SMALL payload as text without consuming it — the reflector must echo the exact bytes it
 * received, and a phase collector must read a tag without disturbing the buffer. Returns null for an empty
 * payload or one larger than [MAX_PEEK_BYTES] (i.e. every s1 binary), which is never decoded.
 */
internal fun ReadBuffer.peekText(): String? {
    val start = position()
    val n = remaining()
    if (n == 0 || n > MAX_PEEK_BYTES) return null
    val text = readString(n, Charset.UTF8)
    position(start)
    return text
}

/**
 * A [size]-byte deterministic pattern, array-free (standing directive #1: no `ByteArray` in a `*Main/`
 * source set). The bytes come from a seeded LCG, so the value at every offset depends on that offset: a
 * reassembly that reorders, duplicates or truncates a fragment produces a mismatch at a KNOWN byte instead
 * of a silently-plausible payload. [firstPatternMismatch] regenerates the same stream to verify, so the
 * payload is never materialised twice.
 */
internal fun patternBuffer(
    size: Int,
    seed: Int,
): ReadBuffer {
    val buffer = BufferFactory.Default.allocate(size, ByteOrder.BIG_ENDIAN)
    var state = seed
    repeat(size) {
        state = state * LCG_MULTIPLIER + LCG_INCREMENT
        buffer.writeByte(((state ushr 16) and 0xFF).toByte())
    }
    buffer.resetForRead()
    buffer.setLimit(size)
    return buffer
}

/** The first byte offset at which [this] differs from the [size]/[seed] pattern, or -1 when identical. */
internal fun ReadBuffer.firstPatternMismatch(
    size: Int,
    seed: Int,
): Int {
    var state = seed
    for (i in 0 until size) {
        state = state * LCG_MULTIPLIER + LCG_INCREMENT
        if (readByte() != ((state ushr 16) and 0xFF).toByte()) return i
    }
    return -1
}

// The classic ANSI-C LCG constants — arbitrary but fixed, so the pattern is identical on every target.
private const val LCG_MULTIPLIER = 1103515245
private const val LCG_INCREMENT = 12345

/**
 * The channel's DCEP label. [Connection] is transport-agnostic by design and carries no label, so the
 * harness reads it off the concrete [DataChannelConnection] the SCTP stack hands back. (Exposing the label
 * on the consumer-facing channel type is a reasonable library follow-up.)
 */
internal fun Connection<ReadBuffer>.channelLabel(): String = (this as? DataChannelConnection)?.config?.label ?: "<unlabelled>"

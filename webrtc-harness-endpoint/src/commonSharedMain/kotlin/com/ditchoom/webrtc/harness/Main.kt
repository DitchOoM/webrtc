@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.deterministic
import com.ditchoom.buffer.flow.AddressFamily
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.PureKotlinDtls
import com.ditchoom.webrtc.IceGatheringPolicy
import com.ditchoom.webrtc.NativePeerConnection
import com.ditchoom.webrtc.PeerConnectionConfig
import com.ditchoom.webrtc.PeerConnectionState
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.ice.IceConfig
import com.ditchoom.webrtc.ice.MdnsResolution
import com.ditchoom.webrtc.ice.MdnsResolver
import com.ditchoom.webrtc.ice.MulticastMdnsResolver
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sdp.SdpParseResult
import com.ditchoom.webrtc.sdp.SdpType
import com.ditchoom.webrtc.sdp.SessionDescription
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.system.exitProcess
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The L2/L3 interop **peer** — the "our side" endpoint the container harness runs behind real NAT kernels
 * (webrtc HANDOFF: the interop endpoint MUST be the native binary, the only one with a real DTLS
 * handshake). It composes the exact production stack — [NativePeerConnection] + [PureKotlinDtls] over the
 * real-UDP [realUdpBinder] — gathers host/srflx(coturn)/relay(coturn TURN) candidates, exchanges
 * offer/answer/candidates over the UDP [UdpSignaling] rendezvous, and proves the data path with a
 * ping/pong over a data channel. Exit 0 = established + echoed; non-zero = a typed failure or timeout.
 */
fun main() {
    val cfg = HarnessConfig.fromEnv()
    // `seed=` is load-bearing for deterministic replay: cfg.seed drives EVERY entropy source (ICE ufrag /
    // tie-breaker / STUN txn-ids / SCTP init-tag via Random(cfg.seed) below, AND the DTLS handshake randoms
    // + ephemeral keys via the derived DtlsConfig.random). Logging it is what lets a real-UDP CI flake be
    // reconstructed as a seeded virtual-time vnet fixture (standing directive #5) — see
    // docs/HARNESS_IPV6_DIAGNOSTICS_DESIGN.md. Without this line the seed that drove a failure is in no artifact.
    val binds = cfg.bindings.joinToString(", ") { "${it.family}=${it.localIp}" }
    println("[harness] role=${cfg.role} session=${cfg.session} policy=${cfg.icePolicy} local=[$binds]:${cfg.localPort} dtls13=${cfg.enableDtls13} seed=${cfg.seed}")
    val code = runBlocking { runPeer(cfg) }
    println("[harness] exit=$code")
    exitProcess(code)
}

// Wrap the mDNS resolver so every `.local` resolution is observable in the peer log — the same-LAN mDNS
// interop lane greps this to prove our MulticastMdnsResolver actually fired on the browser's obfuscated
// `<uuid>.local` candidate (as opposed to the connection winning via a peer-reflexive pair, which on a
// no-NAT shared segment can short-circuit resolution). Harness-only; the library resolver stays silent.
// [onResolved] fires once per successful resolution so [runPeer] can gate the require-mDNS lane on it.
private fun MdnsResolver.logged(onResolved: () -> Unit): MdnsResolver =
    MdnsResolver { hostname ->
        resolve(hostname).also { res ->
            when (res) {
                is MdnsResolution.Resolved -> {
                    println("[harness] mdns resolved $hostname -> ${res.address}")
                    onResolved()
                }
                is MdnsResolution.Unresolved -> println("[harness] mdns UNRESOLVED $hostname")
            }
        }
    }

private suspend fun runPeer(cfg: HarnessConfig): Int =
    coroutineScope {
        // One cancellable child scope for all long-lived machinery (pc, dtls, the gather/trickle/poll
        // loops) so the outer coroutineScope returns the moment the flow finishes and we cancel it.
        val bg = CoroutineScope(coroutineContext + Job())

        // Driver edge: the peer is a driver, not a sans-io core, so the injected clock's production value
        // is genuinely the wall clock (directive #2 — the seam is honored, its default supplied here).
        // The annotation MUST stay on the same line as Clock.System — the standing-directive grep is line-based.
        @Suppress("UnseamedEntropy") val clock: () -> Instant = { Clock.System.now() }

        // The one real-UDP integration fact: socket-udp's io_uring `send` rejects a GC-heap buffer, so
        // every OUTBOUND datagram — STUN checks (ICE), DTLS records, SCTP packets, and the signaling
        // frames — must be encoded into NATIVE memory. Inject buffer's Linux native factory
        // (deterministic() → malloc-backed NativeBuffer) into every layer's bufferFactory seam. (These
        // buffers are manual-free; the peer is a short-lived establish-and-echo process, so the bounded
        // native allocation is acceptable here — pooled release is the W3/W5-deferred production refactor.)
        val net = BufferFactory.deterministic()

        // Seed the DTLS entropy off the SAME cfg.seed (a fixed derivation, xor 0xD715) so the handshake
        // randoms + ephemeral X25519 keys are byte-reproducible from the one logged seed — otherwise
        // DtlsConfig.random defaults to CryptoRandom and a DTLS-layer flake (e.g. the post-Established
        // handshake-record storm) can't be replayed even given the seed. This is a driver, not a core, so a
        // seeded default is correct (the whole peer is deterministic-by-seed for replay).
        @Suppress("UnseamedEntropy") val dtlsRandom = Random(cfg.seed xor 0xD715L)
        val dtls = PureKotlinDtls(bg, clock, DtlsConfig(bufferFactory = net, enableDtls13 = cfg.enableDtls13, random = dtlsRandom))

        // Completes the first time our MulticastMdnsResolver resolves a browser `.local` (via the `.logged`
        // wrapper). The require-mDNS lane awaits it after echo (watchdog-bounded) so a rc=0 there PROVES
        // resolution fired; every other lane leaves it uncompleted and never waits on it. See issue #48.
        val mdnsResolved = CompletableDeferred<Unit>()

        val gathering =
            IceGatheringPolicy { driver ->
                // One host(+srflx)+relay per configured family. A dual-stack lane advertises BOTH v4 and v6
                // candidates, exercising the RFC 6724 candidate-priority ordering (webrtc-ice, PR #37); a
                // single-stack lane advertises exactly one. Real WebRTC stacks (pion, the browsers) gather
                // per family by enumerating interfaces — our explicit-bind peer mirrors that by looping the
                // injected per-family [FamilyBinding]s, each with its own coturn address for that family.
                for (b in cfg.bindings) {
                    val stun = resolveAddress(b.stunHost, cfg.stunPort)
                    val turn = resolveAddress(b.turnHost, cfg.turnPort)
                    if (cfg.icePolicy != IcePolicy.RelayOnly) {
                        driver.gatherHost(b.localIp, cfg.localPort, stunServer = stun)
                    }
                    // Relay is always gathered — the fallback path, and the only path under relayOnly.
                    driver.gatherRelay(turn, cfg.turnUser, cfg.turnPass, b.localIp, cfg.relayPort)
                }
            }

        val pc =
            NativePeerConnection(
                scope = bg,
                clock = clock,
                random = Random(cfg.seed),
                binder = realUdpBinder(),
                gathering = gathering,
                dtls = dtls,
                config =
                    PeerConnectionConfig(
                        iceConfig = IceConfig(bufferFactory = net),
                        // Resolve a peer's `<uuid>.local` host candidate (RFC 8828) over real multicast. Only
                        // fires when a `.local` candidate actually arrives (the same-LAN mDNS lane, where the
                        // browser advertises obfuscated hosts and shares our link); on the NAT'd lanes no
                        // `.local` is ever offered, so this stays dormant. Query only the lane's families.
                        mdnsResolver =
                            MulticastMdnsResolver(
                                families =
                                    cfg.bindings
                                        .map { if (it.family == IpFamily.V4) AddressFamily.IPv4 else AddressFamily.IPv6 }
                                        .distinct(),
                                bufferFactory = net,
                            ).logged(onResolved = { mdnsResolved.complete(Unit) }),
                        // Fast SCTP RTO for the harness's low-RTT network: the default 3s initial RTO
                        // (RFC 4960, tuned for the internet) means a single lost DATA chunk — e.g. the
                        // echo pong under the impaired lane's loss — waits 3s before the first retransmit,
                        // which races the answerer's teardown. Sub-second recovery makes loss reliable here.
                        sctpConfig =
                            SctpConfig(
                                bufferFactory = net,
                                rtoInitial = 500.milliseconds,
                                rtoMin = 100.milliseconds,
                            ),
                    ),
            )

        // Two signaling sockets (PUT + poll), owned here so they are closed AFTER bg.cancel() stops the
        // loops that use them — closing them earlier would leave those loops spinning on a closed socket.
        val sigOut = UdpSignaling.open(cfg.rendezvousHost, cfg.rendezvousPort, cfg.session, net)
        val sigIn = UdpSignaling.open(cfg.rendezvousHost, cfg.rendezvousPort, cfg.session, net)

        // Per-side state-transition trace, dumped on exit (below). The one signal that pins a lossy-path
        // handshake stall is the ASYMMETRY of the two peers' TERMINAL states — one peer sits `Connected`
        // while the other never leaves `Connecting` (the lost-final-flight deadlock, PR #27). A single
        // final-state line hides that; the full timestamped history makes it obvious in each peer's log,
        // which the L2 harness already captures + uploads on failure — so a CI failure is diagnosable from
        // the artifact, no local repro needed. Timestamps ride the injected clock seam (directive #2), and
        // StateFlow collection already yields only distinct transitions.
        val t0 = clock()
        val trace = mutableListOf<StateTransition>()
        bg.launch {
            pc.connectionState.collect { state -> trace += StateTransition(clock() - t0, state) }
        }

        // The replay inputs the seed alone can't reconstruct: the exact SDP this side offered/answered and
        // the candidate set it gathered + received. Captured here, dumped on exit (below), so a diag bundle
        // carries the peer's own view of the exchange to seed a virtual-time vnet fixture from.
        val forensics = Forensics()

        // Require-mDNS lane (issue #48): establish + echo alone don't prove mDNS RESOLUTION — prflx wins the
        // pair long before the resolver matters (and a resolved `.local` can never BE the selected pair: it
        // is link-local, i.e. the same directly-reachable IP). So the offerer additionally waits for our
        // resolver to have fired on one of the browser's obfuscated `.local` candidates. The role's
        // candidate-poll + fire-and-forget resolve loops are still live on `bg`, so the browser's trickled
        // `.local` keeps arriving and resolving while we wait. Watchdog, not a wall-clock budget (directive
        // #4): the observable state is "≥1 `.local` resolved". Off (every other lane) we don't wait.
        //
        // It is checked INSIDE the role (right after phase 0) rather than after it, because the semantics
        // sequence ends by CLOSING the session — a post-hoc mDNS wait would then be watching a torn-down
        // ICE agent.
        val mdnsGate: suspend () -> Boolean = {
            if (!cfg.requireMdns) {
                true
            } else if (withTimeoutOrNull(MDNS_RESOLVE_WAIT) { mdnsResolved.await() } != null) {
                true
            } else {
                println("[harness] mdns REQUIRED but no browser .local resolved within $MDNS_RESOLVE_WAIT")
                false
            }
        }

        // The establishment watchdog, plus the semantics budget when the phase sequence runs (it is bounded
        // again, per phase, inside the sequence itself).
        val overall = if (cfg.semantics) cfg.timeout + cfg.semanticsTimeout else cfg.timeout
        val ok =
            withTimeoutOrNull(overall) {
                when (cfg.role) {
                    Role.Offerer -> runOfferer(bg, pc, cfg, sigOut, sigIn, forensics, clock, mdnsGate)
                    Role.Answerer -> runAnswerer(bg, pc, cfg, sigOut, sigIn, forensics)
                }
            } ?: run {
                println("[harness] TIMEOUT after $overall; state=${pc.connectionState.value}")
                false
            }

        // Dump the transition history before bg.cancel() stops the collector. Ensure the final observed
        // state is recorded even if a terminal transition raced the collector's last resumption.
        val finalState = pc.connectionState.value
        if (trace.lastOrNull()?.state != finalState) trace += StateTransition(clock() - t0, finalState)
        println("[harness] state-transition trace (${cfg.role}, ${trace.size} transitions):")
        for (t in trace) println("[harness]   +${t.at.inWholeMilliseconds}ms  ${t.state}")
        forensics.dump(cfg.role)

        // close() BEFORE bg.cancel(): it now performs a graceful association shutdown (RFC 4960 §9.2), and
        // that needs the stack's drive/writer loops — which live on `bg` — to still be running. Cancelling
        // first would leave the SHUTDOWN chunk queued on a dead loop and the peer would see the association
        // vanish. Idempotent, so the offerer's s6 close phase has usually already done this.
        pc.close()
        bg.cancel()
        sigOut.close()
        sigIn.close()
        if (ok) 0 else 1
    }

private suspend fun runOfferer(
    bg: CoroutineScope,
    pc: NativePeerConnection,
    cfg: HarnessConfig,
    sigOut: UdpSignaling,
    sigIn: UdpSignaling,
    forensics: Forensics,
    clock: () -> Instant,
    mdnsGate: suspend () -> Boolean,
): Boolean {
    // The control channel — phase 0's ping/pong, then (semantics mode) the BEGIN/DONE lifecycle. It keeps
    // its historical label so every existing lane's logs, diag bundles and getStats entries read the same.
    val ctl = ControlChannel(pc.createDataChannel(DataChannelConfig(label = CTL_LABEL)))
    // The offerer reflects too: the answerer-originated reverse channel (s5) is echoed by exactly the same
    // universal reflector the far side runs, so neither side needs role-specific echo logic.
    val reflector = Reflector(bg)
    // The peer's `a=max-message-size` (RFC 8841 §6), read off its answer — s1 clamps its payload to it.
    val remoteMaxMessageSize = CompletableDeferred<Long?>()
    val offer = pc.createOffer()
    forensics.recordSdp(Origin.Local, Sdp(offer))
    pc.setLocalDescription(SdpType.Offer, offer)

    // One PUT socket, single-consumer: the offer first (record 0), then trickled candidates in order.
    val outbox = Channel<OutboundRecord>(Channel.UNLIMITED)
    outbox.trySend(OutboundRecord(Slot.Offer, RecordId(0), offer))
    bg.launch { for (r in outbox) sigOut.put(r.slot, r.recordId, r.payload) }
    bg.launch {
        var i = 0
        pc.localIceCandidates.collect {
            forensics.recordCandidate(Origin.Local, CandidateLine(it))
            outbox.trySend(OutboundRecord(Slot.OffererCandidate, RecordId(i++), it))
        }
    }

    // One poll socket, single-consumer: the answer, then the answerer's trickled candidates.
    bg.launch {
        var answered = false
        var seen = 0
        while (isActive) {
            if (!answered) {
                val a = sigIn.poll(Slot.Answer, RecordId(0))
                if (a.isNotEmpty()) {
                    forensics.recordSdp(Origin.Remote, Sdp(a.first()))
                    remoteMaxMessageSize.complete(maxMessageSizeOf(a.first()))
                    pc.setRemoteDescription(SdpType.Answer, a.first())
                    answered = true
                }
            } else {
                val cands = sigIn.poll(Slot.AnswererCandidate, RecordId(seen))
                seen += cands.size
                for (c in cands) {
                    forensics.recordCandidate(Origin.Remote, CandidateLine(c))
                    pc.addIceCandidate(c)
                }
            }
            delay(POLL_INTERVAL)
        }
    }

    if (!awaitEstablished(pc)) return false

    ctl.start(bg)
    reflector.start(pc)

    // Phase 0 — the liveness ritual every lane has always run, byte-identical: one `ping` on the control
    // channel, one `pong` back. Establishment is still proven exactly as before, ahead of any semantics.
    val pong = ctl.pingPongReply(ECHO_TIMEOUT)
    println("[harness] offerer echo reply: $pong")
    if (pong != "pong") return false
    if (!mdnsGate()) return false
    if (!cfg.semantics) return true

    // The semantics sequence (docs/DC_SEMANTICS_INTEROP_DESIGN.md): every phase runs, a failure is recorded
    // and the run continues (D2), and the summary line below is what run-interop.sh grades.
    val report =
        withTimeoutOrNull(cfg.semanticsTimeout) {
            runSemanticsPhases(bg, pc, ctl, reflector, cfg, clock, remoteMaxMessageSize.await())
        }
    if (report == null) {
        println("[harness] semantics: TIMEOUT — the phase sequence did not finish within ${cfg.semanticsTimeout}")
        println("[harness] semantics-summary: total=0 passed=0 failed=1 failed-phases=[timeout]")
        return !cfg.semanticsRequired
    }

    // s6/close — the DONE handshake, then a graceful ASSOCIATION shutdown (decision D1a). Per-channel
    // close via RFC 6525 stream reset now EXISTS in webrtc-sctp and is covered by its own unit + vnet
    // fixtures; proving it against the foreign peers is a harness phase of its own, not a change to s6.
    // `DONE` returning proves the association was still healthy at teardown, and replaces the old
    // FLUSH_LINGER-vs-ECHO_TIMEOUT teardown race with an explicit agreement that the run is over.
    val closeStarted = clock()
    val doneAcked = ctl.done()
    if (doneAcked) {
        println("[harness] s6/close: DONE acknowledged — starting the graceful association SHUTDOWN")
        // close() drives SHUTDOWN → SHUTDOWN-ACK → SHUTDOWN-COMPLETE and waits (bounded) for the
        // association to report Closed before the ICE transport under it goes away. The far side's log is
        // where the proof lands: a CLEAN close, not an ABORT and not a vanished association.
        pc.close()
    }
    report.record(
        PhaseOutcome(
            id = "s6",
            passed = doneAcked,
            detail =
                if (doneAcked) {
                    "DONE round-tripped and a graceful association SHUTDOWN was initiated (the peer's log carries the clean-close proof)"
                } else {
                    "the DONE handshake never round-tripped — the association was already gone before teardown"
                },
            took = clock() - closeStarted,
        ),
    )
    report.printSummary()
    // Non-gating-first (D7): the phases always run and always report; whether a failure fails THIS process
    // is the orchestrator's call, carried in WEBRTC_SEMANTICS_REQUIRED.
    return if (cfg.semanticsRequired) report.allPassed else true
}

/** The peer's advertised `a=max-message-size` (RFC 8841 §6) from its answer, or null if it advertised none. */
private fun maxMessageSizeOf(sdp: String): Long? =
    when (val parsed = SessionDescription.parseText(sdp)) {
        is SdpParseResult.Success -> parsed.description.mediaDescriptions.firstOrNull()?.maxMessageSize()
        is SdpParseResult.Reject -> null
    }

private suspend fun runAnswerer(
    bg: CoroutineScope,
    pc: NativePeerConnection,
    cfg: HarnessConfig,
    sigOut: UdpSignaling,
    sigIn: UdpSignaling,
    forensics: Forensics,
): Boolean {
    // Await the offer (bounded by the outer watchdog), then answer.
    var offer: String? = null
    while (offer == null) {
        val o = sigIn.poll(Slot.Offer, RecordId(0))
        if (o.isNotEmpty()) offer = o.first() else delay(POLL_INTERVAL)
    }
    forensics.recordSdp(Origin.Remote, Sdp(offer))
    pc.setRemoteDescription(SdpType.Offer, offer)
    val answer = pc.createAnswer()
    forensics.recordSdp(Origin.Local, Sdp(answer))
    pc.setLocalDescription(SdpType.Answer, answer)

    val outbox = Channel<OutboundRecord>(Channel.UNLIMITED)
    outbox.trySend(OutboundRecord(Slot.Answer, RecordId(0), answer))
    bg.launch { for (r in outbox) sigOut.put(r.slot, r.recordId, r.payload) }
    bg.launch {
        var i = 0
        pc.localIceCandidates.collect {
            forensics.recordCandidate(Origin.Local, CandidateLine(it))
            outbox.trySend(OutboundRecord(Slot.AnswererCandidate, RecordId(i++), it))
        }
    }

    // The offer poll above is done, so this launched loop is the only consumer of sigIn (no receive race).
    bg.launch {
        var seen = 0
        while (isActive) {
            val cands = sigIn.poll(Slot.OffererCandidate, RecordId(seen))
            seen += cands.size
            for (c in cands) {
                forensics.recordCandidate(Origin.Remote, CandidateLine(c))
                pc.addIceCandidate(c)
            }
            delay(POLL_INTERVAL)
        }
    }

    // The universal reflector (docs/DC_SEMANTICS_INTEROP_DESIGN.md §4): echo every message back on the
    // channel it arrived on, for EVERY channel the offerer opens — the same ~15-line contract Pion, werift
    // and the browser page implement. `ping`→`pong` is the one historical exception, so phase 0 is
    // unchanged. No scenario logic lives here: the reflector never reads a label to decide behaviour.
    val reflector = Reflector(bg)
    reflector.start(pc)

    val ping = reflector.awaitText("ping", ECHO_TIMEOUT)
    println("[harness] answerer received: ${ping?.text}")
    val ok = awaitEstablished(pc) && ping != null
    if (!ok) return false

    if (!cfg.semantics) {
        // Linger before teardown so SCTP reliably delivers + gets the final "pong" acked. Without this the
        // answerer closes its association the instant after send(), racing delivery, and the offerer's
        // channel.receive() times out (the pong was queued but never transmitted/retransmitted). The
        // offerer's ECHO_TIMEOUT bounds the wait on the other side; this window is shorter than that.
        delay(FLUSH_LINGER)
        return true
    }

    // Semantics mode: reflect until the offerer's explicit DONE — which replaces the linger/timeout race
    // above with an agreement. Two lifecycle words are acted on; every other message is only echoed.
    var reverse: Boolean? = null
    var sawDone = false
    withTimeoutOrNull(cfg.semanticsTimeout) {
        for (event in reflector.events) {
            when (event.text) {
                // s5 (our lanes only): originate a channel in the REVERSE direction and assert our own
                // echo comes back, exercising the DCEP responder path (odd stream-id parity) on the wire.
                REVERSE_CUE -> if (cfg.reverseChannel && reverse == null) reverse = originateReverseChannel(pc)
                DONE_MARKER -> {
                    sawDone = true
                    return@withTimeoutOrNull
                }
            }
        }
    }
    if (!sawDone) {
        println("[harness] semantics: the offerer's DONE never arrived within ${cfg.semanticsTimeout}")
        return false
    }
    println("[harness] reverse-summary: enabled=${cfg.reverseChannel} ok=${reverse ?: "n/a"}")

    // The far half of s6/close: the offerer now starts a graceful association SHUTDOWN, and THIS is where
    // it is observed. A clean close reaches Closed; an ABORT or a vanished association reaches Failed or
    // nothing at all. Observable state + watchdog (directive #4), never a fixed sleep.
    val terminal =
        withTimeoutOrNull(CLOSE_OBSERVE_WAIT) {
            pc.connectionState.first { it is PeerConnectionState.Closed || it is PeerConnectionState.Failed }
        }
    println("[harness] close-summary: observed=${terminal ?: "<nothing within $CLOSE_OBSERVE_WAIT>"} clean=${terminal is PeerConnectionState.Closed}")
    return true
}

/**
 * s5 — the answerer originates a data channel and asserts the OFFERER reflects it. It is the one phase a
 * foreign peer cannot play (they are dumb reflectors and never originate), so `run-interop.sh` enables it
 * only on the native⇄native / jvm⇄native lanes. On the wire it exercises our DCEP responder parity: the
 * answerer is the SCTP server, so this channel takes an ODD stream id (RFC 8832 §6).
 */
private suspend fun originateReverseChannel(pc: NativePeerConnection): Boolean {
    val channel = pc.createDataChannel(DataChannelConfig(label = REVERSE_LABEL))
    channel.send(textBuffer(REVERSE_PAYLOAD))
    val echo = withTimeoutOrNull(ECHO_TIMEOUT) { channel.receive().first() }?.peekText()
    println("[harness] s5/reverse: originated \"$REVERSE_LABEL\" (stream ${channel.id}); echo=${echo?.let { "\"$it\"" } ?: "<none>"}")
    return echo == REVERSE_PAYLOAD
}

/** The single message the answerer sends on its reverse channel; the offerer reflects it verbatim. */
private const val REVERSE_PAYLOAD = "rev#0"

/** Suspend until the session reaches Connected (true) or a typed Failed (false, reason printed). */
private suspend fun awaitEstablished(pc: NativePeerConnection): Boolean {
    val terminal =
        pc.connectionState.first {
            it is PeerConnectionState.Connected || it is PeerConnectionState.Failed
        }
    if (terminal is PeerConnectionState.Failed) {
        println("[harness] FAILED: ${terminal.reason}")
        return false
    }
    println("[harness] CONNECTED")
    return true
}

// [Sdp] + [CandidateLine] — the diagnostics-boundary text wrappers — live in commonMain (SignalingTypes.kt):
// `@JvmInline` value classes are only legal in common sources, not this per-target-compiled shared srcDir.

/** Which peer produced a captured artifact — the local side, or the remote observed over signaling. */
private enum class Origin { Local, Remote }

/** A session description captured during the exchange, tagged with which side produced it. */
private data class RecordedSdp(val origin: Origin, val sdp: Sdp)

/** An ICE candidate line captured during the exchange, tagged with which side produced it. */
private data class RecordedCandidate(val origin: Origin, val line: CandidateLine)

/**
 * The replay inputs a seed alone can't reconstruct: this side's own view of the SDP exchange and the
 * candidate set. Artifacts are recorded **as they are observed** (each tagged with its [Origin]), so there
 * is no "not yet set" state to model with a null — the recorder holds exactly what happened, like the
 * state-transition `trace`. [dump]ed to stdout on exit (the L2 harness captures + uploads it on failure),
 * so a `collect_diagnostics` bundle carries everything a seeded virtual-time vnet fixture needs — the SDPs
 * (fingerprint / ufrag / pwd / setup / mid) and the exact candidate lines — alongside the logged seed and
 * the NAT-WAN pcap. See docs/HARNESS_IPV6_DIAGNOSTICS_DESIGN.md (standing directive #5).
 */
private class Forensics {
    private val descriptions = mutableListOf<RecordedSdp>()
    private val candidates = mutableListOf<RecordedCandidate>()

    fun recordSdp(origin: Origin, sdp: Sdp) {
        descriptions += RecordedSdp(origin, sdp)
    }

    fun recordCandidate(origin: Origin, line: CandidateLine) {
        candidates += RecordedCandidate(origin, line)
    }

    fun dump(role: Role) {
        val local = candidates.count { it.origin == Origin.Local }
        println("[harness] forensics ($role): descriptions=${descriptions.size} localCandidates=$local remoteCandidates=${candidates.size - local}")
        for (d in descriptions) {
            val tag = d.origin.name.lowercase()
            for (line in d.sdp.text.lines()) if (line.isNotBlank()) println("[harness]   $tag-sdp| $line")
        }
        for (c in candidates) println("[harness]   ${c.origin.name.lowercase()}-cand| ${c.line.text}")
    }
}

/** One record queued for the PUT socket — a named type over the old `Triple<slot, id, payload>`. */
private data class OutboundRecord(val slot: Slot, val recordId: RecordId, val payload: String)

/** One observed [PeerConnectionState] transition and [at] how long after the session started it happened. */
private data class StateTransition(val at: Duration, val state: PeerConnectionState)

private val POLL_INTERVAL = 200.milliseconds

// Echo/flush windows for the IMPAIRED lane: with the harness's fast SCTP RTO (500ms initial, 100ms min),
// a lost pong (or SACK) is recovered in well under a second per retransmit, so these need only cover a
// handful of losses. The answerer keeps its association ALIVE (still retransmitting) for FLUSH_LINGER after
// send(pong), and the offerer waits ECHO_TIMEOUT (> FLUSH_LINGER, so it listens for the whole retransmit
// window). Watchdogs, not wall-clock budgets (directive #4); the answerer's exit is the only thing slowed.
private val ECHO_TIMEOUT = 15.seconds
private val FLUSH_LINGER = 10.seconds

// Require-mDNS lane watchdog (issue #48): how long, after echo, to wait for our resolver to fire on the
// browser's obfuscated `.local`. Browsers gather host candidates FIRST (no STUN RTT), so the `.local` is
// among the earliest trickled — it has normally already arrived by the time echo completes; this only
// covers the tail where the browser's trickle lags our sub-second prflx connect. Bounded by the outer
// cfg.timeout regardless. A watchdog on the observable "resolved" state, not a padding delay (directive #4).
private val MDNS_RESOLVE_WAIT = 10.seconds

// How long the answerer watches for the offerer's graceful association SHUTDOWN to land (s6/close). A
// watchdog on the observable terminal state, not a sleep: it ends the moment the association reports
// Closed. Comfortably longer than the offerer's own bounded close, so a clean close is never missed.
private val CLOSE_OBSERVE_WAIT = 15.seconds

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
import com.ditchoom.webrtc.ice.MulticastMdnsResolver
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sdp.SdpType
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
                            ),
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

        val ok =
            withTimeoutOrNull(cfg.timeout) {
                when (cfg.role) {
                    Role.Offerer -> runOfferer(bg, pc, cfg, sigOut, sigIn, forensics)
                    Role.Answerer -> runAnswerer(bg, pc, cfg, sigOut, sigIn, forensics)
                }
            } ?: run {
                println("[harness] TIMEOUT after ${cfg.timeout}; state=${pc.connectionState.value}")
                false
            }

        // Dump the transition history before bg.cancel() stops the collector. Ensure the final observed
        // state is recorded even if a terminal transition raced the collector's last resumption.
        val finalState = pc.connectionState.value
        if (trace.lastOrNull()?.state != finalState) trace += StateTransition(clock() - t0, finalState)
        println("[harness] state-transition trace (${cfg.role}, ${trace.size} transitions):")
        for (t in trace) println("[harness]   +${t.at.inWholeMilliseconds}ms  ${t.state}")
        forensics.dump(cfg.role)

        bg.cancel()
        sigOut.close()
        sigIn.close()
        pc.close()
        if (ok) 0 else 1
    }

private suspend fun runOfferer(
    bg: CoroutineScope,
    pc: NativePeerConnection,
    cfg: HarnessConfig,
    sigOut: UdpSignaling,
    sigIn: UdpSignaling,
    forensics: Forensics,
): Boolean {
    val channel = pc.createDataChannel(DataChannelConfig(label = "harness"))
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
    channel.send(textBuffer("ping"))
    val pong = withTimeoutOrNull(ECHO_TIMEOUT) { channel.receive().first() }?.text()
    println("[harness] offerer echo reply: $pong")
    return pong == "pong"
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

    val incoming = pc.incomingDataChannels.first()
    val msg = withTimeoutOrNull(ECHO_TIMEOUT) { incoming.receive().first() }?.text()
    println("[harness] answerer received: $msg")
    if (msg == "ping") incoming.send(textBuffer("pong"))
    val ok = awaitEstablished(pc) && msg == "ping"
    // Linger before teardown so SCTP reliably delivers + gets the final "pong" acked. Without this the
    // answerer closes its association the instant after send(), racing delivery, and the offerer's
    // channel.receive() times out (the pong was queued but never transmitted/retransmitted). The
    // offerer's ECHO_TIMEOUT bounds the wait on the other side; this window is shorter than that.
    if (ok) delay(FLUSH_LINGER)
    return ok
}

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

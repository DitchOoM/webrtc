@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.deterministic
import com.ditchoom.buffer.flow.AddressFamily
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.PureKotlinDtls
import com.ditchoom.webrtc.IceGatheringPolicy
import com.ditchoom.webrtc.IceRestartPolicy
import com.ditchoom.webrtc.ice.NetworkMonitorSupport
import com.ditchoom.webrtc.ice.systemNetworkMonitor
import com.ditchoom.webrtc.MdnsAdvertisePolicy
import com.ditchoom.webrtc.NativePeerConnection
import com.ditchoom.webrtc.PeerConnectionConfig
import com.ditchoom.webrtc.PeerConnectionState
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.ice.IceConfig
import com.ditchoom.webrtc.ice.MdnsResolution
import com.ditchoom.webrtc.ice.MdnsResolver
import com.ditchoom.webrtc.ice.MdnsResponse
import com.ditchoom.webrtc.ice.MulticastMdnsEndpoint
import com.ditchoom.webrtc.ice.MulticastMdnsResolver
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sdp.SdpParseResult
import com.ditchoom.webrtc.sdp.SdpType
import com.ditchoom.webrtc.sdp.SessionDescription
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineExceptionHandler
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
    // The consent schedule this run actually installed. s9's whole verdict is "we outlived a revocation
    // window", so the window it outlived has to be in the artifact — otherwise a lane that silently ran on
    // the RFC defaults would report the same PASS while proving nothing (see phaseConsentIdle).
    println("[harness] consent: interval=${cfg.consentInterval} timeout=${cfg.consentTimeout} idle=${cfg.consentIdle}")
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
        //
        // The handler is a **backstop, not the fix**: `Job()` makes this a ROOT scope, so a throw escaping
        // any `bg.launch` goes to the unhandled-exception path rather than to the enclosing
        // `coroutineScope` — and on Kotlin/Native that terminates the process (`rc=139`), losing the
        // scenario verdict and every log line still buffered. Each loop is expected to guard its own I/O
        // (see `UdpSignaling.trySend`); this catches the one nobody thought of and leaves the peer alive
        // long enough to report why. It deliberately does NOT cancel `bg`: the loops are independent, and
        // one dead poll loop must not take a healthy data channel down with it.
        val bg =
            CoroutineScope(
                coroutineContext + Job() +
                    CoroutineExceptionHandler { ctx, e ->
                        println("[harness] BUG: unhandled exception in $ctx — absorbed to keep the peer alive: $e")
                        e.printStackTrace()
                    },
            )

        // Driver edge: the peer is a driver, not a sans-io core, so the injected clock's production value
        // is genuinely the wall clock (directive #2 — the seam is honored, its default supplied here).
        // The annotation MUST stay on the same line as Clock.System — the standing-directive grep is line-based.
        @Suppress("UnseamedEntropy") val clock: () -> Instant = { Clock.System.now() }

        // The one real-UDP integration fact: socket-udp's io_uring `send` rejects a GC-heap buffer, so
        // every OUTBOUND datagram — STUN checks (ICE), DTLS records, SCTP packets, and the signaling
        // frames — must be encoded into NATIVE memory. Inject buffer's Linux native factory
        // (deterministic() → malloc-backed NativeBuffer) into every layer's bufferFactory seam. (These
        // buffers are manual-free; the peer is a short-lived establish-and-echo process, so the bounded
        // native allocation is acceptable here — pooled release is a deferred production refactor.)
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

        // …and the mirror, for the direction #88 added: completes the first time OUR responder answers a
        // foreign peer's query for one of the names we minted. The require-answered lane awaits this too, so
        // a rc=0 there proves a browser could resolve OUR `.local` — not merely that it tolerated one.
        val mdnsAnswered = CompletableDeferred<Unit>()

        // The mDNS actual. Advertising off (every NAT lane, and production until a consumer asks for it):
        // the resolve-only [MulticastMdnsResolver], holding a socket only while a query is in flight.
        // Advertising on (the same-LAN lane): ONE [MulticastMdnsEndpoint] serving both halves over one
        // socket per family, because a responder must hold 5353 and a second socket on it would take a
        // hash-chosen share of the unicast replies to our own queries.
        val families =
            cfg.bindings
                .map { if (it.family == IpFamily.V4) AddressFamily.IPv4 else AddressFamily.IPv6 }
                .distinct()
        @Suppress("UnseamedEntropy") val mdnsRandom = Random(cfg.seed xor MDNS_SEED_DERIVATION)
        val mdnsEndpoint =
            if (!cfg.advertiseMdns) {
                null
            } else {
                MulticastMdnsEndpoint(
                    scope = bg,
                    families = families,
                    bufferFactory = net,
                    random = mdnsRandom,
                    onResponse = { response ->
                        // Every responder decision, answers AND typed silences, in the peer's own log. The
                        // silences matter as much: on a shared group most traffic is somebody else's, and a
                        // lane that saw only "answered" could not tell "nobody asked" from "we were mute".
                        when (response) {
                            is MdnsResponse.Answer -> {
                                println("[harness] mdns answered ${response.names.joinToString(",") { it.value }} (${response.destination})")
                                mdnsAnswered.complete(Unit)
                            }
                            is MdnsResponse.Silent -> println("[harness] mdns silent: ${response.reason}")
                        }
                    },
                )
            }
        val mdnsResolver: MdnsResolver =
            (mdnsEndpoint ?: MulticastMdnsResolver(families = families, bufferFactory = net))
                .logged(onResolved = { mdnsResolved.complete(Unit) })
        val mdnsAdvertising =
            if (mdnsEndpoint == null) MdnsAdvertisePolicy.Disabled else MdnsAdvertisePolicy.Advertise(mdnsEndpoint)

        // ── s11 (issue #102): the automatic-restart lane's two halves ────────────────────────────────
        // Built ONLY for that lane, so every other lane's behaviour is byte-identical to what it has
        // always been — an automatic restart is a renegotiation the app must carry, and turning it on
        // where no phase expects it would be a silent behaviour change, not a test improvement.
        val automaticRestart = cfg.iceRestart is IceRestartPhase.Automatic
        val networkMonitor =
            if (!automaticRestart) {
                null
            } else {
                // The PRODUCTION monitor, not a double. On Linux native that is socket's AF_NETLINK
                // monitor for reactivity plus our getifaddrs(3) enumeration — the exact composition a
                // consumer gets from systemNetworkMonitor(), which is what makes this lane a proof of
                // anything. A platform that cannot watch says so in the type, and we refuse rather than
                // run a lane that would pass by never restarting.
                when (val support = systemNetworkMonitor()) {
                    is NetworkMonitorSupport.Available -> support.monitor
                    is NetworkMonitorSupport.Unavailable ->
                        error("s11 needs a working NetworkMonitor and this platform has none: ${support.reason}")
                }
            }
        networkMonitor?.let { println("[harness] s11: automatic restart armed on the production monitor (detection=${it.detection})") }
        val iceRestartPolicy =
            networkMonitor?.let { IceRestartPolicy.OnNetworkChange(it) } ?: IceRestartPolicy.Manual

        // Which ICE generation the next gather belongs to. The stack re-invokes this policy once per
        // RFC 8445 §9 restart (s8), and the OUTGOING generation's sockets deliberately stay bound until the
        // new one nominates — that is the continuity guarantee — so re-gathering onto the same pinned port
        // would be asking the kernel to re-bind an address that is still open. A real stack takes a fresh
        // ephemeral port per generation; the harness pins its ports so the NAT rules can name them, so it
        // STEPS them instead: generation g binds localPort + g*stride, keeping every lane's first
        // generation byte-identical to what it has always used and every later one readable in a pcap.
        var iceGeneration = 0
        val gathering =
            IceGatheringPolicy { driver ->
                val portStep = iceGeneration++ * GENERATION_PORT_STRIDE
                // One host(+srflx)+relay per configured family. A dual-stack lane advertises BOTH v4 and v6
                // candidates, exercising the RFC 6724 candidate-priority ordering (webrtc-ice, PR #37); a
                // single-stack lane advertises exactly one. Real WebRTC stacks (pion, the browsers) gather
                // per family by enumerating interfaces — our explicit-bind peer mirrors that by looping the
                // injected per-family [FamilyBinding]s, each with its own coturn address for that family.
                // On the interface-swap lane the configured primary address may no longer EXIST — the
                // harness has deleted it, which is the network event the lane is built around — so
                // gathering consults the live interface table and binds whichever address this host
                // currently holds. That is what pion and the browsers do anyway; the harness pins an
                // address only so the NAT rules can name it. Off this lane the table is never read and
                // the configured bindings are used exactly as before.
                val live = networkMonitor?.interfaces()?.map { it.address.host }?.toSet()
                for (b in cfg.bindingsPresentIn(live)) {
                    val stun = resolveAddress(b.stunHost, cfg.stunPort)
                    val turn = resolveAddress(b.turnHost, cfg.turnPort)
                    if (cfg.icePolicy != IcePolicy.RelayOnly) {
                        driver.gatherHost(b.localIp, cfg.localPort + portStep, stunServer = stun)
                    }
                    // Relay is always gathered — the fallback path, and the only path under relayOnly.
                    driver.gatherRelay(turn, cfg.turnUser, cfg.turnPass, b.localIp, cfg.relayPort + portStep)
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
                        // RFC 7675 consent timing rides the same injected seam production uses. Left at the
                        // RFC's own defaults unless a lane compresses them (s9 — issue #80): revocation
                        // takes 30 s at the defaults, and no lane used to hold a session open even that
                        // long, which is exactly how a consent bug shipped and stayed invisible.
                        iceConfig =
                            IceConfig(
                                bufferFactory = net,
                                consentInterval = cfg.consentInterval,
                                consentTimeout = cfg.consentTimeout,
                            ),
                        // Resolve a peer's `<uuid>.local` host candidate (RFC 8828) over real multicast. Only
                        // fires when a `.local` candidate actually arrives (the same-LAN mDNS lane, where the
                        // browser advertises obfuscated hosts and shares our link); on the NAT'd lanes no
                        // `.local` is ever offered, so this stays dormant. Query only the lane's families.
                        mdnsResolver = mdnsResolver,
                        // …and, on that same lane, publish OUR host candidates as `.local` names too, so the
                        // browser has to resolve one of ours (issue #88). Disabled everywhere else.
                        mdnsAdvertising = mdnsAdvertising,
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
                        // s11 (issue #102) is the only lane that opts in, and it is the whole point of that
                        // lane: the PRODUCTION monitor — real netlink on Linux, through
                        // systemNetworkMonitor() — decides when to restart, with nothing in this peer
                        // calling restartIce(). Everywhere else the default `Manual` stands, which is also
                        // the library's default and the browser's behaviour.
                        iceRestartPolicy = iceRestartPolicy,
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

        // Every non-fatal thing the session decided, printed as it happens.
        //
        // These were being computed, typed, and dropped on the floor here — the peer collected
        // `connectionState` and nothing else — which is exactly the complaint `SessionDiagnostic` exists to
        // answer, one layer up. It cost a real diagnosis: a `relay-only` lane failed with
        // `AllPairsFailed(pairsTried=2)` and a peer log that said nothing more, and the only way to see what
        // had happened was to read the coturn pcap out of the diag bundle packet by packet. The pcap showed
        // the answerer receiving six relayed connectivity checks and answering none of them — but *why* it
        // stopped answering is precisely a [SessionDiagnostic], and there was no collector.
        //
        // `TransmitFailed` is the one that would have settled it (webrtc#143): a refused send used to escape
        // the driver's output pump silently, abandoning the rest of the batch. Now it reports, and this is
        // the surface that makes it visible in an L2 lane rather than only in a unit test.
        //
        // Timestamped from the same `t0` as the state trace so the two can be read against each other, and
        // against pcap timestamps, without arithmetic.
        bg.launch {
            pc.diagnostics.collect { d -> println("[harness] diag +${clock() - t0}  $d") }
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
        //
        // #88 added the mirror: with advertising on, the lane ALSO requires that our responder answered a
        // foreign peer's query for one of the names we minted. Same reasoning, opposite direction — and it
        // is the only observation that separates "the browser resolved our name" from "the browser ignored
        // our name and reached us peer-reflexively anyway", which is what happens if the responder is mute.
        val mdnsGate: suspend () -> Boolean = {
            when {
                cfg.requireMdns && withTimeoutOrNull(MDNS_RESOLVE_WAIT) { mdnsResolved.await() } == null -> {
                    println("[harness] mdns REQUIRED but no browser .local resolved within $MDNS_RESOLVE_WAIT")
                    false
                }
                cfg.requireMdnsAnswered && withTimeoutOrNull(MDNS_RESOLVE_WAIT) { mdnsAnswered.await() } == null -> {
                    println("[harness] mdns ANSWER REQUIRED but nobody asked for one of our .local names within $MDNS_RESOLVE_WAIT")
                    false
                }
                else -> true
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

    // One PUT socket, single-consumer: the offer first (round 0), then trickled candidates in order.
    val outbox = Channel<OutboundRecord>(Channel.UNLIMITED)
    outbox.trySend(OutboundRecord(Slot.Offer, RecordId(INITIAL_ROUND), offer))
    bg.launch { for (r in outbox) sigOut.put(r.slot, r.recordId, r.payload) }

    // The public address s8 requires this peer to be reachable at once the harness has moved it (null on
    // every lane that names no carrier — a genuine absence, not a disabled flag). It can only ever be
    // learned by a generation gathered AFTER the switch, which is what makes seeing it a proof.
    val expectedCarrier =
        when (val restart = cfg.iceRestart) {
            IceRestartPhase.Off, IceRestartPhase.AnyNewPath -> null
            is IceRestartPhase.ExpectCarrier -> restart.carrierIp
            // s10 moves us onto the same carrier; only the initiator of the restart differs, so the
            // re-gathered generation has to reach exactly the same public address to prove it followed.
            is IceRestartPhase.ForeignInitiated -> restart.carrierIp
            // s11 lands on the same carrier as s8; what differs is who noticed it had to.
            is IceRestartPhase.Automatic -> restart.carrierIp
        }
    val publicAddressSeen = CompletableDeferred<Unit>()

    bg.launch {
        var i = 0
        pc.localIceCandidates.collect {
            forensics.recordCandidate(Origin.Local, CandidateLine(it))
            if (expectedCarrier != null && connectionAddressOf(it) == expectedCarrier) publicAddressSeen.complete(Unit)
            outbox.trySend(OutboundRecord(Slot.OffererCandidate, RecordId(i++), it))
        }
    }

    // Completed by the poll loop below the moment the ORCHESTRATOR reports it has moved this peer onto its
    // second carrier (s8). The harness writes that record into the same mailbox the peers already share,
    // so the switch is an observed event on both sides instead of a sleep either would have to guess at.
    // Left uncompleted — and never awaited — on every lane that does not run s8.
    val carrierSwitched = CompletableDeferred<Unit>()

    // s8 property (4): what the PEER's own answers say it did with its ICE generation. Captured here, where
    // each round's SDP is applied, because by the time the phase runs the descriptions have been consumed
    // into connection state that no longer distinguishes "the peer restarted" from "a pair moved".
    // Uncompleted — and never awaited — on every lane that does not run s8.
    val initialAnswerCredentials = CompletableDeferred<RoundCredentials>()
    val restartAnswerCredentials = CompletableDeferred<RoundCredentials>()

    // s10 (issue #87), the mirror of the above for a restart the PEER originates: what its own re-offer
    // carried, and what OUR answer to it carried. The second is the direct evidence that our detection rule
    // fired — a stack that had not recognised the offer as a restart answers on the credentials it already
    // had — and it is observable in nothing else this peer publishes. Our round-0 offer is the baseline
    // both are judged against, so it is read here, once, from the offer we just built.
    val ourInitialCredentials = credentialsOf(offer)
    val peerReofferCredentials = CompletableDeferred<RoundCredentials>()
    val ourReanswerCredentials = CompletableDeferred<RoundCredentials>()

    // One poll socket, single-consumer: each round's answer, then the answerer's trickled candidates.
    val trickle = TrickleBuffer()
    bg.launch {
        var answers = 0
        var peerRounds = 0
        var seen = 0
        while (isActive) {
            // The answer to round `answers`. A restart lane signals TWO rounds (cfg.negotiationRounds):
            // round 0 negotiates the session, round 1 is the re-answer to s8's ICE-restart offer. Once
            // every round this run can have has been answered we stop asking — which on a single-round
            // lane leaves exactly the one-shot poll sequence this loop has always had.
            if (answers < cfg.negotiationRounds) {
                val a = sigIn.poll(Slot.Answer, RecordId(answers))
                if (a.isNotEmpty()) {
                    forensics.recordSdp(Origin.Remote, Sdp(a.first()))
                    // The peer's ceiling is read off its FIRST answer only: a later round renegotiates ICE,
                    // not the SCTP association s1 already sized itself against.
                    if (answers == INITIAL_ROUND) remoteMaxMessageSize.complete(maxMessageSizeOf(a.first()))
                    when (answers) {
                        INITIAL_ROUND -> initialAnswerCredentials.complete(credentialsOf(a.first()))
                        RESTART_ROUND -> restartAnswerCredentials.complete(credentialsOf(a.first()))
                    }
                    pc.setRemoteDescription(SdpType.Answer, a.first())
                    // s8's restart round renames the peer's generation, so anything trickled in the window
                    // before this answer landed belongs to the new one — see [TrickleBuffer].
                    reattribute(pc, trickle.drain())
                    answers++
                }
            }
            // s10 — an offer the PEER originated, on its own slots. Applied and answered from THIS loop,
            // the single consumer of this socket, for the same reason the answerer answers a later round
            // from its one loop. It is polled BEFORE the peer's candidates on purpose: a trickled candidate
            // carries no ufrag (RFC 8838 §3.1), so the round that renames the peer's generation has to be
            // applied before the candidates belonging to it, and in-order signaling is what makes that hold.
            if (peerRounds < cfg.peerNegotiationRounds) {
                val o = sigIn.poll(Slot.PeerOffer, RecordId(peerRounds))
                if (o.isNotEmpty()) {
                    forensics.recordSdp(Origin.Remote, Sdp(o.first()))
                    peerReofferCredentials.complete(credentialsOf(o.first()))
                    // The role this peer has never played in the harness: answerer. JSEP allows it from
                    // `stable`, and a restart is a renegotiation of the existing session — so this is the
                    // same three calls the answerer makes, in the direction we have never made them.
                    pc.setRemoteDescription(SdpType.Offer, o.first())
                    val reanswer = pc.createAnswer()
                    forensics.recordSdp(Origin.Local, Sdp(reanswer))
                    pc.setLocalDescription(SdpType.Answer, reanswer)
                    ourReanswerCredentials.complete(credentialsOf(reanswer))
                    outbox.trySend(OutboundRecord(Slot.PeerAnswer, RecordId(peerRounds), reanswer))
                    println("[harness] answered the peer's restart offer (round $peerRounds) — the peer restarted ICE")
                    // The peer's own restart offer renamed ITS generation, so its candidates read before
                    // this point were attributed to the generation it just superseded — see [TrickleBuffer].
                    reattribute(pc, trickle.drain())
                    peerRounds++
                }
            }
            if (answers > 0) {
                val cands = sigIn.poll(Slot.AnswererCandidate, RecordId(seen))
                seen += cands.size
                for (c in cands) {
                    forensics.recordCandidate(Origin.Remote, CandidateLine(c))
                    trickle.read(CandidateLine(c))
                    pc.addIceCandidate(c)
                }
            }
            // The orchestrator's carrier-switch record — polled here, on the ONE consumer of this socket,
            // rather than from the phase itself (a second consumer would race this loop's receive()).
            if (cfg.iceRestart != IceRestartPhase.Off &&
                !carrierSwitched.isCompleted &&
                sigIn.poll(Slot.CarrierSwitch, RecordId(0)).isNotEmpty()
            ) {
                carrierSwitched.complete(Unit)
            }
            delay(POLL_INTERVAL)
        }
    }

    // What s8 needs that only this role can provide: the harness's carrier-switch cue, and a SECOND
    // offer/answer round. Both ride the outbox/poll pair already open here, so the single-consumer
    // discipline of the two signaling sockets is untouched and s8 stays free of signaling machinery.
    val restartSignaling =
        object : RestartSignaling {
            override suspend fun awaitCarrierSwitch(): Boolean =
                withTimeoutOrNull(CARRIER_SWITCH_WAIT) { carrierSwitched.await() } != null

            override suspend fun reoffer() {
                val restartOffer = pc.createOffer()
                forensics.recordSdp(Origin.Local, Sdp(restartOffer))
                pc.setLocalDescription(SdpType.Offer, restartOffer)
                outbox.trySend(OutboundRecord(Slot.Offer, RecordId(RESTART_ROUND), restartOffer))
            }

            override suspend fun awaitCarrierPublicAddress(): Boolean =
                withTimeoutOrNull(PUBLIC_ADDRESS_WAIT) { publicAddressSeen.await() } != null

            override suspend fun awaitPeerReanswer(): ReanswerVerdict? =
                withTimeoutOrNull(REANSWER_WAIT) {
                    judgeReanswer(initialAnswerCredentials.await(), restartAnswerCredentials.await())
                }

            override suspend fun cuePeerRestart() {
                outbox.trySend(OutboundRecord(Slot.PeerRestart, RecordId(0), PEER_RESTART_CUE))
            }

            override suspend fun awaitPeerRestartRound(): ForeignRestartEvidence? =
                withTimeoutOrNull(PEER_REOFFER_WAIT) {
                    ForeignRestartEvidence(
                        // Both of the peer's descriptions, so "did it restart" is answered by the peer's own
                        // SDP rather than inferred from a pair that moved…
                        peerReoffer = judgeReanswer(initialAnswerCredentials.await(), peerReofferCredentials.await()),
                        // …and both of ours, so "did WE detect it" is answered by the description our JSEP
                        // produced in response, which is the property this whole lane exists for.
                        ourAnswer = judgeReanswer(ourInitialCredentials, ourReanswerCredentials.await()),
                    )
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
            runSemanticsPhases(bg, pc, ctl, reflector, restartSignaling, cfg, clock, remoteMaxMessageSize.await())
        }
    if (report == null) {
        println("[harness] semantics: TIMEOUT — the phase sequence did not finish within ${cfg.semanticsTimeout}")
        println("[harness] semantics-summary: total=0 passed=0 failed=1 failed-phases=[timeout]")
        return !cfg.semanticsRequired
    }

    // s6/close — the DONE handshake, then a graceful ASSOCIATION shutdown (decision D1a): the end of the
    // whole session, which is why it lives here rather than in the phase list and why it is necessarily
    // last. Closing ONE channel of many (RFC 8831 §6.7 stream reset) is a separate property with its own
    // mid-session phase, `s7`, which has already run by the time we get here.
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

/**
 * The **connection address** of a `candidate:` line (RFC 8839 §5.1 field 5, 1-based) — the address a peer
 * sends to — or null when the line is too short to have one. Deliberately not the `raddr`: our reflexive
 * candidate's related address is the LAN address the route change never touched, so matching on it would
 * declare the carrier switch proven before it had happened.
 */
private fun connectionAddressOf(candidateLine: String): String? = candidateLine.split(' ').getOrNull(4)

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
        val o = sigIn.poll(Slot.Offer, RecordId(INITIAL_ROUND))
        if (o.isNotEmpty()) offer = o.first() else delay(POLL_INTERVAL)
    }
    val outbox = Channel<OutboundRecord>(Channel.UNLIMITED)
    bg.launch { for (r in outbox) sigOut.put(r.slot, r.recordId, r.payload) }
    answerRound(pc, forensics, outbox, INITIAL_ROUND, offer)
    bg.launch {
        var i = 0
        pc.localIceCandidates.collect {
            forensics.recordCandidate(Origin.Local, CandidateLine(it))
            outbox.trySend(OutboundRecord(Slot.AnswererCandidate, RecordId(i++), it))
        }
    }

    // The offer poll above is done, so this launched loop is the only consumer of sigIn (no receive race)
    // — which is also why any LATER round is answered from inside it rather than from a loop of its own.
    val trickle = TrickleBuffer()
    bg.launch {
        var rounds = INITIAL_ROUND + 1
        var peerRounds = 0
        var cued = false
        var seen = 0
        while (isActive) {
            // s10 (issue #87) — the lifecycle word that asks US to restart. Read off the mailbox this loop
            // is already polling, which is exactly how `DONE` is read off the control channel: the reflector
            // acts on a lifecycle word without learning why one was sent, so it stays scenario-agnostic and a
            // lane that never writes the slot never reaches this code (cfg.peerNegotiationRounds is 0 there).
            if (cfg.peerNegotiationRounds > 0 && !cued && sigIn.poll(Slot.PeerRestart, RecordId(0)).isNotEmpty()) {
                cued = true
                originateRestart(pc, forensics, outbox, peerRounds)
            }
            // …and the offerer's answer to it, which is what actually tells our agent the peer's new
            // credentials. Without applying it our checklist would keep authenticating against the
            // generation the restart superseded.
            if (cued && peerRounds < cfg.peerNegotiationRounds) {
                val a = sigIn.poll(Slot.PeerAnswer, RecordId(peerRounds))
                if (a.isNotEmpty()) {
                    forensics.recordSdp(Origin.Remote, Sdp(a.first()))
                    pc.setRemoteDescription(SdpType.Answer, a.first())
                    println("[harness] answerer: the peer answered our restart offer (round $peerRounds)")
                    // This answer names the peer's new generation, so its candidates read before it landed
                    // were attributed to the one it superseded — see [TrickleBuffer].
                    reattribute(pc, trickle.drain())
                    peerRounds++
                }
            }
            // A further offer means the peer restarted ICE (RFC 8445 §9, the offerer's s8): re-answer it
            // on the SAME session — the association and every open channel are untouched by a restart.
            // Only a lane that can have a second round ever asks for one (cfg.negotiationRounds).
            if (rounds < cfg.negotiationRounds) {
                val o = sigIn.poll(Slot.Offer, RecordId(rounds))
                if (o.isNotEmpty()) {
                    answerRound(pc, forensics, outbox, rounds, o.first())
                    // The peer's restart offer renamed its generation — see [TrickleBuffer].
                    reattribute(pc, trickle.drain())
                    rounds++
                }
            }
            val cands = sigIn.poll(Slot.OffererCandidate, RecordId(seen))
            seen += cands.size
            for (c in cands) {
                forensics.recordCandidate(Origin.Remote, CandidateLine(c))
                trickle.read(CandidateLine(c))
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
 * Apply one round's [offer] and publish the answer under the SAME record id, so both peers' rounds line up
 * in the mailbox. Round 0 negotiates the session; a later round carries the offerer's ICE restart (RFC 8445
 * §9). It is deliberately the identical code either way — a restart is a renegotiation of an existing
 * session, not a second session, so the answerer has nothing to do beyond answering again.
 */
private suspend fun answerRound(
    pc: NativePeerConnection,
    forensics: Forensics,
    outbox: Channel<OutboundRecord>,
    round: Int,
    offer: String,
) {
    forensics.recordSdp(Origin.Remote, Sdp(offer))
    pc.setRemoteDescription(SdpType.Offer, offer)
    val answer = pc.createAnswer()
    forensics.recordSdp(Origin.Local, Sdp(answer))
    pc.setLocalDescription(SdpType.Answer, answer)
    if (round != INITIAL_ROUND) println("[harness] answerer: re-answered round $round — the peer restarted ICE")
    outbox.trySend(OutboundRecord(Slot.Answer, RecordId(round), answer))
}

/**
 * s10 — restart ICE (RFC 8445 §9) and publish the resulting offer on the peer-originated slots, because the
 * offerer asked for a fresh generation with the [Slot.PeerRestart] lifecycle word.
 *
 * The three calls are the ones the OFFERER has always made; only the direction is new. `restartIce()`
 * records the intent and the next `createOffer()` carries it out, so the offer this publishes advertises a
 * generation the offerer has never seen — which is the whole of what the lane asks it to detect.
 */
private suspend fun originateRestart(
    pc: NativePeerConnection,
    forensics: Forensics,
    outbox: Channel<OutboundRecord>,
    round: Int,
) {
    pc.restartIce()
    val offer = pc.createOffer()
    forensics.recordSdp(Origin.Local, Sdp(offer))
    pc.setLocalDescription(SdpType.Offer, offer)
    outbox.trySend(OutboundRecord(Slot.PeerOffer, RecordId(round), offer))
    // The token every reflector family prints and `run-interop.sh` greps on the foreign-restart lanes: this
    // peer's OWN report that it restarted, the half of the proof only the restarting side can give.
    println("[harness] $PEER_RESTART_REPORT $round")
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

/**
 * The trickled candidates read since the last remote description was applied — and the reason they are kept.
 *
 * A trickled candidate carries no `ufrag` (RFC 8838 §3.1), so every peer attributes one to whatever
 * generation its **current** remote description names. Across a renegotiation that is a race nobody wins:
 * the description and the candidates of the generation it introduces travel as separate mailbox records, so
 * a candidate read in the window before the description is applied is attributed to the generation the
 * restart just superseded — and discarded when the new description replaces it. The new generation is then
 * left with an empty checklist, sends no connectivity checks, and *nothing in either peer's log says so*.
 *
 * Publishing in order does not fix it, which is what makes this worth a type rather than a comment: the
 * reader can still poll the description slot a moment before it lands and the candidate slot a moment
 * after. Sequencing the writer moves the window; it does not close it. So the fix is timing-independent
 * instead — a candidate read under the old description is RE-APPLIED once the new one arrives. The cost is
 * a duplicate add, which every stack ignores (ours dedupes remote candidates by address + type,
 * `IceAgent.onAddRemoteCandidate`).
 *
 * The window is **routine, not rare**: instrumented runs open it on every single one. What varies is only
 * whether *all* of a generation's candidates land inside it. Usually some arrive after the description and
 * ICE converges on those alone — which is how this silently lost candidates across fourteen green local
 * runs — and when none do, the peer is left with an empty checklist and the lane goes red (issue #95).
 *
 * This is what an application must do while its signalling cannot tag a candidate with the generation it
 * belongs to; the protocol-level fix is RFC 8838 §3.1's `ufrag` on the candidate line itself.
 */
internal class TrickleBuffer {
    private val sinceDescription = mutableListOf<CandidateLine>()

    /** Record [line] as having been read under the description in force at the time. */
    fun read(line: CandidateLine) {
        sinceDescription += line
    }

    /** Take the candidates that must be re-attributed to the generation a just-applied description named. */
    fun drain(): List<CandidateLine> = sinceDescription.toList().also { sinceDescription.clear() }
}

/**
 * Re-apply [buffered] to the generation the description just applied named. See [TrickleBuffer] for why
 * this exists; the log line is deliberately loud, because a run in which it re-applies anything is a run
 * that would previously have been a coin flip.
 */
private suspend fun reattribute(
    pc: NativePeerConnection,
    buffered: List<CandidateLine>,
) {
    if (buffered.isEmpty()) return
    println("[harness] re-applying ${buffered.size} candidate(s) recorded under the previous description to the generation the new one named")
    for (line in buffered) pc.addIceCandidate(line.text)
}

/** One observed [PeerConnectionState] transition and [at] how long after the session started it happened. */
private data class StateTransition(val at: Duration, val state: PeerConnectionState)

private val POLL_INTERVAL = 200.milliseconds

// Offer/answer ROUNDS are mailbox record ids, one per round, on the Offer and Answer slots alike: round 0
// is the initial negotiation every lane runs, round 1 the ICE-restart re-offer only an s8 lane signals.
// Naming them keeps the two slots' ids meaning the same thing on both sides of the exchange.
private const val INITIAL_ROUND = 0
private const val RESTART_ROUND = 1

// How far the pinned ICE ports step per ICE generation (host at localPort+g*stride, relay one above it).
// Two, because a generation binds exactly those two sockets per family.
private const val GENERATION_PORT_STRIDE = 2

// How long s8 waits for the orchestrator's carrier-switch record before giving up on the switch. A
// watchdog on an observable event (the record's arrival in the mailbox), not a budget for the switch to
// take: `docker compose exec ip route replace` is instant, and the phase's own PHASE_TIMEOUT bounds it
// again from outside. Generous because it also covers the harness's log-polling detection of our cue.
private val CARRIER_SWITCH_WAIT = 30.seconds

// How long s8 waits for the restarted generation to learn our new public address from coturn. One STUN
// round trip on a healthy path; the window covers a re-gather that has to retransmit its Binding request.
private val PUBLIC_ADDRESS_WAIT = 15.seconds

// How long s8 waits for the PEER's answer to the restart round to land in the mailbox and be applied.
// Shorter than the phase's own reconvergence wait, deliberately: it is a signaling round trip with no
// gathering in it, and a peer that has not re-answered by now will not reconverge either — failing here
// first is what turns the useless "never reconverged" into "the peer never re-answered".
private val REANSWER_WAIT = 20.seconds

// How long s10 waits for the PEER's own restart offer to land after we published the lifecycle word, and
// for our answer to it to be produced. Longer than [REANSWER_WAIT] because the peer has more to do than
// answer: it has to notice the word on its poll cadence, ask its stack for a fresh generation, and build an
// offer from it. Still a watchdog on an observable event — the offer's arrival in the mailbox.
private val PEER_REOFFER_WAIT = 30.seconds

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

// The mDNS name minter rides the SAME logged cfg.seed as everything else (a fixed derivation), so the
// `<uuid>.local` a failed run published is reconstructible from the artifact — a name that appeared in a
// pcap can be tied back to the peer that minted it. Directive #2: entropy is a seam, never ambient.
private const val MDNS_SEED_DERIVATION = 0x8888L

// How long the answerer watches for the offerer's graceful association SHUTDOWN to land (s6/close). A
// watchdog on the observable terminal state, not a sleep: it ends the moment the association reports
// Closed. Comfortably longer than the offerer's own bounded close, so a clean close is never missed.
private val CLOSE_OBSERVE_WAIT = 15.seconds

@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.stun.IpAddress
import com.ditchoom.webrtc.stun.StunDecodeResult
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.TransportAddress
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Binds an [AddressedDatagramChannel] at a local [SocketAddress] — the one network seam the
 * [IceTransport] driver rides. Production supplies a real-UDP binder (socket-udp `UdpSocket.bind`, at
 * the platform edge — no wasm, ARCHITECTURE §1.1); tests supply the in-memory vnet. Both honor the same
 * buffer-flow contract, so the driver above is identical on either (DESIGN §7).
 *
 * **Addressed, in the type, since buffer 6.23.0.** ICE is the addressed case by nature — one bound
 * socket serving every candidate pair — and the split makes that structural rather than documented:
 * `send` requires its destination, and `localAddress` is non-null because a bound socket has one, so
 * candidate gathering reads the base with no unwrap. The prose here used to say "unconnected"; the
 * type says it now.
 */
public fun interface DatagramBinder {
    /** Bind and return a channel receiving datagrams sent toward [address]. */
    public suspend fun bind(address: SocketAddress): AddressedDatagramChannel
}

/**
 * The point-to-point application-data seam over the ICE-selected pair — the RFC 7983 non-STUN half of
 * the nominated socket. [send] rides the [IcePath]'s `local.base → remote.address`; [receive]
 * yields the demuxed non-STUN datagrams (DTLS/SCTP). This is **the boundary where DTLS slots in**:
 * it is deliberately shaped identically to `webrtc-sctp`'s `SctpDatagramTransport` so the SCTP stack (or
 * a real DTLS record layer wrapping it) drops in as a swap, without `webrtc-ice` depending on `webrtc-sctp`.
 */
public interface IceDataTransport {
    /** Send one packet to the peer over the selected pair. Ownership of [packet] is not transferred. */
    public suspend fun send(packet: ReadBuffer)

    /** Receive the next non-STUN packet, or [IceDataReadResult.Closed] once the transport has closed. */
    public suspend fun receive(): IceDataReadResult

    /** Tear the app-data seam down; a pending/next [receive] answers [IceDataReadResult.Closed]. Idempotent. */
    public fun close()
}

/**
 * The result of one [IceDataTransport.receive] — sealed rather than a nullable [ReadBuffer], mirroring
 * `DatagramReadResult` one layer down. "Closed" is a *state* of the seam, not an absent packet, and the
 * distinction is load-bearing: a caller that elvis-ed the null could not tell a closed transport from one
 * that merely had nothing yet, and the DTLS forwarder's `break` on it is what ends a session.
 */
public sealed interface IceDataReadResult {
    /** A packet arrived. Ownership of [packet] transfers to the caller. */
    public data class Received(
        public val packet: ReadBuffer,
    ) : IceDataReadResult

    /** The seam is closed and will deliver nothing further. Terminal. */
    public data object Closed : IceDataReadResult
}

/**
 * The result of [IceAgentDriver.gatherRelay] — sealed rather than a nullable [IceCandidate], so the
 * reason a relay was not gathered survives the call instead of being flattened into "no candidate".
 *
 * [Unavailable] wraps [TurnAllocationResult.Unavailable] rather than restating its cases: the reasons a
 * relay candidate is missing are exactly the reasons the allocation failed, and duplicating them here
 * would create two hierarchies to keep in step.
 */
public sealed interface RelayGatheringResult {
    /** The relay allocated and [candidate] is bound, forwarding, and already emitted on the gather flow. */
    public data class Gathered(
        public val candidate: IceCandidate,
    ) : RelayGatheringResult

    /** No relay candidate — [cause] is the allocation's own typed reason. */
    public data class Unavailable(
        public val cause: TurnAllocationResult.Unavailable,
    ) : RelayGatheringResult
}

/**
 * A local candidate as it left the gathering seam, with the **ufrag of the ICE generation it landed in**
 * (RFC 8838 §3.1). Signaling a candidate without saying which generation gathered it is what makes a
 * restart's candidates ambiguous on the wire; carrying the two together makes the tag impossible to
 * forget and impossible to take from the wrong generation.
 *
 * The ufrag is a plain [Ufrag] rather than a [CandidateGeneration], because a *local* candidate is never
 * untagged from the driver's point of view: the agent always knows which generation it is in. Whether the
 * session layer then stamps it on the wire is a signaling policy, decided above.
 */
public data class GatheredCandidate(
    public val candidate: IceCandidate,
    public val ufrag: Ufrag,
)

/**
 * The production **driver** the sans-io [IceAgent] lacks by design (ARCHITECTURE §5.1: cores own truth, drivers
 * own I/O). `PeerConnection` and a future media layer compose the *same* transport over the selected
 * pair rather than re-deriving it — which is why this is one class and not a pattern.
 *
 * One merged inbox carries datagrams (from per-socket forwarder loops) and externally posted [IceEvent]s;
 * a single loop pumps `handle(event, now)`, so every `handle` call is serialized and [IceAgent.nextDeadline]
 * is realized as a `select` against virtual time. Because all intake flows through the inbox, trickle
 * (RFC 8838) and restart just work: a candidate gathered or signaled later is one more posted event.
 * Gathering rides the same [gatherServerReflexive]/[TurnAllocation] drivers production uses over real UDP;
 * the [DatagramBinder] is the only substitution between a vnet test and a real socket.
 *
 * Entropy is one injected [random] (directive #2): two independent child streams are derived at
 * construction — one for the agent (tie-breaker/ufrag/pwd/foundations), one for gathering (STUN
 * transaction ids) — so the drive loop and the gathering coroutines never share a mutable `Random`.
 */
public class IceAgentDriver(
    role: IceRole,
    random: Random,
    private val binder: DatagramBinder,
    private val scope: CoroutineScope,
    private val clock: () -> Instant,
    private val config: IceConfig = IceConfig(),
) {
    // Derive two independent, deterministic streams from the single injected seam: the agent and the
    // gathering coroutines run concurrently, so they must not share one Random's mutable state.
    private val agentRandom = Random(random.nextLong())

    @Suppress("UnseamedEntropy") // derived from the injected [random]; not an ambient default
    private val gatheringRandom = Random(random.nextLong())

    // The sans-io agent this driver clocks — internal, never public: every `handle` call must go through
    // the single [driveLoop], so exposing the raw core would let a caller race it and corrupt checklist
    // state. Consumers use the re-exposed [state]/[path]/[localCandidates]/[localCredentials].
    internal val agent: IceAgent = IceAgent(role, agentRandom, config)

    /** This agent's local ICE credentials (ufrag/pwd) — signal them to the peer. */
    public val localCredentials: IceCredentials get() = agent.localCredentials

    private val inbox = Channel<Command>(Channel.UNLIMITED)
    private val channels = HashMap<TransportAddress, AddressedDatagramChannel>()

    // The sockets and candidates of the generation currently being gathered, and — across a restart —
    // those of the outgoing one, which stay BOUND until the new generation nominates (RFC 8445 §9). The
    // agent retains the old pair; the driver must retain the socket underneath it, or continuity would
    // be a promise made over a closed channel.
    private var gathering = GatheredGeneration()
    private var retiring: RetiringGeneration = RetiringGeneration.None

    // Per-family gather ordinal → the [CandidatePreferencePolicy] interfaceIndex, so a multi-homed host's
    // same-family candidates get distinct local preferences (RFC 8445 §5.1.2.2 "SHOULD be unique"). Gathering
    // is serialized by the caller, so this needs no synchronization. (No NetworkMonitor interface identity
    // yet — a documented follow-up the policy seam already fits.)
    private val interfaceIndexByFamily = HashMap<UByte, Int>()

    private fun nextInterfaceIndex(ip: IpAddress): Int {
        val index = interfaceIndexByFamily.getOrElse(ip.family) { 0 }
        interfaceIndexByFamily[ip.family] = index + 1
        return index
    }

    // App-data (non-STUN) demux (RFC 7983): datagrams that are not STUN connectivity checks are DTLS/SCTP
    // and are routed here rather than into the agent, which ignores them. This is the seam SCTP rides.
    private val appInbound = Channel<ReadBuffer>(Channel.UNLIMITED)

    private val _state = MutableStateFlow<IceConnectionState>(IceConnectionState.New)

    /** The ICE connection state (RFC 8445 §6.1.2.6), for the session layer to await/observe. */
    public val state: StateFlow<IceConnectionState> get() = _state

    private val _path = MutableStateFlow<IcePath>(IcePath.Unnominated)

    /**
     * Where application traffic rides (RFC 8445 §9 — see [IcePath]). A [StateFlow], not a snapshot, so
     * the session layer can observe a *mid-session* pair change — the thing a plain `selectedPair`
     * getter could never report, and the reason a restart used to be invisible above ICE.
     */
    public val path: StateFlow<IcePath> get() = _path

    /** A snapshot of the local candidates gathered in the current ICE generation. */
    public val localCandidates: List<IceCandidate> get() = gathering.candidates.toList()

    /**
     * Whether the pair currently carrying data still rides one of [interfaces] — the question an automatic
     * ICE-restart policy asks when the interface set changes (RFC 8445 §9).
     *
     * It lives here because this is the one place both address vocabularies are in scope: buffer-flow's
     * [SocketAddress] on the [NetworkMonitor] side, webrtc-stun's `TransportAddress` on the candidate side.
     * A session-layer implementation would end up comparing *rendered* addresses, and a v6 literal does not
     * render identically on the two sides (`SocketAddress.toString` brackets it; the candidate does not).
     *
     * True when nothing is nominated or a restart is already in flight — in neither case is there a live
     * path to lose, so neither is a reason to restart.
     */
    public fun pathRidesOneOf(interfaces: List<LocalInterface>): Boolean {
        val local =
            when (val current = _path.value) {
                IcePath.Unnominated -> return true
                is IcePath.Restarting -> return true
                is IcePath.Nominated -> current.pair.local
            }
        // Compare the IP only. A [NetworkMonitor] enumerates *interfaces*; it has no idea which ephemeral
        // port ICE happened to bind on one, so its addresses carry no meaningful port. Comparing whole
        // TransportAddresses (whose equality includes the port) would never match, `pathRidesOneOf` would
        // answer false for every change, and the narrow policy would degrade into exactly the restart-on-
        // any-change churn it exists to prevent — silently, since a false answer looks like a real finding.
        val socketIp = localSocketOf(local).ip
        return interfaces.any { it.address.toTransportAddressOrNull()?.ip == socketIp }
    }

    /**
     * The address of the **local socket** a candidate actually occupies — which is not always its `base`.
     * A relayed candidate's base is its address *on the TURN server*, so it never matches a local
     * interface; the socket we hold is its `relatedAddress`. Host, server-reflexive and peer-reflexive
     * candidates all base on the local socket already.
     */
    private fun localSocketOf(candidate: IceCandidate): TransportAddress =
        when (candidate) {
            is IceCandidate.Relayed -> candidate.relatedAddress
            is IceCandidate.Host, is IceCandidate.ServerReflexive, is IceCandidate.PeerReflexive -> candidate.base
        }

    private val gathered = Channel<GatheredCandidate>(Channel.UNLIMITED)

    private val discarded =
        Channel<IceOutput.RemoteCandidateDiscarded>(DISCARD_DIAGNOSTIC_BUFFER, BufferOverflow.DROP_OLDEST)

    private val transmitFailures =
        Channel<IceTransmitFailure>(TRANSMIT_FAILURE_DIAGNOSTIC_BUFFER, BufferOverflow.DROP_OLDEST)

    private val permissionRefusals =
        Channel<TurnPermissionRefusal>(PERMISSION_REFUSAL_DIAGNOSTIC_BUFFER, BufferOverflow.DROP_OLDEST)

    /**
     * Every local candidate as it is gathered (host/srflx/relay) — the trickle (RFC 8838) source — paired
     * with the ufrag of the ICE generation it actually landed in, so the session layer can stamp RFC 8838
     * §3.1's generation tag on the line it signals.
     *
     * The pairing is made **inside the drive loop**, at the instant the agent applies the candidate, and
     * that is load-bearing: gathering runs in its own coroutines, so a candidate gathered just before a
     * restart is applied to the new generation while a `localCredentials` read from the gathering side
     * would still have returned the old ufrag. Tagging a candidate with a generation it is not in is the
     * exact defect the tag exists to prevent, so the tag is taken where the answer cannot be stale.
     */
    public val localCandidateGathered: Flow<GatheredCandidate> get() = gathered.receiveAsFlow()

    /**
     * Remote candidates the core deliberately refused (RFC 8838 §3.1) — the diagnostics half of
     * [IceOutput.RemoteCandidateDiscarded], which the drive loop otherwise has nothing to do with.
     *
     * **Bounded and lossy, unlike [localCandidateGathered].** That channel is `UNLIMITED` because its
     * producer is our own gathering, which is finite per generation. This one's producer is the *peer*,
     * and a peer that trickles candidates for generations it never signals is either broken or hostile —
     * exactly the case [CandidateDiscardReason.UnappliedGenerationOverflow] already exists to bound.
     * An unbounded channel here would let that peer grow our heap through a diagnostic nobody is
     * required to collect, and a rendezvous channel would let it stall the drive loop. Dropping the
     * oldest is the only option that is neither.
     */
    public val remoteCandidateDiscarded: Flow<IceOutput.RemoteCandidateDiscarded> get() = discarded.receiveAsFlow()

    /**
     * A datagram the socket refused — connectivity checks, nomination, keep-alives, relayed data.
     *
     * **Non-fatal by construction, and that is the decision rather than a side effect.** ICE is built to
     * survive lost datagrams: a check that never leaves retransmits, and if the path really is dead the
     * establishment and RFC 7675 consent backstops reach a typed terminal on their own schedule. Treating
     * one refused `sendto` as fatal would throw away that tolerance and, worse, would abandon the rest of
     * the output batch it was in. So the transmit is dropped and reported, never raised.
     *
     * What this exists to make visible is the *silent* case. Without it, a socket refusing every send
     * looks exactly like a peer that stopped answering — the session fails with
     * [IceFailureReason.NoCandidatePairs] or `.ConsentExpired`, naming the symptom, while the cause was
     * local and known. A steady stream here alongside a healthy-looking checklist is the tell.
     *
     * **Bounded and lossy**, on the same reasoning as [remoteCandidateDiscarded]: a failing socket fails
     * at the connectivity-check rate, so an unbounded channel would grow the heap for a collector nobody
     * is obliged to attach, and a rendezvous channel would let the failure stall the drive loop that
     * reports it.
     */
    public val transmitFailed: Flow<IceTransmitFailure> get() = transmitFailures.receiveAsFlow()

    /**
     * CreatePermissions a TURN server refused, across **every** relay allocation this generation gathered
     * (see [TurnAllocation.permissionRefused]).
     *
     * Merged here rather than exposed per-allocation because the allocations are the driver's own — it
     * creates one per relay candidate inside [gatherRelay] and never hands them out — so this is the only
     * point at which a session layer could reach them. Each refusal names its own [TurnPermissionRefusal.relay],
     * which is what keeps a dual-stack session's two allocations tellable apart after the merge.
     *
     * **Bounded and lossy** on the same reasoning as [transmitFailed], with the same size.
     */
    public val relayPermissionRefused: Flow<TurnPermissionRefusal> get() = permissionRefusals.receiveAsFlow()

    /** Launch the serialized drive loop. Gather candidates and feed remote state after this. */
    public fun start() {
        scope.launch { driveLoop() }
    }

    /**
     * Gather a host candidate at [ip]:[port], and — if [stunServer] is given — a server-reflexive
     * candidate on the same socket (gathered *before* the forwarder starts, so it does not race the
     * checklist for `receive()`). Returns the host candidate; both are emitted on [localCandidateGathered].
     *
     * A [port] of **0 asks for an ephemeral port**, which is what a production gathering policy should do:
     * a pinned port cannot survive an ICE restart, because the outgoing generation's sockets stay bound
     * until the new one nominates and no OS will re-bind an address still in use. The candidate then names
     * the port the socket actually received — see [boundAddress].
     */
    public suspend fun gatherHost(
        ip: String,
        port: Int,
        stunServer: SocketAddress? = null,
    ): IceCandidate {
        val socketAddress = SocketAddress.ofLiteral(ip, port)
        val channel = binder.bind(socketAddress)
        channel.requireSendableWith(config.bufferFactory, WireBufferSeam.IceBufferFactory)
        val hostAddress = boundAddress(ip, channel).toTransportAddress()
        // Host + its server-reflexive share one interface index (same socket): family-preferred, tie-unique.
        val ifaceIndex = nextInterfaceIndex(hostAddress.ip)
        val hostPreference = CandidatePreferencePolicy.Default.localPreference(hostAddress.ip, ifaceIndex)
        val host = IceCandidate.host(hostAddress, localPreference = hostPreference)
        bind(host.base, channel)
        gather(host)

        if (stunServer != null) {
            when (val reflexive = gatherServerReflexive(channel, stunServer, gatheringRandom, bufferFactory = config.bufferFactory)) {
                is ServerReflexiveResult.Discovered ->
                    gather(
                        IceCandidate.ServerReflexive(
                            address = reflexive.address,
                            base = hostAddress,
                            component = ComponentId.Rtp,
                            transport = IceTransport.Udp,
                            foundation =
                                Foundation.of(
                                    CandidateType.ServerReflexive,
                                    hostAddress.ip(),
                                    stunServer.toTransportAddress().ip(),
                                    IceTransport.Udp,
                                ),
                            // srflx local preference derives from its base (the host socket), RFC 8445 §5.1.2.2.
                            priority = IceCandidate.computePriority(CandidateType.ServerReflexive, ComponentId.Rtp, hostPreference),
                            relatedAddress = hostAddress,
                        ),
                    )
                is ServerReflexiveResult.Unavailable -> Unit // no srflx on this socket; host/relay still stand
            }
        }
        forward(host.base, channel)
        return host
    }

    /**
     * Gather a relay candidate: bind a dedicated socket at [ip]:[port], allocate on [turnServer], and
     * present the allocation as the candidate's channel. A [port] of 0 asks for an ephemeral one, as in
     * [gatherHost].
     *
     * Answers a sealed [RelayGatheringResult] carrying [TurnAllocation.allocate]'s own cause, so
     * "your TURN credentials were rejected" reaches the caller as that rather than as a null indistinct
     * from a server that never answered. This is the failure mode the whole relay path is judged on: for
     * a peer behind a symmetric NAT there is no other candidate to fall back to.
     */
    public suspend fun gatherRelay(
        turnServer: SocketAddress,
        username: String,
        password: String,
        ip: String,
        port: Int,
    ): RelayGatheringResult {
        val socketAddress = SocketAddress.ofLiteral(ip, port)
        val underlying = binder.bind(socketAddress)
        // Checked on the UNDERLYING channel, not on the allocation that wraps it: the allocation's own
        // send path is this socket, and the check must run before `allocate()` — a TURN Allocate request
        // is itself a send, so a deferred check would report the misconfiguration as a TURN timeout.
        underlying.requireSendableWith(config.bufferFactory, WireBufferSeam.IceBufferFactory)
        // The `raddr` of a relay candidate IS this local base, so it takes the bound port too — otherwise
        // an ephemeral allocation publishes `raddr <ip> rport 0`, which is not a place anything lives.
        val baseAddress = boundAddress(ip, underlying)
        val allocation = TurnAllocation(underlying, turnServer, username, password, gatheringRandom, scope, config.bufferFactory)
        // Merge this allocation's refusals into the driver-wide diagnostic. Launched before `allocate()`
        // rather than after a successful one: the allocation is the only object that can report these, and
        // a subscription started later would miss the refusals a first relayed send provokes. Ends with
        // [scope], which is the generation's — a retired allocation's channel closes and the collect returns.
        scope.launch { allocation.permissionRefused.collect { permissionRefusals.trySend(it) } }
        val relayedSocket =
            when (val result = allocation.allocate()) {
                is TurnAllocationResult.Allocated -> result.relayed
                is TurnAllocationResult.Unavailable -> return RelayGatheringResult.Unavailable(result)
            }
        val relayedAddress = relayedSocket.toTransportAddress()
        // The relay binds its own socket → its own interface index; preference derives from the relayed base.
        val relayPreference =
            CandidatePreferencePolicy.Default.localPreference(relayedAddress.ip, nextInterfaceIndex(relayedAddress.ip))
        val relay =
            IceCandidate.Relayed(
                address = relayedAddress,
                component = ComponentId.Rtp,
                transport = IceTransport.Udp,
                foundation =
                    Foundation.of(
                        CandidateType.Relayed,
                        relayedAddress.ip(),
                        turnServer.toTransportAddress().ip(),
                        IceTransport.Udp,
                    ),
                priority = IceCandidate.computePriority(CandidateType.Relayed, ComponentId.Rtp, relayPreference),
                relatedAddress = baseAddress.toTransportAddress(),
            )
        bind(relay.base, allocation)
        forward(relay.base, allocation)
        gather(relay)
        return RelayGatheringResult.Gathered(relay)
    }

    /**
     * The address a freshly bound [channel] actually holds, as a candidate should advertise it: the caller's
     * own [ip] literal, at the port the socket **received**.
     *
     * The port has to come from the channel, because `bind(ip, 0)` means "give me an ephemeral port" — the
     * requested address then says `0`, and a candidate built from it invites the peer to send to port 0.
     * That is not a corner case: an ICE restart re-gathers while the outgoing generation's sockets are
     * still bound (that is the continuity guarantee), so a production policy has no fixed port to pin and
     * ephemeral is the normal case. Where the caller did pin a port, this is the value it pinned.
     *
     * The **host** deliberately does not come from the channel, even though it is right there. A platform
     * renders a bound address in its own dialect — `getifaddrs`/`InetAddress.getHostAddress` append a
     * `%scope` to a link-local v6 literal, which [toTransportAddress] would reject as malformed — whereas
     * [ip] is the literal the gathering policy chose and every candidate has always carried. One field
     * needed correcting; taking the other along for the ride would trade a real bug for a subtler one.
     */
    private fun boundAddress(
        ip: String,
        channel: AddressedDatagramChannel,
    ): SocketAddress = SocketAddress.ofLiteral(ip, channel.localAddress.port)

    /** Feed the peer's ICE credentials in (from the SDP offer/answer) — pairing can begin. */
    public fun setRemoteCredentials(credentials: IceCredentials) {
        post(IceEvent.SetRemoteCredentials(credentials))
    }

    /**
     * Feed a trickled remote candidate in (RFC 8838), for the ICE generation named by [generation]
     * (RFC 8838 §3.1). The default — untagged — is what a peer that carries no `ufrag` sends, and is
     * applied to whichever generation is current, exactly as before the tag existed.
     */
    public fun addRemoteCandidate(
        candidate: IceCandidate,
        generation: CandidateGeneration = CandidateGeneration.Untagged,
    ) {
        post(IceEvent.AddRemoteCandidate(candidate, generation))
    }

    /** Tear down the socket backing [candidate] (a link/interface going away — the candidate-flap seam). */
    public fun drop(candidate: IceCandidate) {
        channels.remove(candidate.base)?.close()
        gathering.forget(candidate)
        (retiring as? RetiringGeneration.Pending)?.generation?.forget(candidate)
    }

    /**
     * Begin an ICE restart (RFC 8445 §9), returning once the agent has actually applied it — so the
     * returned [IceCredentials] are the **new** generation's.
     *
     * The suspending form exists because [IceEvent.Restart] rides the same serialized inbox as every
     * other event: credentials read immediately after a bare [restart] are still the old ones, and an
     * offer built from them would advertise credentials the agent no longer honours. Re-gather **after**
     * this returns; the sockets of the outgoing generation stay bound until the new one nominates.
     */
    public suspend fun restartAndAwait(): IceCredentials {
        val applied = CompletableDeferred<IceCredentials>()
        inbox.trySend(Command.Restart(applied))
        return applied.await()
    }

    /**
     * Abandon the in-flight restart generation and restore the retained one — the ICE half of
     * `setLocalDescription(rollback)`. Returns once applied. A no-op when no restart is in flight.
     */
    public suspend fun rollbackRestart() {
        val applied = CompletableDeferred<IceCredentials>()
        inbox.trySend(Command.Rollback(applied))
        applied.await()
    }

    /**
     * Begin an ICE restart without waiting for it to be applied. Prefer [restartAndAwait] anywhere the
     * new credentials are about to be read or signaled.
     */
    public fun restart() {
        post(IceEvent.Restart)
    }

    /** Post a raw event into the serialized inbox (trickle/restart/signaling seam). */
    public fun post(event: IceEvent) {
        inbox.trySend(Command.Event(event))
    }

    /**
     * The application-data seam over the nominated pair (the composition point where DTLS sits). Start
     * the SCTP stack over this only after [state] reaches [IceConnectionState.Connected]/[Completed].
     */
    public fun appDataTransport(): IceDataTransport =
        object : IceDataTransport {
            override suspend fun send(packet: ReadBuffer) {
                // Exhaustive, no `else` and no elvis: each arm states a decision rather than falling out
                // of a null. `Restarting` deliberately keeps sending on the retained pair — that is the
                // RFC 8445 §9 continuity guarantee, and it is now written down instead of being a
                // side effect of a field nobody updated.
                val pair =
                    when (val current = _path.value) {
                        IcePath.Unnominated -> return // nothing nominated yet: DTLS/SCTP have not started
                        is IcePath.Nominated -> current.pair
                        is IcePath.Restarting -> current.previous
                    }
                // Deliberately *not* guarded like the check path above, and the asymmetry is the point.
                // [packet] is the caller's buffer (DTLS's record), so there is nothing of ours to leak
                // and no batch of ours to abandon — the two harms that made a raised send unacceptable in
                // `apply()`. What is left is a failed application write, which is exactly the caller's to
                // know: swallowing it here would tell DTLS its record went out when it did not, and a
                // retransmission policy built on that lie is worse than the throw. Socket-udp absorbs and
                // retries backpressure internally (DitchOoM/socket#278), so what reaches here is a real
                // failure, not routine flow control.
                channels[pair.local.base]?.send(packet, to = pair.remote.address.toSocketAddress())
            }

            override suspend fun receive(): IceDataReadResult {
                val packet = appInbound.receiveCatching().getOrNull()
                return if (packet != null) IceDataReadResult.Received(packet) else IceDataReadResult.Closed
            }

            override fun close() {
                appInbound.close()
            }
        }

    /** Tear the whole transport down: close every gathered socket and the app-data seam. Idempotent. */
    public fun close() {
        for (channel in channels.values) channel.close()
        channels.clear()
        appInbound.close()
        inbox.close()
        gathered.close()
    }

    private fun bind(
        base: TransportAddress,
        channel: AddressedDatagramChannel,
    ) {
        channels[base] = channel
        gathering.bases += base
    }

    // The candidate is published on [localCandidateGathered] by the drive loop, not here — see that
    // property for why the generation tag has to be taken where the agent applies the candidate.
    private fun gather(candidate: IceCandidate) {
        gathering.candidates += candidate
        post(IceEvent.AddLocalCandidate(candidate))
    }

    /**
     * Move the current generation's sockets into retirement — they stay bound and keep carrying data
     * until the new generation nominates. A restart *on top of* an in-flight restart discards the
     * intermediate generation immediately: it never nominated, so nothing rides it, and the original
     * retained generation is the one still carrying application data (matching [IceAgent]'s retention).
     */
    private fun beginRestartGeneration() {
        when (retiring) {
            RetiringGeneration.None -> retiring = RetiringGeneration.Pending(gathering)
            is RetiringGeneration.Pending -> closeAll(gathering)
        }
        gathering = GatheredGeneration()
    }

    /** The new generation nominated: retire every socket the outgoing one owned and nothing else. */
    private fun completeRestartGeneration() {
        val pending = (retiring as? RetiringGeneration.Pending)?.generation ?: return
        retiring = RetiringGeneration.None
        closeAll(pending, keep = gathering.bases)
    }

    /** Rollback: discard the generation that never converged and restore the one still carrying data. */
    private fun rollbackRestartGeneration() {
        val pending = (retiring as? RetiringGeneration.Pending)?.generation ?: return
        retiring = RetiringGeneration.None
        closeAll(gathering, keep = pending.bases)
        gathering = pending
    }

    private fun closeAll(
        generation: GatheredGeneration,
        keep: Set<TransportAddress> = emptySet(),
    ) {
        for (base in generation.bases) {
            if (base in keep) continue
            channels.remove(base)?.close()
        }
    }

    private fun forward(
        base: TransportAddress,
        channel: AddressedDatagramChannel,
    ) {
        scope.launch {
            while (true) {
                // A socket closed under an in-flight read can throw rather than return Closed — see
                // [receiveOrClosed], which is also why this loop is not the only site that needed it.
                val datagram =
                    when (val result = channel.receiveOrClosed()) {
                        is DatagramReadResult.Received -> result.datagram
                        is DatagramReadResult.Closed -> return@launch
                    }
                // RFC 7983 demux: STUN → the ICE agent; anything else is application data (DTLS/SCTP).
                if (isStun(datagram.payload)) {
                    post(IceEvent.DatagramReceived(base, datagram.peer.toTransportAddress(), datagram.payload))
                } else {
                    appInbound.trySend(datagram.payload)
                }
            }
        }
    }

    private fun isStun(payload: ReadBuffer): Boolean = StunMessage.decode(payload.slice()) is StunDecodeResult.Success

    private suspend fun driveLoop() {
        while (true) {
            val deadline = agent.nextDeadline(clock())
            val command =
                if (deadline == null) {
                    inbox.receiveCatching().getOrNull() ?: return
                } else {
                    // select (not withTimeoutOrNull { receive() }): a plain timeout can cancel receive()
                    // *after* it was handed an element, silently losing a trickled candidate posted at a
                    // deadline. select leaves an un-taken element in the channel for the next iteration.
                    val wait = (deadline - clock()).coerceAtLeast(Duration.ZERO)
                    select<Command?> {
                        inbox.onReceiveCatching { it.getOrNull() }
                        onTimeout(wait) { null }
                    }
                }
            when (command) {
                null -> apply(agent.handle(IceEvent.TimerFired, clock()))
                is Command.Event -> {
                    if (command.event == IceEvent.Restart) beginRestartGeneration()
                    val event = command.event
                    apply(agent.handle(event, clock()))
                    // Published here, after the agent has applied it: `localCredentials` now names the
                    // generation this candidate is genuinely in, even if a restart overtook the gathering
                    // coroutine that produced it (RFC 8838 §3.1).
                    if (event is IceEvent.AddLocalCandidate) {
                        gathered.trySend(GatheredCandidate(event.candidate, agent.localCredentials.ufrag))
                    }
                }
                is Command.Restart -> {
                    beginRestartGeneration()
                    apply(agent.handle(IceEvent.Restart, clock()))
                    command.applied.complete(agent.localCredentials)
                }
                is Command.Rollback -> {
                    rollbackRestartGeneration()
                    apply(agent.handle(IceEvent.RollbackRestart, clock()))
                    command.applied.complete(agent.localCredentials)
                }
            }
        }
    }

    private suspend fun apply(outputs: List<IceOutput>) {
        for (output in outputs) {
            when (output) {
                is IceOutput.Transmit -> {
                    // Two things this must not do, and both used to happen on a raised send.
                    //
                    // The release is owed on **every** exit, not only the one that sent — a throw between
                    // `send` and the release leaked the buffer outright, against the ownership invariant
                    // #142 established and proved. `finally` states that the way the rest of this module
                    // already does (`IceGathering`, `TurnAllocation`).
                    //
                    // And a failure must not escape this loop. `outputs` is a *batch*: abandoning it
                    // mid-way drops every remaining output, `ConnectionStateChanged` and `PathChanged`
                    // included, so the driver's observable state silently stops matching the core's. A
                    // lost datagram is a thing ICE is built to survive; a state machine whose observers
                    // never heard it moved is not. The transmit is reported and the batch continues.
                    val result =
                        try {
                            channels[output.fromBase]?.sendOrFailure(output.data, to = output.to.toSocketAddress())
                        } finally {
                            output.data.releaseAfterSend()
                        }
                    if (result is IceTransmitResult.Failed) {
                        // trySend on a DROP_OLDEST channel, never send: the drive loop is serialized, so
                        // suspending it on a diagnostic nobody is obliged to collect would let a failing
                        // socket stall ICE itself — the same rule `discarded` follows below.
                        transmitFailures
                            .trySend(IceTransmitFailure(to = output.to, reason = result.reason, cause = result.cause))
                            .let { }
                    }
                }
                is IceOutput.ConnectionStateChanged -> _state.value = output.state
                is IceOutput.PathChanged -> {
                    // A nomination ends the restart window, and only then is it safe to close the outgoing
                    // generation's sockets — closing any earlier would tear down the channel data is on.
                    if (output.path is IcePath.Nominated) completeRestartGeneration()
                    _path.value = output.path
                }
                // Nothing for the driver to *do*: the candidate was refused by the core on purpose
                // (RFC 8838 §3.1), there is no socket to touch and no state to unwind. It is an output
                // rather than a silent return so a fixture — and now a diagnostics surface (webrtc#106)
                // — can see the difference between a candidate discarded and one that never arrived.
                // trySend, never send: the drive loop is serialized, so suspending it on a diagnostic
                // nobody is obliged to collect would let a peer stall ICE by trickling junk.
                is IceOutput.RemoteCandidateDiscarded -> discarded.trySend(output).let { }
            }
        }
    }

    /**
     * What the serialized inbox carries. Restart and rollback are *commands* rather than plain events
     * because the caller must know when they took effect — the coroutine seam belongs here in the
     * driver, not inside the sans-io [IceEvent] vocabulary, which stays free of `Deferred`s.
     */
    private sealed interface Command {
        data class Event(
            val event: IceEvent,
        ) : Command

        data class Restart(
            val applied: CompletableDeferred<IceCredentials>,
        ) : Command

        data class Rollback(
            val applied: CompletableDeferred<IceCredentials>,
        ) : Command
    }

    /** The sockets and candidates gathered for one ICE generation — what a restart swaps, in the driver. */
    private class GatheredGeneration {
        val bases: MutableSet<TransportAddress> = mutableSetOf()
        val candidates: MutableList<IceCandidate> = mutableListOf()

        fun forget(candidate: IceCandidate) {
            candidates.remove(candidate)
            bases.remove(candidate.base)
        }
    }

    /** Whether an outgoing generation's sockets are being held open across a restart (RFC 8445 §9). */
    private sealed interface RetiringGeneration {
        /** No restart in flight — every bound socket belongs to the current generation. */
        data object None : RetiringGeneration

        /** [generation]'s sockets stay bound and carrying data until the new generation nominates. */
        data class Pending(
            val generation: GatheredGeneration,
        ) : RetiringGeneration
    }
}

/**
 * How many refused remote candidates [IceAgentDriver.remoteCandidateDiscarded] holds for a collector
 * that has not caught up. Sized against the thing that produces them in bulk: the agent's own hold
 * buffer for unapplied generations is 32, so one full overflow of that buffer fits here without loss.
 * Beyond it the oldest go — they are diagnostics about a peer misbehaving, and the newest are the ones
 * that describe what it is doing now.
 */
private const val DISCARD_DIAGNOSTIC_BUFFER = 32

/**
 * How many refused transmits [IceAgentDriver.transmitFailed] holds for a collector that has not caught
 * up. Smaller than [DISCARD_DIAGNOSTIC_BUFFER] on purpose: these are not evidence to be counted but a
 * condition to be noticed, and a socket that refuses one send overwhelmingly refuses the next, so the
 * eighth identical failure tells a collector nothing the first did not. Dropping the oldest keeps the
 * window on what the socket is doing *now*.
 */
private const val TRANSMIT_FAILURE_DIAGNOSTIC_BUFFER = 8

/**
 * How many refused permissions [IceAgentDriver.relayPermissionRefused] holds. Deliberately the same size
 * as [TRANSMIT_FAILURE_DIAGNOSTIC_BUFFER] even though it merges every allocation's stream: a dual-stack
 * session gathers two relay candidates, so the merge at most doubles the rate of something that was
 * already "notice it, do not count it".
 */
private const val PERMISSION_REFUSAL_DIAGNOSTIC_BUFFER = 8

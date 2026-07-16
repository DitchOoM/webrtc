@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.stun.StunDecodeResult
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.TransportAddress
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
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
 * Binds an **unconnected** [DatagramChannel] at a local [SocketAddress] — the one network seam the
 * [IceTransport] driver rides. Production supplies a real-UDP binder (socket-udp `UdpSocket.bind`, at
 * the platform edge — no wasm, RFC §1.1); tests supply the in-memory vnet. Both honor the same
 * buffer-flow `DatagramChannel` contract, so the driver above is identical on either (DESIGN §7).
 */
public fun interface DatagramBinder {
    /** Bind and return a channel receiving datagrams sent toward [address]. */
    public suspend fun bind(address: SocketAddress): DatagramChannel
}

/**
 * The point-to-point application-data seam over the ICE-selected pair — the RFC 7983 non-STUN half of
 * the nominated socket. [send] rides `selectedPair.local.base → selectedPair.remote.address`; [receive]
 * yields the demuxed non-STUN datagrams (DTLS/SCTP). This is **the boundary where DTLS slots in** (W4):
 * it is deliberately shaped identically to `webrtc-sctp`'s `SctpDatagramTransport` so the SCTP stack (or
 * a real DTLS record layer wrapping it) drops in as a swap, without `webrtc-ice` depending on `webrtc-sctp`.
 */
public interface IceDataTransport {
    /** Send one packet to the peer over the selected pair. Ownership of [packet] is not transferred. */
    public suspend fun send(packet: ReadBuffer)

    /** Receive the next non-STUN packet, or null once the transport has closed. */
    public suspend fun receive(): ReadBuffer?

    /** Tear the app-data seam down; a pending/next [receive] returns null. Idempotent. */
    public fun close()
}

/**
 * The production **driver** the sans-io [IceAgent] lacks by design (RFC §5.1: cores own truth, drivers
 * own I/O) — promoted from the W5 `IceDriver` composition proof so `PeerConnection` and a future media
 * layer compose the *same* transport-over-the-selected-pair rather than re-deriving it.
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
    config: IceConfig = IceConfig(),
) {
    // Derive two independent, deterministic streams from the single injected seam: the agent and the
    // gathering coroutines run concurrently, so they must not share one Random's mutable state.
    private val agentRandom = Random(random.nextLong())

    @Suppress("UnseamedEntropy") // derived from the injected [random]; not an ambient default
    private val gatheringRandom = Random(random.nextLong())

    // The sans-io agent this driver clocks — internal, never public: every `handle` call must go through
    // the single [driveLoop], so exposing the raw core would let a caller race it and corrupt checklist
    // state. Consumers use the re-exposed [state]/[selectedPair]/[localCandidates]/[localCredentials].
    internal val agent: IceAgent = IceAgent(role, agentRandom, config)

    /** This agent's local ICE credentials (ufrag/pwd) — signal them to the peer. */
    public val localCredentials: IceCredentials get() = agent.localCredentials

    private val inbox = Channel<IceEvent>(Channel.UNLIMITED)
    private val channels = HashMap<TransportAddress, DatagramChannel>()

    // App-data (non-STUN) demux (RFC 7983): datagrams that are not STUN connectivity checks are DTLS/SCTP
    // and are routed here rather than into the agent, which ignores them. This is the seam SCTP rides.
    private val appInbound = Channel<ReadBuffer>(Channel.UNLIMITED)

    private val _state = MutableStateFlow<IceConnectionState>(IceConnectionState.New)

    /** The ICE connection state (RFC 8445 §6.1.2.6), for the session layer to await/observe. */
    public val state: StateFlow<IceConnectionState> get() = _state

    private var _selectedPair: CandidatePair? = null

    /** The nominated pair application traffic uses, or null before nomination. */
    public val selectedPair: CandidatePair? get() = _selectedPair

    private val _localCandidates = mutableListOf<IceCandidate>()

    /** A snapshot of the local candidates gathered so far. */
    public val localCandidates: List<IceCandidate> get() = _localCandidates.toList()

    private val gathered = Channel<IceCandidate>(Channel.UNLIMITED)

    /** Every local candidate as it is gathered (host/srflx/relay) — the trickle (RFC 8838) source. */
    public val localCandidateGathered: Flow<IceCandidate> get() = gathered.receiveAsFlow()

    /** Launch the serialized drive loop. Gather candidates and feed remote state after this. */
    public fun start() {
        scope.launch { driveLoop() }
    }

    /**
     * Gather a host candidate at [ip]:[port], and — if [stunServer] is given — a server-reflexive
     * candidate on the same socket (gathered *before* the forwarder starts, so it does not race the
     * checklist for `receive()`). Returns the host candidate; both are emitted on [localCandidateGathered].
     */
    public suspend fun gatherHost(
        ip: String,
        port: Int,
        stunServer: SocketAddress? = null,
    ): IceCandidate {
        val socketAddress = SocketAddress.ofLiteral(ip, port)
        val channel = binder.bind(socketAddress)
        val hostAddress = socketAddress.toTransportAddress()
        val host = IceCandidate.host(hostAddress)
        channels[host.base] = channel
        gather(host)

        if (stunServer != null) {
            when (val reflexive = gatherServerReflexive(channel, stunServer, gatheringRandom)) {
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
                            priority = IceCandidate.computePriority(CandidateType.ServerReflexive, ComponentId.Rtp),
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
     * present the allocation as the candidate's channel. Returns the relay candidate, or null if the
     * allocation fails.
     */
    public suspend fun gatherRelay(
        turnServer: SocketAddress,
        username: String,
        password: String,
        ip: String,
        port: Int,
    ): IceCandidate? {
        val socketAddress = SocketAddress.ofLiteral(ip, port)
        val underlying = binder.bind(socketAddress)
        val allocation = TurnAllocation(underlying, turnServer, username, password, gatheringRandom, scope)
        val relayedSocket = allocation.allocate() ?: return null
        val relayedAddress = relayedSocket.toTransportAddress()
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
                priority = IceCandidate.computePriority(CandidateType.Relayed, ComponentId.Rtp),
                relatedAddress = socketAddress.toTransportAddress(),
            )
        channels[relay.base] = allocation
        forward(relay.base, allocation)
        gather(relay)
        return relay
    }

    /** Feed the peer's ICE credentials in (from the SDP offer/answer) — pairing can begin. */
    public fun setRemoteCredentials(credentials: IceCredentials) {
        post(IceEvent.SetRemoteCredentials(credentials))
    }

    /** Feed a trickled remote candidate in (RFC 8838). */
    public fun addRemoteCandidate(candidate: IceCandidate) {
        post(IceEvent.AddRemoteCandidate(candidate))
    }

    /** Tear down the socket backing [candidate] (a link/interface going away — the candidate-flap seam). */
    public fun drop(candidate: IceCandidate) {
        channels.remove(candidate.base)?.close()
        _localCandidates.remove(candidate)
    }

    /** Begin an ICE restart (RFC 8445 §9): the driver re-gathers and re-signals after this. */
    public fun restart() {
        post(IceEvent.Restart)
    }

    /** Post a raw event into the serialized inbox (trickle/restart/signaling seam). */
    public fun post(event: IceEvent) {
        inbox.trySend(event)
    }

    /**
     * The application-data seam over the nominated pair (the W6 composition point where DTLS sits). Start
     * the SCTP stack over this only after [state] reaches [IceConnectionState.Connected]/[Completed].
     */
    public fun appDataTransport(): IceDataTransport =
        object : IceDataTransport {
            override suspend fun send(packet: ReadBuffer) {
                val pair = _selectedPair ?: return
                channels[pair.local.base]?.send(packet, to = pair.remote.address.toSocketAddress())
            }

            override suspend fun receive(): ReadBuffer? = appInbound.receiveCatching().getOrNull()

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

    private fun gather(candidate: IceCandidate) {
        _localCandidates += candidate
        post(IceEvent.AddLocalCandidate(candidate))
        gathered.trySend(candidate)
    }

    private fun forward(
        base: TransportAddress,
        channel: DatagramChannel,
    ) {
        scope.launch {
            while (true) {
                val datagram =
                    when (val result = channel.receive()) {
                        is DatagramReadResult.Received -> result.datagram
                        is DatagramReadResult.Closed -> return@launch
                    }
                // RFC 7983 demux: STUN → the ICE agent; anything else is application data (DTLS/SCTP).
                if (isStun(datagram.payload)) {
                    inbox.trySend(IceEvent.DatagramReceived(base, datagram.peer.toTransportAddress(), datagram.payload))
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
            val event =
                if (deadline == null) {
                    inbox.receiveCatching().getOrNull() ?: return
                } else {
                    // select (not withTimeoutOrNull { receive() }): a plain timeout can cancel receive()
                    // *after* it was handed an element, silently losing a trickled candidate posted at a
                    // deadline. select leaves an un-taken element in the channel for the next iteration.
                    val wait = (deadline - clock()).coerceAtLeast(Duration.ZERO)
                    select<IceEvent?> {
                        inbox.onReceiveCatching { it.getOrNull() }
                        onTimeout(wait) { null }
                    }
                }
            val outputs = if (event != null) agent.handle(event, clock()) else agent.handle(IceEvent.TimerFired, clock())
            apply(outputs)
        }
    }

    private suspend fun apply(outputs: List<IceOutput>) {
        for (output in outputs) {
            when (output) {
                is IceOutput.Transmit -> channels[output.fromBase]?.send(output.data, to = output.to.toSocketAddress())
                is IceOutput.ConnectionStateChanged -> _state.value = output.state
                is IceOutput.SelectedPairChanged -> _selectedPair = output.pair
            }
        }
    }
}

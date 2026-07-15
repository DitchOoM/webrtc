@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.vnet.Vnet
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import com.ditchoom.webrtc.stun.TransportAddress
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The **driver** the sans-io [IceAgent] lacks by design (RFC §5.1: cores own truth, drivers own I/O).
 * It wires one agent to the [Vnet]: a single merged inbox carries datagrams (from per-socket forwarder
 * loops) and externally posted [IceEvent]s, and one loop pumps `handle(event, now)` — so every
 * `handle` call is serialized and [IceAgent.nextDeadline] is realized as a [withTimeoutOrNull] against
 * virtual time. Because *all* intake flows through the inbox, trickle (RFC 8838) and restart just work:
 * a candidate gathered or signaled later is one more posted event that wakes the loop.
 *
 * Gathering rides the production drivers ([gatherServerReflexive], [TurnAllocation]) over vnet sockets —
 * the same seams production uses over real UDP; the vnet is the only substitution.
 */
internal class IceDriver(
    role: IceRole,
    seed: Long,
    private val vnet: Vnet,
    private val scope: CoroutineScope,
    private val clock: () -> Instant,
    config: IceConfig = IceConfig(),
) {
    val agent: IceAgent = IceAgent(role, Random(seed), config)

    @Suppress("UnseamedEntropy") // test-only seam; the seed is the injected gathering entropy
    private val random = Random(seed * SEED_SPREAD + 1)
    private val inbox = Channel<IceEvent>(Channel.UNLIMITED)
    private val channels = HashMap<TransportAddress, DatagramChannel>()

    private val _state = MutableStateFlow<IceConnectionState>(IceConnectionState.New)
    val state: StateFlow<IceConnectionState> get() = _state

    private var _selectedPair: CandidatePair? = null
    val selectedPair: CandidatePair? get() = _selectedPair

    /** Local candidates this agent has gathered — signal them to the peer with [connectTo]. */
    val localCandidates = mutableListOf<IceCandidate>()

    fun start() {
        scope.launch { driveLoop() }
    }

    /**
     * Gather a host candidate at [ip]:[port], and — if [stunServer] is given — a server-reflexive
     * candidate on the same socket (gathered *before* the forwarder starts, so it does not race the
     * checklist for `receive()`). Returns the host candidate.
     */
    suspend fun bindHost(
        ip: String,
        port: Int,
        stunServer: SocketAddress? = null,
    ): IceCandidate {
        val socketAddress = vnetAddress(ip, port)
        val channel = vnet.bind(socketAddress)
        val hostAddress = socketAddress.toTransportAddress()
        val host = IceCandidate.host(hostAddress)
        channels[host.base] = channel
        gather(host)

        if (stunServer != null) {
            val reflexive = gatherServerReflexive(channel, stunServer, random)
            if (reflexive != null) {
                gather(
                    IceCandidate(
                        type = CandidateType.ServerReflexive,
                        transport = IceTransport.Udp,
                        address = reflexive,
                        base = hostAddress,
                        foundation =
                            Foundation.of(
                                CandidateType.ServerReflexive,
                                hostAddress.ip(),
                                stunServer.toTransportAddress().ip(),
                                IceTransport.Udp,
                            ),
                        component = ComponentId.Rtp,
                        priority = IceCandidate.computePriority(CandidateType.ServerReflexive, ComponentId.Rtp),
                        relatedAddress = hostAddress,
                    ),
                )
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
    suspend fun gatherRelay(
        turnServer: SocketAddress,
        username: String,
        password: String,
        ip: String,
        port: Int,
    ): IceCandidate? {
        val socketAddress = vnetAddress(ip, port)
        val underlying = vnet.bind(socketAddress)
        val allocation = TurnAllocation(underlying, turnServer, username, password, random, scope)
        val relayedSocket = allocation.allocate() ?: return null
        val relayedAddress = relayedSocket.toTransportAddress()
        val relay =
            IceCandidate(
                type = CandidateType.Relayed,
                transport = IceTransport.Udp,
                address = relayedAddress,
                base = relayedAddress,
                foundation =
                    Foundation.of(
                        CandidateType.Relayed,
                        relayedAddress.ip(),
                        turnServer.toTransportAddress().ip(),
                        IceTransport.Udp,
                    ),
                component = ComponentId.Rtp,
                priority = IceCandidate.computePriority(CandidateType.Relayed, ComponentId.Rtp),
                relatedAddress = socketAddress.toTransportAddress(),
            )
        channels[relay.base] = allocation
        forward(relay.base, allocation)
        gather(relay)
        return relay
    }

    /** Tear down the socket backing [candidate] (a link/interface going away — the candidate-flap seam). */
    fun drop(candidate: IceCandidate) {
        channels.remove(candidate.base)?.close()
        localCandidates.remove(candidate)
    }

    /** Feed [peer]'s credentials and candidates in (the trickle/signaling seam, scripted). */
    fun connectTo(peer: IceDriver) {
        post(IceEvent.SetRemoteCredentials(peer.agent.localCredentials))
        peer.localCandidates.forEach { post(IceEvent.AddRemoteCandidate(it)) }
    }

    fun post(event: IceEvent) {
        inbox.trySend(event)
    }

    suspend fun awaitConnected(): IceConnectionState =
        state.first {
            when (it) {
                is IceConnectionState.Connected, is IceConnectionState.Completed -> true
                // Fail loudly with the reason instead of hanging until the watchdog if ICE actually failed.
                is IceConnectionState.Failed -> error("expected a connection, but ICE failed: ${it.reason}")
                else -> false
            }
        }

    private fun gather(candidate: IceCandidate) {
        localCandidates += candidate
        post(IceEvent.AddLocalCandidate(candidate))
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
                inbox.trySend(IceEvent.DatagramReceived(base, datagram.peer.toTransportAddress(), datagram.payload))
            }
        }
    }

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

    companion object {
        private const val SEED_SPREAD = 31
        private val EPOCH = Instant.fromEpochSeconds(0)

        /** A virtual clock: maps a scheduler's millis to an [Instant]. */
        fun clockOf(currentTimeMillis: () -> Long): () -> Instant = { EPOCH + currentTimeMillis().milliseconds }
    }
}

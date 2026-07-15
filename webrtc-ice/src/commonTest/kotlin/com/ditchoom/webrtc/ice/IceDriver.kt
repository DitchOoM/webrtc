@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.Vnet
import com.ditchoom.webrtc.ice.vnet.toSocketAddress
import com.ditchoom.webrtc.ice.vnet.toTransportAddress
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The **driver** the sans-io [IceAgent] lacks by design (RFC §5.1: cores own truth, drivers own I/O).
 * It wires one agent to the [Vnet]: a single merged inbox carries datagrams (from per-socket forwarder
 * loops) and externally posted [IceEvent]s, and one loop pumps `handle(event, now)` — so every
 * `handle` call is serialized (no concurrent mutation) and [IceAgent.nextDeadline] is realized as a
 * [withTimeoutOrNull] against virtual time. This is the shape the production gathering driver (step 4)
 * takes; here it is just enough to establish and observe a session under `runTest`.
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

    private val inbox = Channel<IceEvent>(Channel.UNLIMITED)
    private val channels = HashMap<com.ditchoom.webrtc.stun.TransportAddress, DatagramChannel>()

    private val _state = MutableStateFlow<IceConnectionState>(IceConnectionState.New)
    val state: StateFlow<IceConnectionState> get() = _state

    private var _selectedPair: CandidatePair? = null
    val selectedPair: CandidatePair? get() = _selectedPair

    /** Local candidates this agent has gathered — signal them to the peer with [connectTo]. */
    val localCandidates = mutableListOf<IceCandidate>()

    fun start() {
        scope.launch { driveLoop() }
    }

    /** Bind a host candidate at [ip]:[port], forward its datagrams into the inbox, and gather it. */
    fun bindHost(
        ip: String,
        port: Int,
    ): IceCandidate {
        val socketAddress = vnetAddress(ip, port)
        val channel = vnet.bind(socketAddress)
        val candidate = IceCandidate.host(socketAddress.toTransportAddress())
        channels[candidate.base] = channel
        localCandidates += candidate
        forward(candidate.base, channel)
        post(IceEvent.AddLocalCandidate(candidate))
        return candidate
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
        state.first { it is IceConnectionState.Connected || it is IceConnectionState.Completed }

    private fun forward(
        base: com.ditchoom.webrtc.stun.TransportAddress,
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
                    withTimeoutOrNull((deadline - clock()).coerceAtLeast(Duration.ZERO)) { inbox.receive() }
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
        private val EPOCH = Instant.fromEpochSeconds(0)

        /** A virtual clock for [IceConfig]-less construction: maps a scheduler's millis to an [Instant]. */
        fun clockOf(currentTimeMillis: () -> Long): () -> Instant = { EPOCH + currentTimeMillis().milliseconds }
    }
}

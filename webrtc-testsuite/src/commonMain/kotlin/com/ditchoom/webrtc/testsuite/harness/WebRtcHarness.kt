@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.testsuite.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.counting
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.DtlsTransportFactory
import com.ditchoom.webrtc.NativePeerConnection
import com.ditchoom.webrtc.PeerConnectionConfig
import com.ditchoom.webrtc.PeerConnectionFailureReason
import com.ditchoom.webrtc.PeerConnectionState
import com.ditchoom.webrtc.PlaintextDtls
import com.ditchoom.webrtc.RtcPeerConnection
import com.ditchoom.webrtc.WebRtcException
import com.ditchoom.webrtc.ice.CandidatePair
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.ice.IceAgentDriver
import com.ditchoom.webrtc.ice.IceConfig
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sdp.SdpType
import com.ditchoom.webrtc.testsuite.vnet.Vnets
import com.ditchoom.webrtc.testsuite.vnet.utf8Buffer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The published consumer harness (RFC §7 "Consumer" tier, §8 harness): drive a full two-peer WebRTC
 * establishment — ICE + DTLS + SCTP + a DataChannel — over the deterministic in-memory **vnet**, under
 * `runTest` virtual time, with a typed scenario DSL. It is the Kotlin front-end a downstream project
 * uses to reproduce the scenarios the L2/L3 container harness (`test-harness/`) runs against real
 * kernels — but here everything replays at zero wall-clock on every platform, no docker, no OS sockets:
 *
 * ```kotlin
 * runTest {
 *     withWebRtcHarness(scope = backgroundScope, clock = virtualClock) {
 *         natType(NatType.Symmetric)      // both peers behind a symmetric NAT (RFC 4787)
 *         relayOnly()                     // force the TURN-relay path
 *         impaired(loss = 0.05)           // 5% packet loss on the link (netem analogue)
 *         val echoed = roundTrip("ping")  // establish, open a data channel, echo a message
 *         assertEquals("ping", echoed)
 *     }
 * }
 * ```
 *
 * **Seams are injected** (directive #2): [scope] owns every coroutine, [clock] every timer (a
 * `runTest` virtual clock), [seed] all entropy (each peer derives a `Random`), [bufferFactory] every
 * allocation (wrapped in a counting decorator — the `TrackingBufferFactory` invariant, exposed as
 * [WebRtcHarnessScope.allocationCount]), and [dtlsFactory] the DTLS backend. The default DTLS is
 * [PlaintextDtls] — the vnet needs no real crypto and it is the only backend on every platform until
 * W4b lands cross-platform DTLS; a native consumer can pass `{ BoringSslDtls(scope, clock) }`.
 *
 * **Typed errors, never stringly** (directive #3): an establishment that fails surfaces as a
 * [WebRtcException] carrying the sealed [PeerConnectionFailureReason] (`Ice`/`Dtls`/`Sctp`), exactly as
 * the production `NativePeerConnection` reports it; a scenario that never converges trips the virtual
 * `withTimeout([establishTimeout])` watchdog (observable state + watchdog, never a wall-clock budget).
 *
 * @param establishTimeout the virtual-time watchdog for reaching `Connected`/`Failed` on both peers.
 */
public suspend fun withWebRtcHarness(
    scope: CoroutineScope,
    clock: () -> Instant,
    seed: Long = 0L,
    bufferFactory: BufferFactory = BufferFactory.Default,
    dtlsFactory: () -> DtlsTransportFactory = { PlaintextDtls },
    establishTimeout: Duration = 60.seconds,
    block: suspend WebRtcHarnessScope.() -> Unit,
) {
    val harnessScope =
        WebRtcHarnessScope(
            scope = scope,
            clock = clock,
            seed = seed,
            bufferFactory = bufferFactory,
            dtlsFactory = dtlsFactory,
            establishTimeout = establishTimeout,
        )
    harnessScope.block()
}

/**
 * The scoped DSL of a [withWebRtcHarness] scenario. Configuration setters ([natType], [relayOnly],
 * [impaired]) describe the topology and must precede [establish]/[roundTrip]; calling one after the
 * peers are up is a misuse and throws. The lifecycle is modeled as a value (`connection == null` means
 * "still configuring"), so an illegal "reconfigure a live scenario" is a single guarded check, not a
 * scatter of booleans.
 */
public class WebRtcHarnessScope internal constructor(
    private val scope: CoroutineScope,
    private val clock: () -> Instant,
    private val seed: Long,
    bufferFactory: BufferFactory,
    private val dtlsFactory: () -> DtlsTransportFactory,
    private val establishTimeout: Duration,
) {
    private val counting = bufferFactory.counting()

    private var natType: NatType = NatType.None
    private var relayOnly: Boolean = false
    private var impairment: NetworkImpairment? = null
    private var connection: WebRtcHarnessConnection? = null

    /** Buffers allocated by the vnet + both peers' ICE/SCTP so far — the no-runaway-allocation invariant. */
    public val allocationCount: Long get() = counting.allocationCount

    /** Place **both** peers behind [type] (RFC 4787). Default [NatType.None] (flat, direct). */
    public fun natType(type: NatType) {
        checkConfigurable()
        natType = type
    }

    /** Constrain ICE to TURN-relay candidates only — no host/srflx offered (forces the relay path). */
    public fun relayOnly() {
        checkConfigurable()
        relayOnly = true
    }

    /** Apply a [NetworkImpairment] to the link. */
    public fun impaired(impairment: NetworkImpairment) {
        checkConfigurable()
        this.impairment = impairment
    }

    /** Apply base [delay] ± [jitter], [loss], and [duplicate] to the link (netem analogue). */
    public fun impaired(
        loss: Double = 0.0,
        delay: Duration = Duration.ZERO,
        jitter: Duration = Duration.ZERO,
        duplicate: Double = 0.0,
    ) {
        impaired(NetworkImpairment.of(delay = delay, jitter = jitter, loss = loss, duplicate = duplicate))
    }

    /**
     * Stand up the configured topology, wire two [NativePeerConnection]s over the vnet, drive scripted
     * offer/answer + trickle, and suspend (under the [establishTimeout] virtual watchdog) until **both**
     * peers reach `Connected`. Idempotent — repeated calls return the same live [WebRtcHarnessConnection].
     *
     * @throws WebRtcException if either peer reaches `Failed` (carrying the typed reason).
     */
    public suspend fun establish(): WebRtcHarnessConnection {
        connection?.let { return it }

        val topology = Vnets.build(scope, natType.toProfileOrNull(), counting, impairment?.toConfig())
        val binder = DatagramBinder { topology.vnet.bind(it) }
        val config =
            PeerConnectionConfig(iceConfig = IceConfig(bufferFactory = counting), sctpConfig = SctpConfig(bufferFactory = counting))

        val offerer =
            NativePeerConnection(
                scope = scope,
                clock = clock,
                random = Random(seed),
                binder = binder,
                gathering = gatheringPolicy(topology.aliceHost, topology),
                dtls = dtlsFactory(),
                config = config,
            )
        val answerer =
            NativePeerConnection(
                scope = scope,
                clock = clock,
                random = Random(seed + 1),
                binder = binder,
                gathering = gatheringPolicy(topology.bobHost, topology),
                dtls = dtlsFactory(),
                config = config,
            )

        // Signaling seam: forward each peer's trickled ICE candidates into the other.
        scope.launch { offerer.localIceCandidates.collect { answerer.addIceCandidate(it) } }
        scope.launch { answerer.localIceCandidates.collect { offerer.addIceCandidate(it) } }

        // Echo responder: the answerer bounces every data-channel message straight back, so a
        // consumer's roundTrip() sees its own payload return end-to-end through the whole stack.
        scope.launch {
            answerer.incomingDataChannels.collect { incoming ->
                scope.launch { incoming.receive().collect { incoming.send(it) } }
            }
        }

        val offer = offerer.createOffer()
        offerer.setLocalDescription(SdpType.Offer, offer)
        answerer.setRemoteDescription(SdpType.Offer, offer)
        val answer = answerer.createAnswer()
        answerer.setLocalDescription(SdpType.Answer, answer)
        offerer.setRemoteDescription(SdpType.Answer, answer)

        val selectedPair =
            withTimeout(establishTimeout) {
                val pair = offerer.awaitConnected()
                answerer.awaitConnected()
                pair
            }

        val manifest =
            HarnessManifest(
                natType = natType,
                relayOnly = relayOnly,
                impairment = impairment,
                offerer = topology.aliceHost.toEndpoint(),
                answerer = topology.bobHost.toEndpoint(),
                stun = topology.stunAddress.toEndpoint(),
                turn = topology.turnAddress.toEndpoint(),
            )
        return WebRtcHarnessConnection(manifest, selectedPair, offerer, answerer).also { connection = it }
    }

    /**
     * [establish] (if not already), open a DataChannel labeled [label] from the offerer, send [message],
     * and return the answerer's echo of it. The whole ICE+DTLS+SCTP+DCEP path is exercised per call.
     */
    public suspend fun roundTrip(
        message: String,
        label: String = "harness",
    ): String {
        val conn = establish()
        return withTimeout(establishTimeout) {
            val channel = conn.offerer.createDataChannel(DataChannelConfig(label = label))
            channel.send(utf8Buffer(message))
            channel.receive().first().decodeUtf8()
        }
    }

    // Host + srflx (+ relay backup) normally; relay-only when forced. Symmetric NAT needs the relay,
    // which is why it is always gathered as a fallback unless the topology is flat.
    private fun gatheringPolicy(
        host: SocketAddress,
        topology: com.ditchoom.webrtc.testsuite.vnet.Topology,
    ): com.ditchoom.webrtc.IceGatheringPolicy {
        val hostIp = host.host
        val hostPort = host.port
        val relayPort = hostPort + RELAY_PORT_OFFSET
        return com.ditchoom.webrtc.IceGatheringPolicy { driver: IceAgentDriver ->
            if (relayOnly) {
                driver.gatherRelay(topology.turnAddress, Vnets.TURN_USERNAME, Vnets.TURN_PASSWORD, hostIp, relayPort)
            } else {
                driver.gatherHost(hostIp, hostPort, stunServer = if (topology.natted) topology.stunAddress else null)
                driver.gatherRelay(topology.turnAddress, Vnets.TURN_USERNAME, Vnets.TURN_PASSWORD, hostIp, relayPort)
            }
        }
    }

    private fun checkConfigurable() =
        check(connection == null) { "the harness is already established; configure natType/relayOnly/impaired before establish()" }

    private suspend fun RtcPeerConnection.awaitConnected(): CandidatePair? {
        val state =
            connectionState.first {
                when (it) {
                    is PeerConnectionState.Connected -> true
                    is PeerConnectionState.Failed -> throw WebRtcException(it.reason)
                    else -> false
                }
            }
        return (state as PeerConnectionState.Connected).selectedPair
    }

    private fun SocketAddress.toEndpoint(): HarnessEndpoint = HarnessEndpoint(host, port)
}

/** Relay socket sits [RELAY_PORT_OFFSET] above the host socket on the same private IP. */
private const val RELAY_PORT_OFFSET = 1000

/**
 * A live, established two-peer harness scenario: the resolved [manifest], the ICE [selectedPair] (as the
 * offerer sees it — inspect `selectedPair.local.type` to assert `Relayed` under [WebRtcHarnessScope.relayOnly]),
 * and the two [RtcPeerConnection]s for direct data-channel exercise.
 */
public class WebRtcHarnessConnection internal constructor(
    public val manifest: HarnessManifest,
    public val selectedPair: CandidatePair?,
    public val offerer: RtcPeerConnection,
    public val answerer: RtcPeerConnection,
)

/** Decode a whole [ReadBuffer]'s remaining bytes as UTF-8 via buffer-native readString (no array copy). */
private fun ReadBuffer.decodeUtf8(): String = readString(remaining(), Charset.UTF8)

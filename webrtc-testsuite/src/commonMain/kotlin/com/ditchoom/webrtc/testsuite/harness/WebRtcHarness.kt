@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.testsuite.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.use
import com.ditchoom.webrtc.DtlsTransportFactory
import com.ditchoom.webrtc.NativePeerConnection
import com.ditchoom.webrtc.PeerConnectionConfig
import com.ditchoom.webrtc.PeerConnectionFailureReason
import com.ditchoom.webrtc.PeerConnectionState
import com.ditchoom.webrtc.PlaintextDtls
import com.ditchoom.webrtc.RtcPeerConnection
import com.ditchoom.webrtc.SelectedPath
import com.ditchoom.webrtc.WebRtcException
import com.ditchoom.webrtc.ice.CandidatePair
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.ice.IceAgentDriver
import com.ditchoom.webrtc.ice.IceConfig
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sdp.SdpType
import com.ditchoom.webrtc.testsuite.vnet.Topology
import com.ditchoom.webrtc.testsuite.vnet.Vnets
import com.ditchoom.webrtc.testsuite.vnet.utf8Buffer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The published consumer harness (ARCHITECTURE §7 "Consumer" tier, §8 harness): drive a full two-peer WebRTC
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
 * allocation (backing a pooled tracker, so the scenario can answer for its buffers as well as count them
 * — [WebRtcHarnessScope.allocationCount], [WebRtcHarnessScope.assertNoBufferLeaks] and [BufferCensus]),
 * and [dtlsFactory] the DTLS backend. The default DTLS is
 * [PlaintextDtls]: a scenario about NAT traversal and data-channel semantics gets nothing from a real
 * handshake but the time it takes, and this is the one backend that exists on **every** platform the
 * harness runs on, browsers included. Pass `{ PureKotlinDtls(scope, clock) }` for the real thing on any
 * non-browser target.
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
    try {
        harnessScope.block()
    } catch (t: Throwable) {
        // The scenario's own failure is the one worth reporting; a teardown that also fails on the way
        // out must not replace it.
        runCatching { harnessScope.close() }
        throw t
    }
    harnessScope.close()
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
    private val counting = TrackingBufferFactory(bufferFactory)

    // Everything the harness itself launches — the two signaling forwarders, the echo responder, and the
    // vnet's STUN/TURN servers — runs here rather than directly on the caller's [scope], so [close] can
    // stop exactly the harness's coroutines and JOIN them. Joining is the load-bearing half: a cancelled
    // coroutine's `finally` is where the last in-flight buffers go back, and a census taken before those
    // have run reports a leak the scenario does not have.
    private val harnessJob = SupervisorJob(scope.coroutineContext[Job])
    private val harnessScope = CoroutineScope(scope.coroutineContext + harnessJob)

    private var natType: NatType = NatType.None
    private var relayOnly: Boolean = false
    private var impairment: NetworkImpairment? = null
    private var connection: WebRtcHarnessConnection? = null
    private var topology: Topology? = null
    private var closed = false

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
        check(!closed) { "the harness scenario is closed" }
        connection?.let { return it }

        val topology = Vnets.build(harnessScope, natType.toProfileOrNull(), counting, impairment?.toConfig()).also { this.topology = it }
        val binder = DatagramBinder { topology.vnet.bind(it) }
        val config =
            PeerConnectionConfig(iceConfig = IceConfig(bufferFactory = counting), sctpConfig = SctpConfig(bufferFactory = counting))

        val offerer =
            NativePeerConnection(
                scope = harnessScope,
                clock = clock,
                random = Random(seed),
                binder = binder,
                gathering = gatheringPolicy(topology.aliceHost, topology),
                dtls = dtlsFactory(),
                config = config,
            )
        val answerer =
            NativePeerConnection(
                scope = harnessScope,
                clock = clock,
                random = Random(seed + 1),
                binder = binder,
                gathering = gatheringPolicy(topology.bobHost, topology),
                dtls = dtlsFactory(),
                config = config,
            )

        // Signaling seam: forward each peer's trickled ICE candidates into the other.
        harnessScope.launch { offerer.localIceCandidates.collect { answerer.addIceCandidate(it) } }
        harnessScope.launch { answerer.localIceCandidates.collect { offerer.addIceCandidate(it) } }

        // Echo responder: the answerer bounces every data-channel message straight back, so a
        // consumer's roundTrip() sees its own payload return end-to-end through the whole stack.
        //
        // An inbound message is TRANSFERRED to its collector (`DataChannelConnection.receive`), so this
        // responder owes it a release once it has been echoed — `send` reads the message and never takes
        // it. Skipping that would leak one reassembly buffer per echoed message, in the harness rather
        // than in the stack, which is precisely the kind of accounting [BufferCensus] must not invent.
        harnessScope.launch {
            answerer.incomingDataChannels.collect { incoming ->
                harnessScope.launch {
                    incoming.receive().collect { message ->
                        try {
                            incoming.send(message)
                        } finally {
                            message.freeIfNeeded()
                        }
                    }
                }
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
            // Both buffers are ours to release: `send` reads the outgoing one and never takes it, and the
            // echo arrives as a transfer the collector owes (see the responder in [establish]).
            utf8Buffer(message).use { channel.send(it) }
            val echoed = channel.receive().first()
            try {
                echoed.decodeUtf8()
            } finally {
                echoed.freeIfNeeded()
            }
        }
    }

    /**
     * Tear the scenario down: close both peers (graceful SCTP shutdown included), stop and **join** every
     * coroutine the harness launched, then unbind the vnet. Idempotent, and called for you when a
     * [withWebRtcHarness] block ends — so a consumer only calls it to measure earlier than that.
     *
     * Joining rather than merely cancelling is what makes [bufferCensus] answerable: the last buffers of a
     * torn-down session go back in a cancelled coroutine's `finally`, and a census taken before those have
     * been dispatched reports a leak that is not there.
     */
    public suspend fun close() {
        if (closed) return
        closed = true
        connection?.let { live ->
            live.offerer.close()
            live.answerer.close()
        }
        harnessJob.cancelAndJoin()
        // Last: whatever is still queued at a vnet endpoint was never delivered, so the vnet is its last
        // reader. Unbinding after the peers are gone is what makes that true rather than a race.
        topology?.vnet?.close()
    }

    /**
     * [close] the scenario and report what it did with its buffers — the standing no-leak invariant as a
     * value. See [BufferCensus] for why `outstandingChunks` is the claim that matters and
     * `unreleasedBuffers` is the one that names *which*.
     */
    public suspend fun bufferCensus(): BufferCensus {
        close()
        return counting.census()
    }

    /**
     * [close] the scenario and fail unless **every buffer it allocated came back** — directive #6's
     * invariant, which until now only this library's own fixtures could assert.
     *
     * [what] names the scenario in the failure, since a count alone says nothing about where. Throws
     * [AssertionError], so it reads like any other assertion in a `kotlin.test` body without this
     * published artifact having to depend on a test framework.
     */
    public suspend fun assertNoBufferLeaks(what: String = "the harness scenario") {
        val census = bufferCensus()
        if (census.unreleasedBuffers != 0) {
            throw AssertionError(
                "$what leaked ${census.unreleasedBuffers} of ${census.allocations} buffer(s): " +
                    "they were never released back to the pool — $census",
            )
        }
        // Not folded into isDrained's message: a saturated pool is a broken MEASUREMENT, not a leak, and
        // saying so is the difference between fixing a fixture and hunting a bug that is not there.
        if (census.saturated) {
            throw AssertionError(
                "$what filled the harness buffer pool (peak ${census.peakPoolSize} of ${census.poolCapacity}) — " +
                    "a full pool drops returned chunks, so this measurement cannot be trusted — $census",
            )
        }
        if (census.outstandingChunks != 0) {
            throw AssertionError(
                "$what did not return every chunk: the pool created ${census.chunksCreated} and only " +
                    "${census.chunksIdle} are idle, so ${census.outstandingChunks} still has a reference nobody " +
                    "released (a slice, not a missing free) — $census",
            )
        }
        if (census.chunksCreated == 0) {
            throw AssertionError("$what never allocated a chunk — it cannot have exercised anything — $census")
        }
    }

    // Host + srflx (+ relay backup) normally; relay-only when forced. Symmetric NAT needs the relay,
    // which is why it is always gathered as a fallback unless the topology is flat.
    private fun gatheringPolicy(
        host: SocketAddress,
        topology: Topology,
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
        // The harness surfaces a plain pair-or-null: a scenario asserts on the pair it got, and "the browser
        // owns selection internally" is not a case a harness scenario can do anything with.
        return when (val path = (state as PeerConnectionState.Connected).path) {
            SelectedPath.Opaque -> null
            is SelectedPath.Known -> path.pair
        }
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

@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.webrtc.ice.IceAgentDriver
import com.ditchoom.webrtc.ice.IceCandidateLine
import com.ditchoom.webrtc.ice.IceConfig
import com.ditchoom.webrtc.ice.IceConnectionState
import com.ditchoom.webrtc.ice.IceCredentials
import com.ditchoom.webrtc.ice.IcePassword
import com.ditchoom.webrtc.ice.IceRole
import com.ditchoom.webrtc.ice.Ufrag
import com.ditchoom.webrtc.sctp.association.SctpAssociationState
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.association.SctpFailureReason
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sctp.datachannel.SctpClosedException
import com.ditchoom.webrtc.sctp.datachannel.SctpDataChannelStack
import com.ditchoom.webrtc.sctp.datachannel.SctpRole
import com.ditchoom.webrtc.sdp.DataChannelParameters
import com.ditchoom.webrtc.sdp.Fingerprint
import com.ditchoom.webrtc.sdp.JsepEvent
import com.ditchoom.webrtc.sdp.JsepOutput
import com.ditchoom.webrtc.sdp.JsepSession
import com.ditchoom.webrtc.sdp.Mid
import com.ditchoom.webrtc.sdp.SdpParseResult
import com.ditchoom.webrtc.sdp.SdpType
import com.ditchoom.webrtc.sdp.SessionDescription
import com.ditchoom.webrtc.sdp.SetupRole
import com.ditchoom.webrtc.sdp.SignalingState
import com.ditchoom.webrtc.sdp.icePwd
import com.ditchoom.webrtc.sdp.iceUfrag
import com.ditchoom.webrtc.sdp.setup
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.emitAll
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.random.Random
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * How the [NativePeerConnection] gathers local ICE candidates — the seam over "which sockets to bind"
 * (RFC §5.2: gathering rides an injected driver). A test supplies host addresses over the vnet
 * (`{ it.gatherHost("10.0.0.1", 5000) }`); a production policy enumerates interfaces via socket's
 * `NetworkMonitor` and adds srflx/relay from the configured ICE servers (the real-UDP default lands with
 * the platform edge in W7). It runs once, when negotiation starts.
 */
public fun interface IceGatheringPolicy {
    /** Gather candidates on [driver] (host/srflx/relay) — each gathered candidate trickles out. */
    public suspend fun gather(driver: IceAgentDriver)
}

/** Static configuration for a [NativePeerConnection] (W3C `RTCConfiguration`, the subset we honor). */
public data class PeerConnectionConfig(
    public val iceConfig: IceConfig = IceConfig(),
    public val sctpConfig: SctpConfig = SctpConfig(),
    /**
     * The local certificate fingerprint carried in `a=fingerprint` (RFC 8122). DTLS (W4) owns real
     * certificate identity; until then this is a placeholder the SDP carries verbatim, unverified.
     */
    public val localFingerprint: Fingerprint = PLACEHOLDER_FINGERPRINT,
    /** The `m=application` media id (RFC 8829 §5.2.1). */
    public val mid: Mid = Mid("0"),
) {
    public companion object {
        /** A syntactically valid SHA-256 fingerprint placeholder (all-zero) — replaced by W4's real cert. */
        public val PLACEHOLDER_FINGERPRINT: Fingerprint =
            Fingerprint("sha-256", List(32) { "00" }.joinToString(":"))
    }
}

/**
 * The consumer session API (RFC §3.1) — a **Layer-2 session** (`establish` is signaling-shaped, not
 * host:port-shaped, so WebRTC is only ever a session type, never a `Transport.connect`). It is
 * transport-agnostic by shape: a data channel *is* a buffer-flow [Connection]<[ReadBuffer]>
 * ([createDataChannel] / [incomingDataChannels]), so any `StreamMux`-style consumer code runs over it
 * unchanged (DESIGN §7).
 *
 * Descriptions and candidates cross as **SDP text / `candidate:` lines** — the exact currency a browser
 * `RTCPeerConnection` and the SDP wire speak — so the same interface backs both the native stack
 * ([NativePeerConnection]) and the browser delegate, and the app ships them over *its* signaling. Every
 * failure surfaces as [PeerConnectionState.Failed] with a typed [PeerConnectionFailureReason] and, where
 * thrown, a [WebRtcException] in socket's `SocketException` vocabulary (RFC §3.1).
 */
public interface RtcPeerConnection {
    /** The connection lifecycle (W3C `connectionState`). */
    public val connectionState: StateFlow<PeerConnectionState>

    /** The JSEP signaling state (W3C `signalingState`, RFC 8829 §3.5.1). */
    public val signalingState: StateFlow<SignalingState>

    /** Local ICE candidates as they are gathered, as `candidate:` lines to trickle to the peer (onicecandidate). */
    public val localIceCandidates: Flow<String>

    /** Data channels the peer opened (W3C `ondatachannel`). */
    public val incomingDataChannels: Flow<Connection<ReadBuffer>>

    /** Open a data channel (RFC 8832). Returns immediately; the channel becomes live once SCTP is up. */
    public suspend fun createDataChannel(config: DataChannelConfig = DataChannelConfig()): Connection<ReadBuffer>

    /** Generate an SDP offer (RFC 8829). Does not apply it — pass it to [setLocalDescription]. */
    public suspend fun createOffer(): String

    /** Generate an SDP answer to the applied remote offer. Does not apply it — pass it to [setLocalDescription]. */
    public suspend fun createAnswer(): String

    /**
     * Apply a local description (offer/answer/rollback). Throws [IllegalStateException] on an illegal
     * offer/answer transition (W3C `InvalidStateError`) and [IllegalArgumentException] on malformed SDP —
     * signaling-API misuse, distinct from a transport [WebRtcException].
     */
    public suspend fun setLocalDescription(
        type: SdpType,
        sdp: String,
    )

    /** Apply a remote description; extracts the peer's ICE credentials + in-SDP candidates. */
    public suspend fun setRemoteDescription(
        type: SdpType,
        sdp: String,
    )

    /** Add a trickled remote `candidate:` line (RFC 8838). A malformed line is ignored. */
    public suspend fun addIceCandidate(candidate: String)

    /** Close the session and release every socket/stream. Idempotent. */
    public suspend fun close()
}

/**
 * The **native-stack** [RtcPeerConnection] (RFC §1.1: we own the protocol on every non-browser target).
 * It is a driver composing the sans-io cores: the [JsepSession] offer/answer machine (webrtc-sdp), the
 * [IceAgentDriver] (webrtc-ice) over an injected [IceGatheringPolicy], the injected [DtlsTransportFactory]
 * (plaintext while W4 is parked — the same seam W5 proved SCTP over), and the [SctpDataChannelStack]
 * (webrtc-sctp) over the nominated pair. Every seam — [scope], [clock], [random], the network binder
 * inside the gathering policy — is injected, so the whole session replays under `runTest` virtual time
 * (RFC §5.1). Its own mutable negotiation state is confined behind [negotiationLock]; the cores beneath
 * are each internally single-threaded.
 *
 * Roles: the **offerer** is ICE-controlling, the **answerer** ICE-controlled (RFC 8445 §6.1.1). The
 * DTLS role — and thus the SCTP role and DCEP stream-id parity — is **negotiated from `a=setup`** (RFC
 * 8842), not assumed from who offered: the answerer picks the complement of the offer's setup, and the
 * offerer adopts the complement of the answer's, so we don't deadlock against a peer that answers passive
 * or offers active. The real ICE+**DTLS**+SCTP end-to-end is the exit gate once W4 lands; the injected
 * [dtls] factory is the seam DTLS slots in at — pass [PlaintextDtls] explicitly for the W5-proven
 * plaintext stand-in (it is **not** wire-secure; there is deliberately no default, so the insecure choice
 * is greppable at every call site).
 */
public class NativePeerConnection(
    private val scope: CoroutineScope,
    private val clock: () -> Instant,
    random: Random,
    private val binder: com.ditchoom.webrtc.ice.DatagramBinder,
    private val gathering: IceGatheringPolicy,
    private val dtls: DtlsTransportFactory,
    private val config: PeerConnectionConfig = PeerConnectionConfig(),
) : RtcPeerConnection {
    private val random = random
    private val jsep = JsepSession(random)
    private val negotiationLock = Mutex()

    private val _connectionState = MutableStateFlow<PeerConnectionState>(PeerConnectionState.New)
    override val connectionState: StateFlow<PeerConnectionState> get() = _connectionState

    private val _signalingState = MutableStateFlow<SignalingState>(SignalingState.Stable)
    override val signalingState: StateFlow<SignalingState> get() = _signalingState

    private val localCandidateChannel = Channel<String>(Channel.UNLIMITED)
    override val localIceCandidates: Flow<String> get() = localCandidateChannel.receiveAsFlow()

    private val incomingChannels = Channel<Connection<ReadBuffer>>(Channel.UNLIMITED)
    override val incomingDataChannels: Flow<Connection<ReadBuffer>> get() = incomingChannels.receiveAsFlow()

    // Negotiation state — touched only under [negotiationLock].
    private var driver: IceAgentDriver? = null
    private var stack: SctpDataChannelStack? = null
    private var establishJob: Job? = null
    private val pendingChannels = mutableListOf<PendingChannel>()
    private val pendingRemoteCandidates = mutableListOf<String>()
    private var closed = false

    // The remote endpoint's negotiated a=setup (RFC 8842), captured from the peer's description; the DTLS
    // (and hence SCTP) role is derived from it — NOT hardcoded from who offered — so we adopt the role the
    // peer's setup implies (offerer-passive vs offerer-active, answerer-active vs answerer-passive) instead
    // of assuming the browser default and deadlocking against a peer that answers passive / offers active.
    private var remoteSetup: SetupRole? = null

    // Resolved once both descriptions are applied; runEstablishment awaits it before the DTLS handshake.
    private val roleResolved = CompletableDeferred<DtlsRole>()

    // ── RtcPeerConnection ──

    override suspend fun createOffer(): String =
        negotiationLock.withLock {
            val d = startIce(asOfferer = true)
            jsep.createOffer(localParams(d, SetupRole.ActPass)).toText()
        }

    override suspend fun createAnswer(): String =
        negotiationLock.withLock {
            val d = driver ?: startIce(asOfferer = false)
            // The answerer chooses the a=setup that complements the offer's (RFC 8842 §5.1.2): an
            // actpass/passive offer → we are active (DTLS/SCTP client); an active offer → we are passive
            // (server). The chosen setup goes into the answer AND fixes our role.
            val ourSetup =
                when (remoteSetup) {
                    SetupRole.Active -> SetupRole.Passive
                    else -> SetupRole.Active
                }
            resolveRole(ourSetup == SetupRole.Active)
            jsep.createAnswer(localParams(d, ourSetup)).toText()
        }

    override suspend fun setLocalDescription(
        type: SdpType,
        sdp: String,
    ) = negotiationLock.withLock {
        val description = if (type == SdpType.Rollback) null else parseOrThrow(sdp)
        applyJsep(JsepEvent.SetLocalDescription(type, description))
    }

    override suspend fun setRemoteDescription(
        type: SdpType,
        sdp: String,
    ) = negotiationLock.withLock {
        val description = if (type == SdpType.Rollback) null else parseOrThrow(sdp)
        // A remote offer arriving first makes us the answerer — start ICE (controlled) before applying it.
        if (type == SdpType.Offer && driver == null) startIce(asOfferer = false)
        applyJsep(JsepEvent.SetRemoteDescription(type, description))
        if (description != null) ingestRemote(description)
        // A remote ANSWER fixes the offerer's role: the answer's setup names the peer's role, so we take
        // its complement (answer active → peer is client → we are server; answer passive → we are client).
        if (type == SdpType.Answer) resolveRole(asClient = remoteSetup != SetupRole.Active)
    }

    // Resolve our DTLS/SCTP role exactly once (idempotent); runEstablishment awaits it.
    private fun resolveRole(asClient: Boolean) {
        roleResolved.complete(if (asClient) DtlsRole.Client else DtlsRole.Server)
    }

    override suspend fun addIceCandidate(candidate: String): Unit =
        negotiationLock.withLock {
            val d = driver
            if (d == null) {
                pendingRemoteCandidates += candidate
            } else {
                IceCandidateLine.parse(candidate)?.let(d::addRemoteCandidate)
            }
        }

    override suspend fun createDataChannel(config: DataChannelConfig): Connection<ReadBuffer> =
        negotiationLock.withLock {
            if (closed) throw SctpClosedException(null)
            val live = stack
            if (live != null) return@withLock live.open(config)
            // SCTP is not up yet (the offerer creates channels before negotiating) — hand back a proxy
            // that binds to the real channel once the stack establishes.
            val pending = PendingChannel(config)
            pendingChannels += pending
            pending
        }

    override suspend fun close(): Unit =
        negotiationLock.withLock {
            if (closed) return@withLock
            closed = true
            jsep.handle(JsepEvent.Close, clock())
            // Cancel the establishment coroutine so a session closed before ICE nomination doesn't leak it
            // suspended on d.state forever (IceAgentDriver.close emits no terminal state).
            establishJob?.cancel()
            roleResolved.cancel() // unblock any runEstablishment awaiting the role
            stack?.shutdown()
            driver?.close()
            localCandidateChannel.close()
            incomingChannels.close()
            for (pending in pendingChannels) pending.fail(SctpClosedException(null))
            pendingChannels.clear()
            _connectionState.value = PeerConnectionState.Closed
        }

    // ── composition ──

    // Construct + launch the ICE driver for our resolved role, wire trickle-out and the establishment
    // progression, and flush any candidates that arrived early. Idempotent (returns the existing driver).
    private fun startIce(asOfferer: Boolean): IceAgentDriver {
        driver?.let { return it }
        val iceRole = if (asOfferer) IceRole.Controlling else IceRole.Controlled
        val sctpRandom = Random(random.nextLong())
        val d = IceAgentDriver(iceRole, random, binder, scope, clock, config.iceConfig)
        driver = d
        d.start()
        _connectionState.value = PeerConnectionState.Connecting
        scope.launch { gathering.gather(d) }
        scope.launch {
            d.localCandidateGathered.collect { localCandidateChannel.trySend(IceCandidateLine.format(it)) }
        }
        establishJob = scope.launch { runEstablishment(d, sctpRandom) }
        for (line in pendingRemoteCandidates) IceCandidateLine.parse(line)?.let(d::addRemoteCandidate)
        pendingRemoteCandidates.clear()
        return d
    }

    // Await ICE nomination, secure the app-data seam with DTLS (plaintext for now), bring up the SCTP
    // data-channel stack, open every queued data channel, then watch for a post-Connected loss. The
    // liveness invariant (RFC §5.3 #5): the session reaches Connected or a typed terminal failure, never
    // hangs — so the whole body is guarded and a DTLS/SCTP-establishment throw becomes a typed Failed.
    private suspend fun runEstablishment(
        d: IceAgentDriver,
        sctpRandom: Random,
    ) {
        try {
            val terminal =
                d.state.first {
                    it is IceConnectionState.Connected || it is IceConnectionState.Completed || it is IceConnectionState.Failed
                }
            if (terminal is IceConnectionState.Failed) {
                fail(PeerConnectionFailureReason.Ice(terminal.reason))
                return
            }
            val dtlsRole = roleResolved.await()
            val transport = dtls.secure(d.appDataTransport(), dtlsRole)
            val sctpRole = if (dtlsRole == DtlsRole.Client) SctpRole.Client else SctpRole.Server
            val liveStack =
                SctpDataChannelStack(transport, scope, clock, sctpRole, config.sctpConfig, sctpRandom).also { it.start() }

            negotiationLock.withLock {
                if (closed) {
                    liveStack.shutdown()
                    return
                }
                stack = liveStack
                for (pending in pendingChannels) scope.launch { pending.bind(liveStack) }
                pendingChannels.clear()
            }

            // Declare Connected only once SCTP has actually established (the data-channel transport is
            // usable) — not merely because ICE nominated a pair. The stack's *initial* state is Closed, so
            // first wait for the handshake to get underway (leave Closed), then for it to resolve to
            // Established or tear back down; a pre-Established teardown is a typed failure, never a hang.
            liveStack.state.first { it != SctpAssociationState.Closed }
            liveStack.state.first { it == SctpAssociationState.Established || it == SctpAssociationState.Closed }
            if (closed) return
            if (liveStack.state.value != SctpAssociationState.Established) {
                fail(PeerConnectionFailureReason.Sctp(SctpFailureReason.HandshakeTimeout))
                return
            }
            _connectionState.value = PeerConnectionState.Connected(d.selectedPair)

            // Structured children of this coroutine (cancelled by close() → establishJob.cancel), so no
            // monitor leaks: forward incoming channels, and surface a post-Connected loss as a terminal
            // state (RFC 7675 consent expiry → Failed(Ice); SCTP teardown → Closed, its typed reason
            // already delivered to the data-channel caller as SctpClosedException).
            coroutineScope {
                launch {
                    try {
                        while (true) incomingChannels.trySend(liveStack.acceptBidirectional())
                    } catch (_: kotlinx.coroutines.channels.ClosedReceiveChannelException) {
                        // stack closed — no more incoming channels
                    }
                }
                launch {
                    val lost = d.state.first { it is IceConnectionState.Failed } as IceConnectionState.Failed
                    if (!closed) fail(PeerConnectionFailureReason.Ice(lost.reason))
                }
                launch {
                    liveStack.state.first { it == SctpAssociationState.Closed }
                    if (!closed && _connectionState.value is PeerConnectionState.Connected) {
                        _connectionState.value = PeerConnectionState.Closed
                    }
                }
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e // close() cancelled us — structured cancellation, not a failure
        } catch (e: WebRtcException) {
            fail(e.failure) // a real DTLS/SCTP-establishment failure (W4) — typed, never a hang
        } catch (e: Exception) {
            fail(PeerConnectionFailureReason.Unknown(e.message ?: e::class.simpleName ?: "establishment error"))
        }
    }

    // Set a terminal Failed state once, only if not already terminal (the first cause wins; a later monitor
    // must not overwrite it).
    private fun fail(reason: PeerConnectionFailureReason) {
        val current = _connectionState.value
        if (current !is PeerConnectionState.Failed && current !is PeerConnectionState.Closed) {
            _connectionState.value = PeerConnectionState.Failed(reason)
        }
    }

    // Apply a JSEP event; a rejected transition is a signaling-API misuse (W3C throws InvalidStateError),
    // modeled as an IllegalStateException carrying the typed JsepError — not a transport failure. The
    // signaling state flow is updated on every accepted change.
    private fun applyJsep(event: JsepEvent) {
        for (output in jsep.handle(event, clock())) {
            when (output) {
                is JsepOutput.Rejected -> throw JsepStateException(output.error)
                is JsepOutput.SignalingStateChanged -> _signalingState.value = output.to
                is JsepOutput.DescriptionApplied -> Unit
            }
        }
    }

    // Pull the peer's ICE credentials + any in-SDP (non-trickle) candidates out of a remote description.
    private fun ingestRemote(description: SessionDescription) {
        val media = description.mediaDescriptions.firstOrNull()
        val ufrag = media?.iceUfrag() ?: description.iceUfrag()
        val pwd = media?.icePwd() ?: description.icePwd()
        if (ufrag != null && pwd != null) {
            driver?.setRemoteCredentials(IceCredentials(Ufrag(ufrag), IcePassword(pwd)))
        }
        // The peer's negotiated DTLS role (RFC 8842) — used to derive our own role (see resolveRole).
        remoteSetup = media?.setup() ?: description.setup()
        media?.candidates()?.forEach { line -> IceCandidateLine.parse(line)?.let { driver?.addRemoteCandidate(it) } }
    }

    private fun localParams(
        d: IceAgentDriver,
        setup: SetupRole,
    ): DataChannelParameters =
        DataChannelParameters(
            iceUfrag = d.localCredentials.ufrag.value,
            icePwd = d.localCredentials.password.value,
            fingerprint = config.localFingerprint,
            setup = setup,
            mid = config.mid,
        )

    private fun parseOrThrow(sdp: String): SessionDescription =
        when (val result = SessionDescription.parseText(sdp)) {
            is SdpParseResult.Success -> result.description
            is SdpParseResult.Reject -> throw SdpFormatException(result.reason)
        }

    // A data channel handed back before SCTP is up: proxies to the real channel once [bind] completes.
    private inner class PendingChannel(
        val config: DataChannelConfig,
    ) : Connection<ReadBuffer> {
        private val real = CompletableDeferred<Connection<ReadBuffer>>()

        override val id: Long get() = if (real.isCompleted && !real.isCancelled) real.getCompleted().id else -1L

        override suspend fun send(message: ReadBuffer) = real.await().send(message)

        override fun receive(): Flow<ReadBuffer> = flow { emitAll(real.await().receive()) }

        override suspend fun close() {
            if (real.isCompleted && !real.isCancelled) {
                real.getCompleted().close()
            } else {
                // Not bound yet — fail the deferred so an awaiting send/receive unblocks, and so a bind
                // that races in afterward sees `real` already completed and closes the channel it opened
                // (rather than leaking a live DCEP-OPENed channel with no local owner).
                real.completeExceptionally(SctpClosedException(null))
            }
        }

        suspend fun bind(liveStack: SctpDataChannelStack) {
            try {
                val connection = liveStack.open(config)
                // If the proxy was closed before we bound, `complete` returns false — close the channel we
                // just opened so it isn't leaked on the association.
                if (!real.complete(connection)) connection.close()
            } catch (e: Exception) {
                // open() failed (e.g. the stack tore down in the race window) — unblock awaiters typed,
                // never hang them on a deferred that will never complete.
                real.completeExceptionally(e)
            }
        }

        fun fail(cause: Throwable) {
            real.completeExceptionally(cause)
        }
    }
}

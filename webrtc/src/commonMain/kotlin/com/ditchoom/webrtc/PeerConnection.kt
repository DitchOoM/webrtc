@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.webrtc.dtls.DtlsFailureReason
import com.ditchoom.webrtc.ice.CandidateParse
import com.ditchoom.webrtc.ice.IceAgentDriver
import com.ditchoom.webrtc.ice.IceCandidateLine
import com.ditchoom.webrtc.ice.IceConfig
import com.ditchoom.webrtc.ice.IceConnectionState
import com.ditchoom.webrtc.ice.IceCredentials
import com.ditchoom.webrtc.ice.IcePassword
import com.ditchoom.webrtc.ice.IcePath
import com.ditchoom.webrtc.ice.IceRole
import com.ditchoom.webrtc.ice.MdnsResolution
import com.ditchoom.webrtc.ice.MdnsResolver
import com.ditchoom.webrtc.ice.NetworkMonitor
import com.ditchoom.webrtc.ice.Ufrag
import com.ditchoom.webrtc.ice.resolveHostCandidate
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
import com.ditchoom.webrtc.sdp.fingerprints
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
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * How the [NativePeerConnection] gathers local ICE candidates — the seam over "which sockets to bind"
 * (RFC §5.2: gathering rides an injected driver). A test supplies host addresses over the vnet
 * (`{ it.gatherHost("10.0.0.1", 5000) }`); a production policy enumerates interfaces via socket's
 * `NetworkMonitor` and adds srflx/relay from the configured ICE servers (the real-UDP default lands with
 * the platform edge in W7).
 *
 * It runs **once per ICE generation** — when negotiation starts, and again on every ICE restart (RFC 8445
 * §9), which exists precisely because the interfaces may have changed underneath the session. A policy
 * that pins fixed ports must therefore hand out a fresh one each call: the outgoing generation's sockets
 * stay bound until the new generation nominates, and an OS will not re-bind an address still in use.
 */
public fun interface IceGatheringPolicy {
    /** Gather candidates on [driver] (host/srflx/relay) — each gathered candidate trickles out. */
    public suspend fun gather(driver: IceAgentDriver)
}

/**
 * When a [NativePeerConnection] restarts ICE by itself (RFC 8445 §9). A sealed choice rather than a
 * `Boolean` plus a nullable monitor, which could encode "automatic restarts enabled, nothing to watch".
 *
 * The monitor is the **webrtc-owned** [NetworkMonitor] seam, not socket's: neither `webrtc` nor
 * `webrtc-ice` `commonMain` depends on socket at all (they target `buffer-flow` only, so the cores stay
 * all-platform including browsers), and socket's monitor lives in socket *core*, which vendors a second
 * BoringSSL — the documented duplicate-symbol break that already defers the `SocketException` bridge.
 */
public sealed interface IceRestartPolicy {
    /** Only an explicit [RtcPeerConnection.restartIce] restarts. The default, and the browser's behaviour. */
    public data object Manual : IceRestartPolicy

    /**
     * Watch [monitor] and restart automatically when the interface carrying the **selected pair's base**
     * leaves the set — deliberately narrow. A blanket restart on *any* change would churn a perfectly
     * healthy session every time a VPN or virtual adapter appears.
     *
     * Automatic and manual restarts route through the same intent path, and the monitor is injected, so
     * a Wi-Fi→cellular flip is a scripted timeline event under `runTest` rather than a real radio.
     */
    public data class OnNetworkChange(
        public val monitor: NetworkMonitor,
    ) : IceRestartPolicy
}

/**
 * Static configuration for a [NativePeerConnection] (W3C `RTCConfiguration`, the subset we honor).
 *
 * The local `a=fingerprint` is deliberately **not** here: certificate identity belongs to the DTLS
 * factory that holds the certificate ([DtlsTransportFactory.localFingerprint]), so advertising a digest
 * other than the one we present is unrepresentable rather than merely discouraged (DESIGN §4).
 */
public data class PeerConnectionConfig(
    public val iceConfig: IceConfig = IceConfig(),
    public val sctpConfig: SctpConfig = SctpConfig(),
    /**
     * The media id of the **data-channel** `m=application` section (RFC 8829 §5.2.1).
     *
     * Named for its section rather than being the bare `mid`: a session has one mid *per* m-section, so
     * once Phase 2 adds `m=audio`/`m=video` an unqualified `mid` on the session config would be
     * ambiguous about which section it identifies. It is the data channel's, and always was.
     */
    public val dataChannelMid: Mid = Mid("0"),
    /**
     * Resolves a peer's `<uuid>.local` mDNS host candidate (RFC 8838 privacy) to an address before a
     * connectivity check is sent to it. The `commonMain` default is a **no-op** — it resolves nothing, so
     * a `.local` candidate is simply dropped (the safe prior behaviour, and correct where no multicast
     * responder exists). Platform `peerConnectionSupport()` factories inject a real multicast resolver;
     * tests inject a deterministic stub. Never a hardwired `224.0.0.251` socket in the session core.
     */
    public val mdnsResolver: MdnsResolver = MdnsResolver { MdnsResolution.Unresolved },
    /**
     * How long [RtcPeerConnection.close] lets an ESTABLISHED SCTP association finish its graceful shutdown
     * (RFC 4960 §9.2 SHUTDOWN → SHUTDOWN-ACK → SHUTDOWN-COMPLETE) before the ICE transport underneath it is
     * torn down. Without the wait the SHUTDOWN chunk is merely *queued* on the drive loop while `close()`
     * shuts the socket, so the peer sees the association simply vanish — indistinguishable from a crash —
     * instead of a clean close (W3C `close()` and every browser send it).
     *
     * A watchdog on observable state, not a budget: the wait ends the instant the association reports
     * Closed, and is skipped entirely when there is nothing established to shut down. Set it to
     * [Duration.ZERO] for an immediate teardown.
     */
    public val gracefulShutdownTimeout: Duration = 2.seconds,
    /**
     * Whether the session restarts ICE on its own when the network moves under it (RFC 8445 §9).
     * Defaults to [IceRestartPolicy.Manual] — the browser's behaviour, and the only honest default while
     * no target ships a production [NetworkMonitor] actual enumerating real OS interfaces.
     */
    public val iceRestartPolicy: IceRestartPolicy = IceRestartPolicy.Manual,
)

/**
 * Opt-in marker for IMPLEMENTING [RtcPeerConnection] outside this library.
 *
 * Sealing would be the natural expression of "we own every implementation", and every implementation
 * really is ours — but Kotlin treats each multiplatform source set as its own module, so a `commonMain`
 * sealed interface cannot be implemented by `BrowserPeerConnection` in `jsMain`. This marker is the
 * equivalent that does work across source sets: nobody implements the interface by accident, and anyone
 * who opts in has accepted that Phase 2 adds members to it (media: `addTrack`, incoming tracks,
 * transceivers). USING an RtcPeerConnection needs no opt-in — only implementing one does.
 */
@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message =
        "Implementing RtcPeerConnection outside com.ditchoom:webrtc is not a stable contract: Phase 2 " +
            "(media) adds members to it, which will break external implementations. Prefer wrapping an " +
            "existing implementation, or the harnesses in webrtc-testsuite.",
)
public annotation class ExternalRtcPeerConnectionImplementation

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

@SubclassOptInRequired(ExternalRtcPeerConnectionImplementation::class)
public interface RtcPeerConnection {
    /** The connection lifecycle (W3C `connectionState`). */
    public val connectionState: StateFlow<PeerConnectionState>

    /** The JSEP signaling state (W3C `signalingState`, RFC 8829 §3.5.1). */
    public val signalingState: StateFlow<SignalingState>

    /** Local ICE candidates as they are gathered, as `candidate:` lines to trickle to the peer (onicecandidate). */
    public val localIceCandidates: Flow<String>

    /** Data channels the peer opened (W3C `ondatachannel`). */
    public val incomingDataChannels: Flow<Connection<ReadBuffer>>

    /**
     * Fires when the session needs the app to run a new offer/answer round (W3C `negotiationneeded`).
     *
     * A session cannot renegotiate on its own — it does not own the signaling channel — so anything that
     * makes renegotiation necessary has to be *told* to the app or it simply never happens. Today that is
     * [restartIce] and an [IceRestartPolicy.OnNetworkChange] detecting the selected pair's interface going
     * away; without this the automatic policy would record an intent into a field nobody reads.
     *
     * Conflated: what matters is that a round is owed, not how many times it became owed.
     */
    public val renegotiationNeeded: Flow<Unit>

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

    /**
     * Request an ICE restart (W3C `restartIce()`, RFC 8445 §9). Records the intent; the **next**
     * [createOffer] carries fresh ICE credentials and re-gathered candidates. Deferred rather than
     * immediate so the native stack and the browser delegate mean the same thing by the same name.
     *
     * The session survives it: DTLS and SCTP are untouched, every open data channel stays open, and data
     * keeps flowing on the existing pair while the new one converges — the session state passes through
     * [PeerConnectionState.Restarting] and back to [PeerConnectionState.Connected] on the new pair.
     */
    public suspend fun restartIce()

    /** Close the session and release every socket/stream. Idempotent. */
    public suspend fun close()
}

/**
 * The **native-stack** [RtcPeerConnection] (RFC §1.1: we own the protocol on every non-browser target).
 * It is a driver composing the sans-io cores: the [JsepSession] offer/answer machine (webrtc-sdp), the
 * [IceAgentDriver] (webrtc-ice) over an injected [IceGatheringPolicy], the injected [DtlsTransportFactory]
 * ([PureKotlinDtls] on any non-browser target), and the [SctpDataChannelStack]
 * (webrtc-sctp) over the nominated pair. Every seam — [scope], [clock], [random], the network binder
 * inside the gathering policy — is injected, so the whole session replays under `runTest` virtual time
 * (RFC §5.1). Its own mutable negotiation state is confined behind [negotiationLock]; the cores beneath
 * are each internally single-threaded.
 *
 * Roles: the **offerer** is ICE-controlling, the **answerer** ICE-controlled (RFC 8445 §6.1.1). The
 * DTLS role — and thus the SCTP role and DCEP stream-id parity — is **negotiated from `a=setup`** (RFC
 * 8842), not assumed from who offered: the answerer picks the complement of the offer's setup, and the
 * offerer adopts the complement of the answer's, so we don't deadlock against a peer that answers passive
 * or offers active.
 *
 * The injected [dtls] factory is both the security boundary and the endpoint's certificate identity:
 * pass [PureKotlinDtls] for real DTLS (every non-browser target — the engine is pure Kotlin), or
 * [PlaintextDtls] for the W5-proven
 * plaintext stand-in — which is **not** wire-secure. There is deliberately no default, so the insecure
 * choice is greppable at every call site.
 */
@OptIn(ExternalRtcPeerConnectionImplementation::class)
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

    private val renegotiationChannel = Channel<Unit>(Channel.CONFLATED)
    override val renegotiationNeeded: Flow<Unit> get() = renegotiationChannel.receiveAsFlow()

    // Negotiation state — touched only under [negotiationLock].
    //
    // Every field a renegotiation touches is a sealed case rather than a nullable, because on the restart
    // path each of these nulls was about to acquire a second meaning ("not yet" vs "not any more"), and a
    // null that means two things is read correctly at some call sites and not at others.
    private var transport: IceTransport = IceTransport.NotStarted
    private var dataChannels: DataChannelStack = DataChannelStack.NotUp
    private var establishJob: Job? = null
    private val pendingChannels = mutableListOf<PendingChannel>()
    private val pendingRemoteCandidates = mutableListOf<String>()
    private var closed = false

    // What the next createOffer() must produce: a plain re-offer, or one carrying a fresh ICE generation.
    private var negotiationIntent: NegotiationIntent = NegotiationIntent.Fresh

    // The remote endpoint's negotiated a=setup (RFC 8842), captured from the peer's description; the DTLS
    // (and hence SCTP) role is derived from it — NOT hardcoded from who offered — so we adopt the role the
    // peer's setup implies (offerer-passive vs offerer-active, answerer-active vs answerer-passive) instead
    // of assuming the browser default and deadlocking against a peer that answers passive / offers active.
    private var remoteSetup: RemoteSetup = RemoteSetup.NotDeclared

    // The peer's a=fingerprint (RFC 8122), captured from its description. DTLS verifies the certificate
    // the peer presents against exactly this — it is the only thing binding the signaling channel we
    // trust to the data path we don't, so a session whose SDP carried none is refused, never trusted.
    private var remoteFingerprint: RemoteFingerprint = RemoteFingerprint.NotDeclared

    // The peer's ICE credentials as last signaled. Kept (rather than merely forwarded to the driver)
    // because a *change* in both ufrag and pwd is precisely how a peer announces its own ICE restart
    // (RFC 8445 §9) — and there is nothing to compare against if we never remembered the previous pair.
    private var remoteIceCredentials: RemoteIceCredentials = RemoteIceCredentials.NotReceived

    // Resolved once both descriptions are applied; runEstablishment awaits it before the DTLS handshake.
    // Completing exactly once is what pins the DTLS role for the association's lifetime, so a
    // renegotiation cannot flip client/server underneath a live handshake (RFC 8842 §5.5).
    private val roleResolved = CompletableDeferred<DtlsRole>()

    // ── RtcPeerConnection ──

    override suspend fun createOffer(): String =
        negotiationLock.withLock {
            val d = startIce(asOfferer = true)
            // RFC 8842 §5.5: an offerer that does not want a NEW DTLS association still re-offers
            // `a=setup:actpass` — continuity is signaled by the UNCHANGED fingerprint, not by the setup
            // value — and `localParams` always advertises the certificate the factory actually holds. So a
            // restart re-offer needs no DTLS handling at all beyond not disturbing it.
            when (negotiationIntent) {
                NegotiationIntent.Fresh -> Unit
                NegotiationIntent.IceRestart -> applyIceRestart(d)
            }
            jsep.createOffer(localParams(d, SetupRole.ActPass)).toText()
        }

    override suspend fun createAnswer(): String =
        negotiationLock.withLock {
            val d = startedTransport() ?: startIce(asOfferer = false)
            // The answerer chooses the a=setup that complements the offer's (RFC 8842 §5.1.2): an
            // actpass/passive offer → we are active (DTLS/SCTP client); an active offer → we are passive
            // (server). The chosen setup goes into the answer AND fixes our role.
            val ourSetup =
                when (val declared = remoteSetup) {
                    is RemoteSetup.Declared -> if (declared.role == SetupRole.Active) SetupRole.Passive else SetupRole.Active
                    RemoteSetup.NotDeclared -> SetupRole.Active
                }
            resolveRole(ourSetup == SetupRole.Active)
            jsep.createAnswer(localParams(d, ourSetup)).toText()
        }

    override suspend fun restartIce(): Unit =
        negotiationLock.withLock {
            // W3C-faithful: record the intent, let the next createOffer() carry it out. The deferred shape
            // is what lets the browser delegate map 1:1 onto pc.restartIce() instead of approximating it.
            requestIceRestart()
        }

    /**
     * Perform the restart the intent asked for: swap the agent's ICE generation and re-gather onto the new
     * one. Awaiting the swap is load-bearing — [IceEvent.Restart][com.ditchoom.webrtc.ice.IceEvent.Restart]
     * rides the driver's serialized inbox, so credentials read straight after a bare `restart()` are the
     * *old* ones and the offer we are about to build from them would advertise credentials the agent no
     * longer honours.
     */
    private suspend fun applyIceRestart(d: IceAgentDriver) {
        negotiationIntent = NegotiationIntent.Fresh
        d.restartAndAwait()
        // Once per ICE generation, not once per session: a restart exists precisely because the interfaces
        // may have changed underneath us. The outgoing generation's sockets stay bound (and carrying data)
        // until the new generation nominates, so this never re-binds an address it is still using.
        scope.launch { gathering.gather(d) }
    }

    override suspend fun setLocalDescription(
        type: SdpType,
        sdp: String,
    ) = negotiationLock.withLock {
        val description = if (type == SdpType.Rollback) null else parseOrThrow(sdp)
        applyJsep(JsepEvent.SetLocalDescription(type, description))
        // Rollback discards the local offer, so the ICE generation that offer advertised must go with it —
        // otherwise the agent is left honouring credentials no peer has ever seen. JSEP's
        // HaveLocalOffer → Stable edge already existed; this is its ICE half.
        if (type == SdpType.Rollback) startedTransport()?.rollbackRestart()
    }

    override suspend fun setRemoteDescription(
        type: SdpType,
        sdp: String,
    ) = negotiationLock.withLock {
        val description = if (type == SdpType.Rollback) null else parseOrThrow(sdp)
        // A remote offer arriving first makes us the answerer — start ICE (controlled) before applying it.
        if (type == SdpType.Offer && transport is IceTransport.NotStarted) startIce(asOfferer = false)
        applyJsep(JsepEvent.SetRemoteDescription(type, description))
        if (description != null) ingestRemote(type, description)
        // A remote ANSWER fixes the offerer's role: the answer's setup names the peer's role, so we take
        // its complement (answer active → peer is client → we are server; answer passive → we are client).
        if (type == SdpType.Answer) resolveRole(asClient = !remoteSetupIsActive())
    }

    private fun remoteSetupIsActive(): Boolean =
        when (val declared = remoteSetup) {
            is RemoteSetup.Declared -> declared.role == SetupRole.Active
            RemoteSetup.NotDeclared -> false
        }

    /**
     * Resolve our DTLS/SCTP role. The first resolution wins and pins the role for the association's
     * lifetime; a *later* description implying the opposite role is a peer asking for a new DTLS
     * association on renegotiation, which we do not support (RFC 8842 §5.5 — an endpoint that wants
     * continuity keeps its fingerprint and re-offers `actpass`). Refuse it with a typed reason instead of
     * silently ignoring it, which would leave the peer handshaking against a role we never adopted.
     */
    private fun resolveRole(asClient: Boolean) {
        val role = if (asClient) DtlsRole.Client else DtlsRole.Server
        if (roleResolved.complete(role)) return
        if (roleResolved.isCompleted && !roleResolved.isCancelled && roleResolved.getCompleted() != role) {
            fail(PeerConnectionFailureReason.Dtls(DtlsFailureReason.RoleChangeOnRenegotiation))
        }
    }

    override suspend fun addIceCandidate(candidate: String): Unit =
        negotiationLock.withLock {
            when (val current = transport) {
                IceTransport.NotStarted -> pendingRemoteCandidates += candidate
                is IceTransport.Started -> addRemoteCandidateLine(current.driver, candidate)
            }
        }

    // Route a remote candidate line to the ICE driver, resolving an `<uuid>.local` mDNS host (RFC 8838
    // privacy) via the injected [PeerConnectionConfig.mdnsResolver] first. The IP path adds synchronously
    // (unchanged behaviour); only the mDNS path is launched — a multicast resolution round-trip must not
    // block negotiation, and trickle candidates arrive asynchronously by nature. An unresolved `.local`
    // (no responder) or a malformed line is silently dropped, exactly as before.
    private fun addRemoteCandidateLine(
        d: IceAgentDriver,
        line: String,
    ) {
        when (val parsed = IceCandidateLine.parseLine(line)) {
            is CandidateParse.Parsed -> d.addRemoteCandidate(parsed.candidate)
            is CandidateParse.MdnsHost ->
                scope.launch { config.mdnsResolver.resolveHostCandidate(parsed)?.let(d::addRemoteCandidate) }
            CandidateParse.Reject -> Unit
        }
    }

    override suspend fun createDataChannel(config: DataChannelConfig): Connection<ReadBuffer> =
        negotiationLock.withLock {
            if (closed) throw SctpClosedException(null)
            when (val channels = dataChannels) {
                is DataChannelStack.Up -> channels.stack.open(config)
                // SCTP is not up yet (the offerer creates channels before negotiating) — hand back a proxy
                // that binds to the real channel once the stack establishes.
                DataChannelStack.NotUp -> PendingChannel(config).also { pendingChannels += it }
            }
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
            // Graceful association teardown (RFC 4960 §9.2) BEFORE the transport under it disappears:
            // `shutdown()` only posts the request to the stack's drive loop, so closing the ICE driver in
            // the same breath would pull the socket out from under the SHUTDOWN chunk and the peer would
            // see the association vanish rather than close. Bounded by
            // [PeerConnectionConfig.gracefulShutdownTimeout] and skipped unless something is established,
            // so `close()` still never hangs.
            val live = (dataChannels as? DataChannelStack.Up)?.stack
            if (live != null) {
                live.shutdown()
                // Wait only where a shutdown can actually complete: an established association, or one
                // already mid-shutdown (our own request may have been processed before this check). A
                // handshake that never finished has nothing to shut down gracefully, so waiting there
                // would just add the timeout to every failed session's teardown.
                val shuttingDown =
                    when (live.state.value) {
                        SctpAssociationState.Established,
                        SctpAssociationState.ShutdownPending,
                        SctpAssociationState.ShutdownSent,
                        SctpAssociationState.ShutdownReceived,
                        SctpAssociationState.ShutdownAckSent,
                        -> true
                        else -> false
                    }
                if (shuttingDown && config.gracefulShutdownTimeout > Duration.ZERO) {
                    withTimeoutOrNull(config.gracefulShutdownTimeout) {
                        live.state.first { it == SctpAssociationState.Closed }
                    }
                }
            }
            startedTransport()?.close()
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
        startedTransport()?.let { return it }
        val iceRole = if (asOfferer) IceRole.Controlling else IceRole.Controlled
        val sctpRandom = Random(random.nextLong())
        val d = IceAgentDriver(iceRole, random, binder, scope, clock, config.iceConfig)
        transport = IceTransport.Started(d)
        d.start()
        _connectionState.value = PeerConnectionState.Connecting
        scope.launch { gathering.gather(d) }
        scope.launch {
            d.localCandidateGathered.collect { localCandidateChannel.trySend(IceCandidateLine.format(it)) }
        }
        establishJob = scope.launch { runEstablishment(d, sctpRandom) }
        when (val policy = config.iceRestartPolicy) {
            IceRestartPolicy.Manual -> Unit
            is IceRestartPolicy.OnNetworkChange -> scope.launch { watchNetwork(d, policy.monitor) }
        }
        for (line in pendingRemoteCandidates) addRemoteCandidateLine(d, line)
        pendingRemoteCandidates.clear()
        return d
    }

    private fun startedTransport(): IceAgentDriver? = (transport as? IceTransport.Started)?.driver

    /**
     * Restart automatically when the interface carrying the *current* path's base goes away — and only
     * then. Restarting on any interface-set change would churn a healthy session every time a VPN or
     * virtual adapter appears; restarting on none of them is the manual policy.
     *
     * It routes through the same [negotiationIntent] the explicit API sets, so automatic and manual
     * restarts are one code path and both still wait for the app to drive the offer/answer round —
     * a session cannot renegotiate without its signaling channel, whoever noticed the change.
     */
    private suspend fun watchNetwork(
        d: IceAgentDriver,
        monitor: NetworkMonitor,
    ) {
        monitor.changes.collect { interfaces ->
            if (d.pathRidesOneOf(interfaces)) return@collect
            negotiationLock.withLock { requestIceRestart() }
        }
    }

    // Record the intent and tell the app it must run an offer/answer round. Both halves matter: without
    // the intent nothing restarts, and without the signal an automatically-detected network change would
    // sit in a field no caller ever reads. Callers of restartIce() get it too — harmless for them, and it
    // means one rule ("renegotiate when this fires") rather than two.
    private fun requestIceRestart() {
        negotiationIntent = NegotiationIntent.IceRestart
        renegotiationChannel.trySend(Unit)
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
            // A peer that advertised no a=fingerprint cannot be verified, so it is refused with a typed
            // reason (RFC 8827) rather than connected to insecurely or left to hang.
            val peerFingerprint =
                when (val declared = negotiationLock.withLock { remoteFingerprint }) {
                    is RemoteFingerprint.Declared -> declared.fingerprint
                    RemoteFingerprint.NotDeclared -> {
                        fail(PeerConnectionFailureReason.Dtls(DtlsFailureReason.FingerprintMissing))
                        return
                    }
                }
            val transport = dtls.secure(d.appDataTransport(), dtlsRole, peerFingerprint)
            val sctpRole = if (dtlsRole == DtlsRole.Client) SctpRole.Client else SctpRole.Server
            val liveStack =
                SctpDataChannelStack(transport, scope, clock, sctpRole, config.sctpConfig, sctpRandom).also { it.start() }

            negotiationLock.withLock {
                if (closed) {
                    liveStack.shutdown()
                    return
                }
                dataChannels = DataChannelStack.Up(liveStack)
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
            _connectionState.value = PeerConnectionState.Connected(sessionPath(d.path.value))

            monitorLiveSession(d, liveStack)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e // close() cancelled us — structured cancellation, not a failure
        } catch (e: WebRtcException) {
            fail(e.failure) // a real DTLS/SCTP-establishment failure (W4) — typed, never a hang
        } catch (e: Exception) {
            fail(PeerConnectionFailureReason.Unknown(e.message ?: e::class.simpleName ?: "establishment error"))
        }
    }

    /**
     * Watch a *live* session until something ends it. Structured children of the establishment coroutine
     * (cancelled by close() → establishJob.cancel), so no monitor outlives the session that owns it.
     *
     * Extracted from [runEstablishment] rather than left inline: establishment is a linear sequence that
     * ends here, and these four are a concurrent set that begins here — one function doing both was the
     * thing that made it hard to see that the ICE path was never being watched at all.
     */
    private suspend fun monitorLiveSession(
        d: IceAgentDriver,
        liveStack: SctpDataChannelStack,
    ) {
        coroutineScope {
            // The ICE path moving mid-session is exactly what an RFC 8445 §9 restart does, and until
            // now nothing above ICE could see it: `runEstablishment` awaited nomination once and then
            // never looked again. Note this monitor *only* maps a live session's path — it never
            // resurrects a Failed or Closed session, so the terminal-state monitors below still win.
            launch {
                d.path.collect { path ->
                    val live = _connectionState.value
                    if (live !is PeerConnectionState.Connected && live !is PeerConnectionState.Restarting) return@collect
                    _connectionState.value =
                        when (path) {
                            // Nothing nominated in either generation — the pair is gone, not moved. The
                            // ICE failure monitor owns that terminal; do not pre-empt it with a guess.
                            IcePath.Unnominated -> return@collect
                            is IcePath.Nominated -> PeerConnectionState.Connected(SelectedPath.Known(path.pair))
                            is IcePath.Restarting -> PeerConnectionState.Restarting(SelectedPath.Known(path.previous))
                        }
                }
            }
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
    private suspend fun ingestRemote(
        type: SdpType,
        description: SessionDescription,
    ) {
        val media = description.mediaDescriptions.firstOrNull()
        val ufrag = media?.iceUfrag() ?: description.iceUfrag()
        val pwd = media?.icePwd() ?: description.icePwd()
        val d = startedTransport()
        if (ufrag != null && pwd != null) {
            val incoming = IceCredentials(Ufrag(ufrag), IcePassword(pwd))
            if (d != null && type == SdpType.Offer && peerRestarted(incoming)) {
                // RFC 8445 §9: the peer restarted ICE. Restart our side too — otherwise our checklist stays
                // bound to the old password and every check we send is silently discarded by an agent that
                // no longer knows it. Our next answer/offer then carries our own new credentials.
                applyIceRestart(d)
            }
            remoteIceCredentials = RemoteIceCredentials.Received(incoming)
            d?.setRemoteCredentials(incoming)
        }
        // The peer's negotiated DTLS role (RFC 8842) — used to derive our own role (see resolveRole).
        val setup = media?.setup() ?: description.setup()
        if (setup != null) remoteSetup = RemoteSetup.Declared(setup)
        // RFC 8122 §5 / RFC 8827: the fingerprint may sit in the media section or be inherited from the
        // session level. Multiple lines are legal; we verify against the first (we accept exactly one
        // certificate, and a peer offering several digests for one cert gains nothing by the extras).
        val fingerprint =
            (media?.fingerprints() ?: emptyList()).firstOrNull() ?: description.fingerprints().firstOrNull()
        if (fingerprint != null) remoteFingerprint = RemoteFingerprint.Declared(fingerprint)
        startedTransport()?.let { live -> media?.candidates()?.forEach { line -> addRemoteCandidateLine(live, line) } }
    }

    /**
     * Whether [incoming] announces the peer's own ICE restart. RFC 8445 §9 requires a restarting agent to
     * change **both** the ufrag and the password, so both changing is the signal — and requiring both is
     * what keeps a re-signaled description that merely repeats one of them from being mistaken for one.
     * Nothing to compare against before the first description, which is a first negotiation, not a restart.
     *
     * Only ever asked of a remote **offer**. An answer to *our* restart offer necessarily carries new
     * credentials — that is how the peer completes the restart we asked for — so treating that as an
     * independent peer-initiated restart makes the two sides restart each other forever, each new
     * generation provoking the next.
     */
    private fun peerRestarted(incoming: IceCredentials): Boolean =
        when (val known = remoteIceCredentials) {
            RemoteIceCredentials.NotReceived -> false
            is RemoteIceCredentials.Received ->
                known.credentials.ufrag != incoming.ufrag && known.credentials.password != incoming.password
        }

    private fun localParams(
        d: IceAgentDriver,
        setup: SetupRole,
    ): DataChannelParameters =
        DataChannelParameters(
            iceUfrag = d.localCredentials.ufrag.value,
            icePwd = d.localCredentials.password.value,
            // The digest of the certificate the DTLS factory actually presents — never a config value,
            // so what we advertise and what we prove are the same thing by construction (RFC 8122).
            fingerprint = dtls.localFingerprint,
            setup = setup,
            mid = config.dataChannelMid,
        )

    private fun parseOrThrow(sdp: String): SessionDescription =
        when (val result = SessionDescription.parseText(sdp)) {
            is SdpParseResult.Success -> result.description
            is SdpParseResult.Reject -> throw SdpFormatException(result.reason)
        }

    private fun sessionPath(path: IcePath): SelectedPath =
        when (path) {
            IcePath.Unnominated -> SelectedPath.Opaque // unreachable here: we only ask once ICE has nominated
            is IcePath.Nominated -> SelectedPath.Known(path.pair)
            is IcePath.Restarting -> SelectedPath.Known(path.previous)
        }

    // ── negotiation state, as cases rather than nulls ──
    //
    // Each of these is a field a renegotiation writes twice, so each nullable would have had to carry both
    // "not yet" and "not any more". Naming the cases costs a few lines and makes every read site say which
    // one it meant (DESIGN §2).

    /** Whether the ICE transport for this session exists yet. */
    private sealed interface IceTransport {
        data object NotStarted : IceTransport

        data class Started(
            val driver: IceAgentDriver,
        ) : IceTransport
    }

    /** Whether the SCTP data-channel stack has established. */
    private sealed interface DataChannelStack {
        data object NotUp : DataChannelStack

        data class Up(
            val stack: SctpDataChannelStack,
        ) : DataChannelStack
    }

    /** The peer's `a=setup` (RFC 8842), once it has actually declared one. */
    private sealed interface RemoteSetup {
        data object NotDeclared : RemoteSetup

        data class Declared(
            val role: SetupRole,
        ) : RemoteSetup
    }

    /** The peer's `a=fingerprint` (RFC 8122) — absent means unverifiable, which is a refusal, not a default. */
    private sealed interface RemoteFingerprint {
        data object NotDeclared : RemoteFingerprint

        data class Declared(
            val fingerprint: Fingerprint,
        ) : RemoteFingerprint
    }

    /** The peer's ICE credentials as last signaled — the baseline a peer-initiated restart is detected against. */
    private sealed interface RemoteIceCredentials {
        data object NotReceived : RemoteIceCredentials

        data class Received(
            val credentials: IceCredentials,
        ) : RemoteIceCredentials
    }

    /** What the next [createOffer] must carry. */
    private sealed interface NegotiationIntent {
        /** An ordinary offer on the current ICE generation. */
        data object Fresh : NegotiationIntent

        /** An offer carrying a new ICE generation (RFC 8445 §9) — see [RtcPeerConnection.restartIce]. */
        data object IceRestart : NegotiationIntent
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

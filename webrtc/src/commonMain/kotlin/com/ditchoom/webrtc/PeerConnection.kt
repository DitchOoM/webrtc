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
import com.ditchoom.webrtc.sdp.AppliedSdpType
import com.ditchoom.webrtc.sdp.DataChannelParameters
import com.ditchoom.webrtc.sdp.Fingerprint
import com.ditchoom.webrtc.sdp.JsepEvent
import com.ditchoom.webrtc.sdp.JsepOutput
import com.ditchoom.webrtc.sdp.JsepSession
import com.ditchoom.webrtc.sdp.MediaDescription
import com.ditchoom.webrtc.sdp.Mid
import com.ditchoom.webrtc.sdp.SdpParseResult
import com.ditchoom.webrtc.sdp.SdpType
import com.ditchoom.webrtc.sdp.SessionDescription
import com.ditchoom.webrtc.sdp.SetupRole
import com.ditchoom.webrtc.sdp.SignalingState
import com.ditchoom.webrtc.sdp.TlsId
import com.ditchoom.webrtc.sdp.TlsIdAttribute
import com.ditchoom.webrtc.sdp.fingerprints
import com.ditchoom.webrtc.sdp.icePwd
import com.ditchoom.webrtc.sdp.iceUfrag
import com.ditchoom.webrtc.sdp.setup
import com.ditchoom.webrtc.sdp.tlsId
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
     *
     * **It is also the way back from a lost path.** RFC 7675 §5.1 says of revoked consent that *"a new
     * session, or an ICE restart, is needed"*, and this is that restart: called on a session sitting in
     * [PeerConnectionState.Failed] with an [PeerConnectionFailureReason.Ice] cause, it re-runs
     * establishment on the new generation — through [PeerConnectionState.Connecting], since there is no
     * surviving pair to ride — and **the association comes with it**. RFC 8842 §5.5: a restart
     * renegotiates ICE and nothing else, so DTLS is not re-handshaken, SCTP is not rebuilt, and every open
     * data channel keeps its stream id and its state. The consumer does not build a new peer connection.
     *
     * A failure a fresh candidate pair cannot mend — the DTLS handshake or its RFC 8122 fingerprint check,
     * the SCTP association, a cause this backend cannot name — stays [PeerConnectionState.Failed] with the
     * cause it already had. The ICE generation is still swapped (the offer must not claim a restart it did
     * not perform), but the session does not come back.
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

    /**
     * This session's `a=tls-id` (RFC 8842 §5.3) — the identity of the one DTLS association it will ever
     * have. Drawn once, from the injected entropy seam (directive #2), and never redrawn: §5.5 makes a
     * *changed* tls-id the request for a new association, so re-generating it per offer would tell the
     * peer to tear down and re-handshake on every renegotiation. An ICE restart therefore re-offers this
     * same value, which is precisely the continuity claim the unchanged `a=fingerprint` already makes.
     */
    private val localTlsId: TlsId = TlsId.random(random)

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

    // Asks the establishment loop for another attempt, on an ICE generation that has just been restarted
    // — the session half of RFC 7675 §5.1's "a new session, or an ICE restart, is needed". CONFLATED
    // because the request carries exactly one bit ("try again"), and a second restart arriving before the
    // loop woke up is the same bit; buffered because the loop may not be parked on it yet when it is sent.
    private val resumeEstablishment = Channel<Unit>(Channel.CONFLATED)

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

    // The peer's a=tls-id (RFC 8842 §5.3), once it has declared one. Kept for the same reason the ICE
    // credentials are: the signal is a CHANGE, and there is nothing to compare against if the previous
    // value was never remembered. Not declared is the common case — see [honorTlsId].
    private var remoteTlsId: RemoteTlsId = RemoteTlsId.NotDeclared

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
            //
            // …with one exception, which only a SUBSEQUENT offer can reach: `actpass` leaves the choice to
            // the answerer, and once this association has pinned a role there is no choice left to make.
            // RFC 8842 §5.5 has an offerer that wants to keep its DTLS association re-offer `actpass` —
            // continuity is signaled by the UNCHANGED fingerprint, not by the setup value (it is exactly
            // what our own [createOffer] does) — so re-running the initial-offer rule on one would answer
            // `active` and claim a role the association already gave away, which [resolveRole] then
            // (correctly) refuses as a role change. RFC 8445 §9 is explicit that an ICE restart does not
            // redetermine roles; keeping ours is what makes a PEER-INITIATED restart answerable at all.
            // An offer that explicitly declares `active`/`passive` is untouched by this — that peer is
            // asking for a specific role rather than leaving it open, and a flip there is still refused.
            val ourSetup =
                when (val declared = remoteSetup) {
                    is RemoteSetup.Declared ->
                        when (declared.role) {
                            SetupRole.Active -> SetupRole.Passive
                            SetupRole.Passive -> SetupRole.Active
                            SetupRole.ActPass -> pinnedSetup() ?: SetupRole.Active
                            // `holdconn` names an offerer that has not chosen yet (RFC 4145 §4); there is
                            // nothing to complement, so it falls to the same default an undeclared setup does.
                            SetupRole.HoldConn -> SetupRole.Active
                        }
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
     *
     * It is also where a **failed** session comes back (see [RtcPeerConnection.restartIce]). Both callers
     * route through here — our own [restartIce] and a peer-initiated restart detected in [ingestRemote] —
     * so a peer that restarts because *its* consent died revives our side too, without the app on this end
     * having to notice anything.
     */
    private suspend fun applyIceRestart(d: IceAgentDriver) {
        negotiationIntent = NegotiationIntent.Fresh
        d.restartAndAwait()
        // Read AFTER the swap, not before. `restartAndAwait` suspends on the driver's inbox, and a session
        // can fail across a suspension — so a decision taken before it can be stale by the time it is
        // acted on, and the stale answer is the bad one: a restart that failed to notice a failure leaves
        // the establishment loop parked with nobody ever going to wake it. Reading after cannot be wrong
        // the other way, because the swap itself publishes only ICE states and a path change, and neither
        // moves a *session* out of Failed (the path monitor deliberately ignores non-live states).
        val recovery = recoveryFor(_connectionState.value)
        // Once per ICE generation, not once per session: a restart exists precisely because the interfaces
        // may have changed underneath us. The outgoing generation's sockets stay bound (and carrying data)
        // until the new generation nominates, so this never re-binds an address it is still using.
        scope.launch { gathering.gather(d) }
        when (recovery) {
            Recovery.NotNeeded, Recovery.Impossible -> Unit
            Recovery.Resume ->
                // A restart renegotiates ICE and nothing else (RFC 8842 §5.5), so it recovers a session by
                // re-riding the association it already has. SCTP outlives an ICE outage by design, but not
                // forever: past Association.Max.Retrans there is nothing left to re-ride, and the ICE
                // failure already published stays the honest last word rather than being overwritten by a
                // Connecting that leads nowhere.
                if (associationIsLive()) {
                    // W3C: a restart on a failed connection returns it to `connecting`. Not `Restarting` —
                    // that state names a window in which data keeps flowing on the retained pair, and a
                    // revoked generation is never retained (RFC 7675 §5.1 forbids transmitting on it), so
                    // there is no pair to flow on. Published here rather than by the establishment loop so
                    // that a *second* failure on the new generation can be reported: `fail` is
                    // first-cause-wins and would otherwise be swallowed by the terminal we are leaving.
                    _connectionState.value = PeerConnectionState.Connecting
                    resumeEstablishment.trySend(Unit)
                }
        }
    }

    /**
     * Whether an ICE restart can bring the session back — and, when it can, that the session is actually
     * waiting for one. Derived from the state each time it is asked, never stored, so it cannot go stale
     * behind a transition.
     */
    private enum class Recovery {
        /** The session is live, or has not started: this is an ordinary RFC 8445 §9 restart, nothing more. */
        NotNeeded,

        /**
         * ICE failed — consent revoked on the selected pair (RFC 7675 §5.1), or a checklist that never
         * converged — and a *new generation* is that RFC's own named remedy. Establishment resumes.
         */
        Resume,

        /**
         * The session failed for something a fresh candidate pair cannot mend: DTLS (including the RFC 8122
         * fingerprint verdicts), SCTP, or a cause this backend cannot name — or it is closed.
         *
         * Discriminating on the reason is load-bearing rather than tidy. A re-answer that flips the DTLS
         * role is *refused* on purpose (RFC 8842 §5.5), and the association underneath such a session is
         * usually still up — so resuming it would walk straight back to [PeerConnectionState.Connected] and
         * quietly undo the refusal.
         */
        Impossible,
    }

    private fun recoveryFor(state: PeerConnectionState): Recovery =
        when (state) {
            is PeerConnectionState.Failed ->
                when (state.reason) {
                    is PeerConnectionFailureReason.Ice -> Recovery.Resume
                    is PeerConnectionFailureReason.Dtls,
                    is PeerConnectionFailureReason.Sctp,
                    is PeerConnectionFailureReason.Unknown,
                    -> Recovery.Impossible
                }
            PeerConnectionState.Closed -> Recovery.Impossible
            PeerConnectionState.New,
            PeerConnectionState.Connecting,
            is PeerConnectionState.Connected,
            is PeerConnectionState.Restarting,
            -> Recovery.NotNeeded
        }

    /**
     * Whether there is still a data transport for a resumed establishment to ride. Callers hold
     * [negotiationLock].
     *
     * **Defensive, and labelled as such: no fixture kills it.** Reaching the false arm needs the app to sit
     * on a failed session until SCTP gives up on its own — Association.Max.Retrans, which at the RFC's own
     * RTO defaults is around six minutes against a thirty-second consent window. It is kept because the lie
     * it prevents is one only this layer is placed to tell: the new ICE pair really is up, and nothing else
     * here knows there are no streams left riding it.
     */
    private fun associationIsLive(): Boolean =
        when (val channels = dataChannels) {
            // Never established — the resumed attempt builds DTLS and SCTP for the first time.
            DataChannelStack.NotUp -> true
            is DataChannelStack.Up -> channels.stack.state.value != SctpAssociationState.Closed
        }

    override suspend fun setLocalDescription(
        type: SdpType,
        sdp: String,
    ): Unit =
        negotiationLock.withLock {
            // The W3C `type` is 4-valued at this boundary, but the JSEP core's is not: `AppliedSdpType.of`
            // returns null exactly for rollback, which applies no description and so takes no `sdp` at all.
            val applied = AppliedSdpType.of(type)
            if (applied == null) {
                applyJsep(JsepEvent.SetLocalDescription.Rollback)
                // Rollback discards the local offer, so the ICE generation that offer advertised must go
                // with it — otherwise the agent is left honouring credentials no peer has ever seen. JSEP's
                // HaveLocalOffer → Stable edge already existed; this is its ICE half.
                startedTransport()?.rollbackRestart()
            } else {
                applyJsep(JsepEvent.SetLocalDescription.Apply(applied, parseOrThrow(sdp)))
            }
        }

    override suspend fun setRemoteDescription(
        type: SdpType,
        sdp: String,
    ): Unit =
        negotiationLock.withLock {
            val applied = AppliedSdpType.of(type)
            if (applied == null) {
                applyJsep(JsepEvent.SetRemoteDescription.Rollback)
            } else {
                // Parsed BEFORE anything is started: malformed SDP throws without having moved the session.
                val description = parseOrThrow(sdp)
                // A remote offer arriving first makes us the answerer — start ICE (controlled) first.
                if (applied == AppliedSdpType.Offer && transport is IceTransport.NotStarted) startIce(asOfferer = false)
                applyJsep(JsepEvent.SetRemoteDescription.Apply(applied, description))
                ingestRemote(applied, description)
                // A remote ANSWER fixes the offerer's role: the answer's setup names the peer's role, so we
                // take its complement (answer active → peer is client → we are server; passive → client).
                if (applied == AppliedSdpType.Answer) resolveRole(asClient = !remoteSetupIsActive())
            }
        }

    private fun remoteSetupIsActive(): Boolean =
        when (val declared = remoteSetup) {
            is RemoteSetup.Declared -> declared.role == SetupRole.Active
            RemoteSetup.NotDeclared -> false
        }

    /**
     * The `a=setup` value that names the role this association has ALREADY pinned, or null when no role has
     * been resolved yet — a genuine absence (the first negotiation), never an error or a default. Read by
     * [createAnswer] to keep its role across a renegotiation whose offer left the choice open.
     */
    private fun pinnedSetup(): SetupRole? =
        if (roleResolved.isCompleted && !roleResolved.isCancelled) {
            when (roleResolved.getCompleted()) {
                DtlsRole.Client -> SetupRole.Active
                DtlsRole.Server -> SetupRole.Passive
            }
        } else {
            null
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
     * Two reasons to restart, one predicate. The pair we ride is no longer on any live interface — or the
     * session is already sitting in an ICE failure a fresh generation is the remedy for.
     * [IceAgentDriver.pathRidesOneOf] answers *true* for an unnominated path, correctly, because "no live
     * path to lose" is no reason to churn a session that is still converging; but a consent-revoked session
     * is also unnominated, and there it means the opposite. Asking [recoveryFor] first is what tells those
     * two apart — the mobile case this policy exists for is exactly "Wi-Fi went away, consent died with it,
     * and here comes cellular".
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
            if (recoveryFor(_connectionState.value) != Recovery.Resume && d.pathRidesOneOf(interfaces)) return@collect
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

    /**
     * The session's establishment coroutine, for the whole life of the session rather than for one ICE
     * generation: it runs an attempt, and then — if a restart asks for one — runs another.
     *
     * It is a loop because RFC 7675 §5.1's remedy for a revoked pair is *"a new session, or an ICE
     * restart"*, and offering only the first of those is what made a lost path unrecoverable. A single-shot
     * attempt could not resume: it had already returned by the time the app called [restartIce], so there
     * was nothing left to tell.
     */
    private suspend fun runEstablishment(
        d: IceAgentDriver,
        sctpRandom: Random,
    ) {
        while (true) {
            // The liveness invariant (RFC §5.3 #5): an attempt reaches Connected or a typed terminal
            // failure, never hangs — so the whole body is guarded and a DTLS/SCTP throw becomes a typed
            // Failed rather than an establishment coroutine that dies silently.
            try {
                attemptEstablishment(d, sctpRandom)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e // close() cancelled us — structured cancellation, not a failure
            } catch (e: WebRtcException) {
                fail(e.failure) // a real DTLS/SCTP-establishment failure (W4) — typed, never a hang
            } catch (e: Exception) {
                fail(PeerConnectionFailureReason.Unknown(e.message ?: e::class.simpleName ?: "establishment error"))
            }
            // Park until an ICE restart asks for another attempt on a fresh generation. Nothing else can
            // wake this: a session that failed for a reason ICE cannot mend simply stays parked, and
            // close() cancels the whole coroutine.
            resumeEstablishment.receive()
        }
    }

    /**
     * One attempt on the ICE generation currently installed: await nomination, obtain the data transport
     * (existing or new), declare the session live, and watch it until ICE loses the path.
     *
     * Returns rather than throws on every typed outcome — the caller's loop is what decides whether there
     * is another attempt, and it must not have to tell "failed" apart from "closed" by catching.
     */
    private suspend fun attemptEstablishment(
        d: IceAgentDriver,
        sctpRandom: Random,
    ) {
        val terminal =
            d.state.first {
                it is IceConnectionState.Connected || it is IceConnectionState.Completed || it is IceConnectionState.Failed
            }
        if (terminal is IceConnectionState.Failed) {
            fail(PeerConnectionFailureReason.Ice(terminal.reason))
            return
        }
        val liveStack = dataTransport(d, sctpRandom) ?: return
        if (closed) return
        _connectionState.value = PeerConnectionState.Connected(sessionPath(d.path.value))
        monitorLiveSession(d, liveStack)
    }

    /**
     * The data-channel stack this attempt rides — the one already established, or a new one over a fresh
     * DTLS handshake. Null means the attempt is over: a typed failure has been published, or the session
     * closed underneath it.
     *
     * The `Up` arm is the whole of RFC 8842 §5.5 at this layer. An ICE restart — including one recovering a
     * session whose consent was revoked — renegotiates ICE and **nothing else**: DTLS is never
     * re-handshaken and the association is never rebuilt, so every open data channel keeps its stream id,
     * its ordering state and its queued data across the outage. Rebuilding here instead would look almost
     * identical from the outside and silently renumber every channel.
     */
    private suspend fun dataTransport(
        d: IceAgentDriver,
        sctpRandom: Random,
    ): SctpDataChannelStack? =
        when (val existing = negotiationLock.withLock { dataChannels }) {
            is DataChannelStack.Up -> existing.stack
            DataChannelStack.NotUp -> secureAndAssociate(d, sctpRandom)
        }

    /**
     * Secure the app-data seam with DTLS, bring the SCTP data-channel stack up over it, and bind every data
     * channel the app opened before there was an association to open it on. Null on a typed failure or a
     * concurrent close, both already published.
     */
    private suspend fun secureAndAssociate(
        d: IceAgentDriver,
        sctpRandom: Random,
    ): SctpDataChannelStack? {
        val dtlsRole = roleResolved.await()
        // A peer that advertised no a=fingerprint cannot be verified, so it is refused with a typed
        // reason (RFC 8827) rather than connected to insecurely or left to hang.
        val peerFingerprint =
            when (val declared = negotiationLock.withLock { remoteFingerprint }) {
                is RemoteFingerprint.Declared -> declared.fingerprint
                RemoteFingerprint.NotDeclared -> {
                    fail(PeerConnectionFailureReason.Dtls(DtlsFailureReason.FingerprintMissing))
                    return null
                }
            }
        val secured = dtls.secure(d.appDataTransport(), dtlsRole, peerFingerprint)
        val sctpRole = if (dtlsRole == DtlsRole.Client) SctpRole.Client else SctpRole.Server
        val liveStack =
            SctpDataChannelStack(secured, scope, clock, sctpRole, config.sctpConfig, sctpRandom).also { it.start() }

        negotiationLock.withLock {
            if (closed) {
                liveStack.shutdown()
                return null
            }
            dataChannels = DataChannelStack.Up(liveStack)
            for (pending in pendingChannels) scope.launch { pending.bind(liveStack) }
            pendingChannels.clear()
        }
        // Accepting the peer's channels belongs to the ASSOCIATION, not to an ICE generation: it must keep
        // running across a restart and across the recovery from a lost path, so it is launched once, here,
        // with the stack it serves. Under the establishment coroutine it would have to be torn down and
        // rebuilt on every attempt, which is how an incoming DCEP OPEN gets dropped in the gap.
        scope.launch { pumpIncomingChannels(liveStack) }

        // Declare the transport usable only once SCTP has actually established — not merely because ICE
        // nominated a pair. The stack's *initial* state is Closed, so first wait for the handshake to get
        // underway (leave Closed), then for it to resolve to Established or tear back down; a
        // pre-Established teardown is a typed failure, never a hang.
        liveStack.state.first { it != SctpAssociationState.Closed }
        liveStack.state.first { it == SctpAssociationState.Established || it == SctpAssociationState.Closed }
        if (closed) return null
        if (liveStack.state.value != SctpAssociationState.Established) {
            fail(PeerConnectionFailureReason.Sctp(SctpFailureReason.HandshakeTimeout))
            return null
        }
        return liveStack
    }

    /** Publish every channel the peer opens, for as long as the association lives. */
    private suspend fun pumpIncomingChannels(liveStack: SctpDataChannelStack) {
        try {
            while (true) incomingChannels.trySend(liveStack.acceptBidirectional())
        } catch (_: kotlinx.coroutines.channels.ClosedReceiveChannelException) {
            // the association tore down — no more incoming channels, ever
        }
    }

    /**
     * Watch a *live* session until ICE loses the path under it, then return. Its watchers are structured
     * children (cancelled by close() → establishJob.cancel, and by the return below), so no monitor
     * outlives the generation that owns it.
     *
     * Extracted from [runEstablishment] rather than left inline: establishment is a linear sequence that
     * ends here, and these are a concurrent set that begins here — one function doing both was the thing
     * that made it hard to see that the ICE path was never being watched at all.
     */
    private suspend fun monitorLiveSession(
        d: IceAgentDriver,
        liveStack: SctpDataChannelStack,
    ) {
        coroutineScope {
            val watchers =
                listOf(
                    // The ICE path moving mid-session is exactly what an RFC 8445 §9 restart does, and until
                    // now nothing above ICE could see it: `runEstablishment` awaited nomination once and then
                    // never looked again. Note this monitor *only* maps a live session's path — it never
                    // resurrects a Failed or Closed session, so the terminals below still win.
                    launch {
                        d.path.collect { path ->
                            val live = _connectionState.value
                            if (live !is PeerConnectionState.Connected && live !is PeerConnectionState.Restarting) return@collect
                            _connectionState.value =
                                when (path) {
                                    // Nothing nominated in either generation — the pair is gone, not moved. The
                                    // ICE failure terminal owns that; do not pre-empt it with a guess.
                                    IcePath.Unnominated -> return@collect
                                    is IcePath.Nominated -> PeerConnectionState.Connected(SelectedPath.Known(path.pair))
                                    is IcePath.Restarting -> PeerConnectionState.Restarting(SelectedPath.Known(path.previous))
                                }
                        }
                    },
                    launch {
                        liveStack.state.first { it == SctpAssociationState.Closed }
                        if (!closed && _connectionState.value is PeerConnectionState.Connected) {
                            _connectionState.value = PeerConnectionState.Closed
                        }
                    },
                )
            // A live session ends, for this ICE generation, when ICE loses the path — consent revoked on the
            // selected pair (RFC 7675 §5.1), or every pair failed. Awaited HERE rather than in a sibling
            // `launch` so this function RETURNS on it: what happens next is the establishment loop's to
            // decide (a restart may resume it), and it cannot decide anything while parked in a
            // `coroutineScope` that only close() could ever end.
            val lost = d.state.first { it is IceConnectionState.Failed } as IceConnectionState.Failed
            if (!closed) fail(PeerConnectionFailureReason.Ice(lost.reason))
            for (watcher in watchers) watcher.cancel()
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
        type: AppliedSdpType,
        description: SessionDescription,
    ) {
        val media = description.mediaDescriptions.firstOrNull()
        val ufrag = media?.iceUfrag() ?: description.iceUfrag()
        val pwd = media?.icePwd() ?: description.icePwd()
        val d = startedTransport()
        if (ufrag != null && pwd != null) {
            val incoming = IceCredentials(Ufrag(ufrag), IcePassword(pwd))
            if (d != null && type == AppliedSdpType.Offer && peerRestarted(incoming)) {
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
        honorTlsId(media, description)
        startedTransport()?.let { live -> media?.candidates()?.forEach { line -> addRemoteCandidateLine(live, line) } }
    }

    /**
     * RFC 8842 §5.5, the explicit half. `a=tls-id` is the peer *stating* which DTLS association a
     * description refers to, where an unchanged `a=fingerprint` only implies it: a description repeating
     * the tls-id it already declared wants the association it already has, and one carrying a **new**
     * value is asking us to tear that association down and handshake again — the same request the
     * [DtlsFailureReason.RoleChangeOnRenegotiation] heuristic catches from the other end, now stated
     * outright instead of inferred from a role flip.
     *
     * Deliberately only ever an **additional** reason to refuse, never a new reason to drop an association
     * we would otherwise have kept:
     * - **Absent** is the norm, not an error — the attribute is optional and no peer in the interop matrix
     *   (Chrome, Firefox, WebKit, Pion, werift) emits one. Nothing changes; continuity keeps being read off
     *   the unchanged fingerprint, exactly as PR #78/#86 established and every foreign lane depends on.
     * - **Malformed** is a typed reject at the SDP layer ([TlsIdAttribute.Malformed]) and is treated here
     *   as *no usable statement*, falling back to that same inference. Failing the session on it would let
     *   a peer whose tls-id merely fails our grammar lose a connection it would otherwise have kept —
     *   strictly worse than the behaviour that has been through the whole interop matrix.
     * - **Changed** is refused only once the association is actually committed (a role has been resolved,
     *   so the handshake is under way or done). Before that there is nothing to keep, and a peer that
     *   re-derives its tls-id mid-first-negotiation is asking for nothing we are not already doing.
     */
    private fun honorTlsId(
        media: MediaDescription?,
        description: SessionDescription,
    ) {
        val declared =
            when (val inMedia = media?.tlsId()) {
                // RFC 8842 §5.3 allows either level; media wins, session level is the fallback default.
                null, TlsIdAttribute.Absent -> description.tlsId()
                is TlsIdAttribute.Present, is TlsIdAttribute.Malformed -> inMedia
            }
        val incoming =
            when (declared) {
                TlsIdAttribute.Absent, is TlsIdAttribute.Malformed -> return
                is TlsIdAttribute.Present -> declared.tlsId
            }
        when (val known = remoteTlsId) {
            RemoteTlsId.NotDeclared -> remoteTlsId = RemoteTlsId.Declared(incoming)
            is RemoteTlsId.Declared ->
                when {
                    known.tlsId == incoming -> Unit // the association it already has — which is the one we keep
                    roleResolved.isCompleted -> fail(PeerConnectionFailureReason.Dtls(DtlsFailureReason.NewAssociationRequested))
                    else -> remoteTlsId = RemoteTlsId.Declared(incoming)
                }
        }
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
            // RFC 8842 §5.3/§5.5: the same value in every offer and answer this session ever emits, so a
            // peer that honours tls-id reads "keep the association" from us as reliably as it reads it
            // from the unchanged fingerprint.
            tlsId = localTlsId,
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

    /**
     * The peer's `a=tls-id` (RFC 8842 §5.3) as last signaled — the baseline a new-association request is
     * detected against. Not-declared is a *different fact* from any particular value (it means the peer
     * says nothing about association identity and we infer from the fingerprint), so it is a case, not a
     * null that every read site would have to remember to mean that.
     */
    private sealed interface RemoteTlsId {
        data object NotDeclared : RemoteTlsId

        data class Declared(
            val tlsId: TlsId,
        ) : RemoteTlsId
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

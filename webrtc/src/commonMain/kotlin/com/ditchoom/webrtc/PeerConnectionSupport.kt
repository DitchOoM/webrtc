package com.ditchoom.webrtc

import kotlinx.coroutines.CoroutineScope

/**
 * The per-platform WebRTC capability (ARCHITECTURE §3.1 last bullet): how this target provides a
 * [RtcPeerConnection]. A **sealed** hierarchy, so the two ways a platform can provide one are mutually
 * exclusive *and* checked by the compiler — there is no runtime "unsupported operation" for asking a
 * native target to delegate (DESIGN §4: make illegal states unrepresentable, never a runtime reject for a
 * statically-known-impossible call).
 *
 *  - [BrowserDelegated] — a browser (js/wasmJs), the one place we **wrap rather than reimplement**
 *    (ARCHITECTURE §1.1): [BrowserDelegated.create] returns an [RtcPeerConnection] backed by the browser's own
 *    `RTCPeerConnection`, and is reachable **only** after narrowing to this type.
 *  - [Native] — every non-browser target: we **own** the protocol, so there is nothing to delegate to and
 *    — by construction — no delegation method exists. The app builds a [NativePeerConnection] directly
 *    with its injected seams.
 *  - [Unavailable] — this target can host **neither**: there is no `RTCPeerConnection` to delegate to,
 *    *and* a piece the native stack needs is missing here. The [PeerConnectionUnavailableReason] says
 *    which, at **config** time.
 *
 * Obtain this platform's value from [peerConnectionSupport] and branch with an exhaustive `when`:
 * ```
 * val pc = when (val s = peerConnectionSupport()) {
 *     is PeerConnectionSupport.BrowserDelegated -> s.create(scope, iceServers)
 *     PeerConnectionSupport.Native              -> NativePeerConnection(scope, clock, random, binder, gathering, dtls)
 *     is PeerConnectionSupport.Unavailable      -> error("no WebRTC here: ${s.reason}")
 * }
 * ```
 */
public sealed interface PeerConnectionSupport {
    /** A browser target (js/wasmJs) that delegates to the platform `RTCPeerConnection`. */
    public interface BrowserDelegated : PeerConnectionSupport {
        /**
         * Create an [RtcPeerConnection] wrapping the browser's own `RTCPeerConnection`. The flows
         * ([RtcPeerConnection.localIceCandidates] etc.) are pumped on [scope]; [iceServers] become the
         * `RTCConfiguration.iceServers` (STUN/TURN, with TURN credentials — see [IceServer]).
         */
        public fun create(
            scope: CoroutineScope,
            iceServers: List<IceServer> = emptyList(),
        ): RtcPeerConnection
    }

    /**
     * A non-browser target: this platform owns the WebRTC protocol, so there is nothing to delegate to —
     * construct a [NativePeerConnection] with your seams. Shared by the JVM/Android/Native actuals (and
     * returned by the js/wasmJs actuals under Node, where no `RTCPeerConnection` exists to wrap).
     */
    public object Native : PeerConnectionSupport

    /**
     * This target can host **no** peer connection: nothing to delegate to, and the native stack is
     * missing a piece here. [reason] says which, exhaustively.
     *
     * The point of this case is *when* the caller learns. Before it existed, `js` under Node reported
     * [Native]; the app built a [NativePeerConnection], ICE gathered and checked happily, and the session
     * died at the **DTLS handshake** with `DtlsFailureReason.BackendUnavailable` — a capability advertised
     * at config time and dishonoured at connect time, discovered at the worst possible moment. Same
     * courtesy `NetworkMonitorSupport.Unavailable(NoPlatformApi)` already extends for interface
     * enumeration (webrtc#126).
     */
    public data class Unavailable(
        public val reason: PeerConnectionUnavailableReason,
    ) : PeerConnectionSupport
}

/**
 * Why a target can host no peer connection — a typed reason, exhaustively matchable. The discriminant is
 * the **type**; nothing here is a string to be parsed (standing directive 3).
 *
 * Both cases are properties of the *target*, not of the moment: neither is retryable, and neither is
 * something an app can configure its way out of. That is exactly why they belong at `peerConnectionSupport()`
 * rather than in a failure surfaced mid-session.
 */
public sealed interface PeerConnectionUnavailableReason {
    /**
     * **js outside a browser (Node).** UDP is *not* the obstacle — `socket-udp` publishes a full js
     * actual (`bind`/`connect`/`bindMulticast`). The single missing primitive is a **blocking raw-ECDH**
     * premaster, which the DTLS key schedule needs: `buffer-crypto`'s `KeyAgreement.jsAndWasmJs.kt` is one
     * WebCrypto implementation shared by js and wasmJs, and WebCrypto is **async-only**, so
     * `RawEcdh.js.kt` throws `BackendUnavailable` by construction. In a browser that line is unreachable
     * (the delegate handles everything); under Node it is the whole story.
     *
     * It is fixable, and deliberately not fixed here: Node's own `crypto.createECDH()` **is** synchronous,
     * so a blocking premaster is implementable — preferably as an upstream `buffer-crypto` Node actual,
     * which keeps the abstraction whole. Tracked separately.
     */
    public data object NoBlockingKeyAgreement : PeerConnectionUnavailableReason

    /**
     * **wasmJs outside a browser.** There is no raw-UDP transport at all: `socket-udp` publishes no wasm
     * actual, so no `AddressedDatagramChannel` can be bound and a [NativePeerConnection] has nothing to
     * send on. Strictly more missing than [NoBlockingKeyAgreement] — wasm lacks the transport *and* the
     * crypto primitive.
     *
     * Inside a browser this is unreachable: there `peerConnectionSupport()` returns
     * [PeerConnectionSupport.BrowserDelegated] and the platform's own `RTCPeerConnection` does everything.
     */
    public data object NoDatagramTransport : PeerConnectionUnavailableReason
}

/**
 * This platform's [PeerConnectionSupport] (`expect`/`actual`).
 *
 *  - A browser (js/wasmJs, `RTCPeerConnection` present) → [PeerConnectionSupport.BrowserDelegated].
 *  - jvm / android / linux / macOS / iOS → [PeerConnectionSupport.Native].
 *  - js under **Node** → [PeerConnectionSupport.Unavailable] with
 *    [PeerConnectionUnavailableReason.NoBlockingKeyAgreement].
 *  - wasmJs outside a browser → [PeerConnectionSupport.Unavailable] with
 *    [PeerConnectionUnavailableReason.NoDatagramTransport].
 */
public expect fun peerConnectionSupport(): PeerConnectionSupport

package com.ditchoom.webrtc

import kotlinx.coroutines.CoroutineScope

/**
 * The per-platform WebRTC capability (RFC §3.1 last bullet): how this target provides a
 * [RtcPeerConnection]. A **sealed** hierarchy, so the two ways a platform can provide one are mutually
 * exclusive *and* checked by the compiler — there is no runtime "unsupported operation" for asking a
 * native target to delegate (DESIGN §4: make illegal states unrepresentable, never a runtime reject for a
 * statically-known-impossible call).
 *
 *  - [BrowserDelegated] — a browser (js/wasmJs), the one place we **wrap rather than reimplement**
 *    (RFC §1.1): [BrowserDelegated.create] returns an [RtcPeerConnection] backed by the browser's own
 *    `RTCPeerConnection`, and is reachable **only** after narrowing to this type.
 *  - [Native] — every non-browser target: we **own** the protocol, so there is nothing to delegate to and
 *    — by construction — no delegation method exists. The app builds a [NativePeerConnection] directly
 *    with its injected seams.
 *
 * Obtain this platform's value from [peerConnectionSupport] and branch with an exhaustive `when`:
 * ```
 * val pc = when (val s = peerConnectionSupport()) {
 *     is PeerConnectionSupport.BrowserDelegated -> s.create(scope, iceServers)
 *     PeerConnectionSupport.Native              -> NativePeerConnection(scope, clock, random, binder, gathering, dtls)
 * }
 * ```
 */
public sealed interface PeerConnectionSupport {
    /** A browser target (js/wasmJs) that delegates to the platform `RTCPeerConnection`. */
    public interface BrowserDelegated : PeerConnectionSupport {
        /**
         * Create an [RtcPeerConnection] wrapping the browser's own `RTCPeerConnection`. The flows
         * ([RtcPeerConnection.localIceCandidates] etc.) are pumped on [scope]; [iceServers] are STUN/TURN
         * URLs for the `RTCConfiguration`.
         */
        public fun create(
            scope: CoroutineScope,
            iceServers: List<String> = emptyList(),
        ): RtcPeerConnection
    }

    /**
     * A non-browser target: this platform owns the WebRTC protocol, so there is nothing to delegate to —
     * construct a [NativePeerConnection] with your seams. Shared by the JVM/Android/Native actuals (and
     * returned by the js/wasmJs actuals under Node, where no `RTCPeerConnection` exists to wrap).
     */
    public object Native : PeerConnectionSupport
}

/**
 * This platform's [PeerConnectionSupport] (`expect`/`actual`). A browser with an `RTCPeerConnection`
 * returns a [PeerConnectionSupport.BrowserDelegated]; every other target returns [PeerConnectionSupport.Native].
 */
public expect fun peerConnectionSupport(): PeerConnectionSupport

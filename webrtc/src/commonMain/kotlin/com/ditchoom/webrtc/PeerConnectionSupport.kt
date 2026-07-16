package com.ditchoom.webrtc

import kotlinx.coroutines.CoroutineScope

/** Whether a platform runs our own protocol stack or delegates to a native `RTCPeerConnection`. */
public enum class PeerConnectionKind {
    /** Non-browser targets (JVM/Android/Native): the sans-io stack ([NativePeerConnection]). */
    Native,

    /** Browser / wasmJs: `peerConnectionSupport().createDelegated(...)` wraps `RTCPeerConnection`. */
    BrowserDelegated,
}

/**
 * The per-platform WebRTC capability (RFC §3.1 last bullet: `peerConnectionSupport()` reports how this
 * target provides a `PeerConnection`). On every non-browser target we **own** the protocol
 * ([PeerConnectionKind.Native]) and the app constructs a [NativePeerConnection] directly with its seams.
 * In a **browser** (js/wasmJs) we are the one target that **wraps rather than reimplements** (RFC §1.1):
 * [createDelegated] returns an [RtcPeerConnection] backed by the browser's own `RTCPeerConnection`.
 */
public interface PeerConnectionSupport {
    /** How this platform provides a peer connection. */
    public val kind: PeerConnectionKind

    /**
     * Create an [RtcPeerConnection] delegating to the platform `RTCPeerConnection` (browser only). The
     * flows ([RtcPeerConnection.localIceCandidates] etc.) are pumped on [scope]; [iceServers] are STUN/TURN
     * URLs for the `RTCConfiguration`. On a [PeerConnectionKind.Native] platform this throws
     * [UnsupportedOperationException] — construct a [NativePeerConnection] with your seams instead.
     */
    public fun createDelegated(
        scope: CoroutineScope,
        iceServers: List<String> = emptyList(),
    ): RtcPeerConnection
}

/** This platform's [PeerConnectionSupport] (`expect`/`actual`; browser targets return a delegating one). */
public expect fun peerConnectionSupport(): PeerConnectionSupport

/**
 * The non-browser [PeerConnectionSupport]: this target owns the protocol, so there is nothing to
 * delegate to — [createDelegated] throws and the app builds a [NativePeerConnection] with its seams.
 * Shared by the JVM/Android/Native actuals.
 */
internal object NativePeerConnectionSupport : PeerConnectionSupport {
    override val kind: PeerConnectionKind get() = PeerConnectionKind.Native

    override fun createDelegated(
        scope: CoroutineScope,
        iceServers: List<String>,
    ): RtcPeerConnection =
        throw UnsupportedOperationException(
            "This target runs the native WebRTC stack — construct a NativePeerConnection with your seams; " +
                "RTCPeerConnection delegation exists only in a browser (js/wasmJs).",
        )
}

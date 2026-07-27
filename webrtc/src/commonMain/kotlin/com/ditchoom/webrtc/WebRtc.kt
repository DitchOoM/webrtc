package com.ditchoom.webrtc

import com.ditchoom.webrtc.ice.CandidatePair

/**
 * Module identity marker (mirrors the sibling modules' markers) — the consumer API itself is
 * [RtcPeerConnection] / [NativePeerConnection] / [PeerConnectionState].
 */
public object WebRtc {
    public const val MODULE: String = "webrtc"
}

/**
 * The ICE pair a live session's traffic rides, or an honest statement that this backend does not expose
 * one. It replaces a `CandidatePair?` whose null meant "the browser owns pair selection internally" —
 * a fact about the *backend*, which read at every call site as the far more alarming "there is no pair".
 */
public sealed interface SelectedPath {
    /** The backend selects and owns the pair internally and does not surface it (the browser delegate). */
    public data object Opaque : SelectedPath

    /** The typed [pair] traffic rides (the native stack). */
    public data class Known(
        public val pair: CandidatePair,
    ) : SelectedPath
}

/**
 * Peer-connection lifecycle (W3C `RTCPeerConnectionState`) as a sealed hierarchy where each state carries
 * exactly the data that is valid in it — and nothing that isn't. There is no `connected: Boolean` +
 * nullable `failureReason` soup that could encode "connected AND failed"; the illegal states are simply
 * unrepresentable (DESIGN §4). [Failed] carries the **typed** [PeerConnectionFailureReason], never a
 * string (directive #3) — the same value the terminal [WebRtcException] throws.
 */
public sealed interface PeerConnectionState {
    /** Constructed, no negotiation started (W3C `new`). */
    public data object New : PeerConnectionState

    /** ICE/DTLS/SCTP establishment is in progress (W3C `connecting`). */
    public data object Connecting : PeerConnectionState

    /** The data-channel transport is up over the nominated ICE pair (W3C `connected`), riding [path]. */
    public data class Connected(
        public val path: SelectedPath,
    ) : PeerConnectionState

    /**
     * An ICE restart (RFC 8445 §9) is in flight and the new generation has not nominated yet. The session
     * is **still usable**: DTLS and SCTP are untouched, every open data channel stays open, and data keeps
     * riding [path] — the pair the outgoing generation nominated. It is a distinct state rather than a
     * flag on [Connected] because "connected, and also mid-restart" is precisely the combination a caller
     * needs to tell apart: the pair underneath is about to change.
     */
    public data class Restarting(
        public val path: SelectedPath,
    ) : PeerConnectionState

    /** Establishment failed or the session was lost with a typed cause (W3C `failed`). */
    public data class Failed(
        public val reason: PeerConnectionFailureReason,
    ) : PeerConnectionState

    /** The session was closed locally (W3C `closed`). */
    public data object Closed : PeerConnectionState
}

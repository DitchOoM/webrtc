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

    /**
     * The data-channel transport is up over the nominated ICE pair (W3C `connected`). [selectedPair] is
     * the ICE pair traffic rides — the typed [CandidatePair] on the native stack, or null when the
     * backend does not expose it (the browser delegate, which owns pair selection internally).
     */
    public data class Connected(
        public val selectedPair: CandidatePair?,
    ) : PeerConnectionState

    /** Establishment failed or the session was lost with a typed cause (W3C `failed`). */
    public data class Failed(
        public val reason: PeerConnectionFailureReason,
    ) : PeerConnectionState

    /** The session was closed locally (W3C `closed`). */
    public data object Closed : PeerConnectionState
}

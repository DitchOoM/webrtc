package com.ditchoom.webrtc.sdp

/**
 * The JSEP signaling state (RFC 8829 §3.5.1 / the W3C `RTCSignalingState`). Modeled as a sealed set of
 * objects rather than a boolean/nullable bag (DESIGN_PRINCIPLES §4): there is no representable value
 * that is, say, both `stable` and mid-offer. The offer/answer transition table is enforced by
 * [JsepSession]; an illegal edge is a typed [JsepError.InvalidTransition], never a silent no-op.
 */
public sealed interface SignalingState {
    /** No offer/answer exchange in progress — the steady state between negotiations. */
    public data object Stable : SignalingState

    /** A local offer has been applied ([SdpType.Offer] via `setLocalDescription`); awaiting the answer. */
    public data object HaveLocalOffer : SignalingState

    /** A remote offer has been applied; a local answer is expected next. */
    public data object HaveRemoteOffer : SignalingState

    /** A local provisional answer has been applied ([SdpType.PrAnswer]); awaiting the final answer. */
    public data object HaveLocalPrAnswer : SignalingState

    /** A remote provisional answer has been applied; awaiting the final answer. */
    public data object HaveRemotePrAnswer : SignalingState

    /** The session is closed; every further offer/answer event is rejected. */
    public data object Closed : SignalingState
}

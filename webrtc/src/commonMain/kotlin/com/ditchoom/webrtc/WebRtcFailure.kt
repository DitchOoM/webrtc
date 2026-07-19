package com.ditchoom.webrtc

import com.ditchoom.webrtc.dtls.DtlsFailureReason
import com.ditchoom.webrtc.ice.IceFailureReason
import com.ditchoom.webrtc.sctp.association.SctpFailureReason

/**
 * The exhaustive, typed cause of a WebRTC session failure. It composes the sub-layer sealed reasons
 * unchanged ([IceFailureReason], [DtlsFailureReason], [SctpFailureReason]) rather than flattening them,
 * so a caller recovers the exact ICE/DTLS/SCTP condition, and `when` is exhaustive at every level
 * (DESIGN §3/§6). This realizes "typed errors, never stringly" (directive #3) at the session boundary —
 * the ICE and SCTP handoffs explicitly deferred mapping their reasons into a shared vocabulary to W6.
 *
 * Unifying this *further* into socket's `SocketException`/`ConnectionFailureReason` hierarchy (RFC §3.1
 * "one thrown vocabulary") is blocked on a real cross-repo constraint discovered this wave: depending on
 * `com.ditchoom:socket` links socket's `LinuxSockets` cinterop, whose vendored **BoringSSL** duplicate-
 * symbols against `buffer-crypto`'s BoringSSL on every native target (`AES_set_decrypt_key`, …). Until
 * socket and buffer-crypto share one BoringSSL build upstream, webrtc cannot take that dependency on
 * native — so the `SocketException` bridge is deferred exactly like DTLS is deferred to W4, and this
 * self-contained typed vocabulary is the discriminant callers use in the meantime.
 */
public sealed interface PeerConnectionFailureReason {
    /** One-line summary for the exception message; the sealed value is the API surface. */
    public val description: String

    /** ICE never produced (or lost) a usable candidate pair (RFC 8445 / RFC 7675). */
    public data class Ice(
        public val reason: IceFailureReason,
    ) : PeerConnectionFailureReason {
        override val description: String get() = "ICE failed: $reason"
    }

    /**
     * The DTLS handshake over the selected pair failed, or its `a=fingerprint` check did (W4). The
     * webrtc-dtls layer owns this vocabulary — including the RFC 8122 fingerprint verdicts, which the
     * session driver makes because the sans-io engine is signaling-agnostic (see [DtlsFailureReason]).
     */
    public data class Dtls(
        public val reason: DtlsFailureReason,
    ) : PeerConnectionFailureReason {
        override val description: String get() = "DTLS failed: $reason"
    }

    /** The SCTP association aborted or never established (RFC 4960 / RFC 3758). */
    public data class Sctp(
        public val reason: SctpFailureReason,
    ) : PeerConnectionFailureReason {
        override val description: String get() = "SCTP failed: $reason"
    }

    /**
     * A failure whose sub-layer cause this backend does not expose — chiefly the browser delegate, whose
     * `RTCPeerConnection` reports `connectionState = "failed"` without a portable discriminant. [detail]
     * is diagnostic only, never a discriminant (directive #3).
     */
    public data class Unknown(
        public val detail: String,
    ) : PeerConnectionFailureReason {
        override val description: String get() = "WebRTC failed: $detail"
    }
}

/**
 * A JSEP offer/answer transition was rejected (W3C `InvalidStateError`) — a **signaling-API misuse**, not
 * a transport failure, so it extends [IllegalStateException] rather than [WebRtcException]. The typed
 * [error] is the discriminant (directive #3): a caller branches on it, never on the message string.
 */
public class JsepStateException(
    public val error: com.ditchoom.webrtc.sdp.JsepError,
) : IllegalStateException("JSEP rejected the description: $error")

/**
 * A description handed to `setLocalDescription`/`setRemoteDescription` was not well-formed SDP (W3C
 * `TypeError`) — malformed input, so it extends [IllegalArgumentException]. The typed [reason] is the
 * discriminant (directive #3).
 */
public class SdpFormatException(
    public val reason: com.ditchoom.webrtc.sdp.SdpRejectReason,
) : IllegalArgumentException("malformed SDP: $reason")

/**
 * The single thrown vocabulary for a WebRTC session failure. It carries the typed [failure] as the
 * discriminant (directive #3), never a string. When the upstream BoringSSL constraint above is resolved,
 * this is intended to become a `SocketClosedException` subtype (as W5's
 * [com.ditchoom.webrtc.sctp.datachannel.SctpClosedException] will) so a WebRTC failure is caught uniformly
 * with every other transport failure (RFC §3.1). Note that re-parenting is **binary-breaking** (a
 * superclass change alters the ABI and which `catch` clauses match); keeping the cause on the typed
 * [failure] field keeps a `when (e.failure)` branch source-stable across that change, but the supertype
 * migration itself is a breaking bump, tracked for when the dependency is unblocked.
 */
public class WebRtcException(
    public val failure: PeerConnectionFailureReason,
    cause: Throwable? = null,
) : Exception(failure.description, cause)

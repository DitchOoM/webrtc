package com.ditchoom.webrtc

import com.ditchoom.webrtc.dtls.DtlsFailureReason
import com.ditchoom.webrtc.ice.IceFailureReason
import com.ditchoom.webrtc.sctp.association.SctpFailureReason

/**
 * The exhaustive, typed cause of a WebRTC session failure. It composes the sub-layer sealed reasons
 * unchanged ([IceFailureReason], [DtlsFailureReason], [SctpFailureReason]) rather than flattening them,
 * so a caller recovers the exact ICE/DTLS/SCTP condition, and `when` is exhaustive at every level
 * (DESIGN §3/§6). This realizes "typed errors, never stringly" (directive #3) at the session boundary.
 *
 * Unifying this *further* into socket's `SocketException`/`ConnectionFailureReason` hierarchy
 * (ARCHITECTURE §3.1 "one thrown vocabulary") is simply **not done yet**. It used to be *blocked*, and
 * the note here said so: depending on `com.ditchoom:socket` linked its `LinuxSockets` cinterop, whose
 * vendored BoringSSL duplicate-symboled against `buffer-crypto`'s on every native target. **That is
 * obsolete** — socket's klib embeds only `liburing.a` now, and socket and `buffer-crypto` resolve to the
 * same `boringssl-canonical`, which Gradle dedupes; `webrtc-ice`'s native leaf already depends on socket
 * core and links on both Linux architectures. The remaining cost is a real one but ordinary: a
 * `commonMain` dependency on socket would put it in front of every target, browsers included, which
 * ARCHITECTURE §11.6 keeps out on purpose. So this self-contained vocabulary stands on its own merits
 * rather than on an expired constraint.
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
     * The DTLS handshake over the selected pair failed, or its `a=fingerprint` check did. The
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
 * discriminant (directive #3), never a string. If the socket dependency question above is ever settled
 * the other way, this becomes a `SocketClosedException` subtype (as
 * [com.ditchoom.webrtc.sctp.datachannel.SctpClosedException] would) so a WebRTC failure is caught
 * uniformly with every other transport failure (ARCHITECTURE §3.1). Re-parenting is **binary-breaking**
 * — a superclass change alters the ABI and which `catch` clauses match — but keeping the cause on the
 * typed [failure] field keeps a `when (e.failure)` branch source-stable across it, so only the supertype
 * migration itself would need a major bump.
 */
public class WebRtcException(
    public val failure: PeerConnectionFailureReason,
    cause: Throwable? = null,
) : Exception(failure.description, cause)

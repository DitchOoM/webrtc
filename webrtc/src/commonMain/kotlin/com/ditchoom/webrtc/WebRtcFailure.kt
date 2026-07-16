package com.ditchoom.webrtc

import com.ditchoom.webrtc.ice.IceFailureReason
import com.ditchoom.webrtc.sctp.association.SctpFailureReason

/**
 * Why a DTLS handshake failed — a sealed, exhaustive vocabulary defined here (W6) so the session-layer
 * error sweep is complete before the real backend (W4) lands (HANDOFF W6 step 4: map ICE + SCTP + "the
 * coming DTLS reasons" into one typed vocabulary). The BoringSSL driver produces these; until then the
 * plaintext DTLS stand-in never fails, so no value is constructed at runtime yet.
 */
public sealed interface DtlsFailureReason {
    /** Human-readable summary — the sealed value is the discriminant, never the string (directive #3). */
    public val description: String

    /** The DTLS handshake did not complete (alert, record error, or version/cipher mismatch). */
    public data object HandshakeFailed : DtlsFailureReason {
        override val description: String get() = "DTLS handshake failed"
    }

    /** The peer's certificate fingerprint did not match the `a=fingerprint` in its SDP (RFC 8122). */
    public data object FingerprintMismatch : DtlsFailureReason {
        override val description: String get() = "DTLS certificate fingerprint did not match the SDP a=fingerprint"
    }

    /** The handshake did not complete within its retransmission budget. */
    public data object Timeout : DtlsFailureReason {
        override val description: String get() = "DTLS handshake timed out"
    }
}

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

    /** The DTLS handshake over the selected pair failed (W4). */
    public data class Dtls(
        public val reason: DtlsFailureReason,
    ) : PeerConnectionFailureReason {
        override val description: String get() = reason.description
    }

    /** The SCTP association aborted or never established (RFC 4960 / RFC 3758). */
    public data class Sctp(
        public val reason: SctpFailureReason,
    ) : PeerConnectionFailureReason {
        override val description: String get() = "SCTP failed: $reason"
    }
}

/**
 * The single thrown vocabulary for a WebRTC session failure. It carries the typed [failure] as the
 * discriminant (directive #3), never a string. When the upstream BoringSSL constraint above is resolved,
 * this becomes a `SocketClosedException` subtype (as W5's [com.ditchoom.webrtc.sctp.datachannel.SctpClosedException]
 * will) so a WebRTC failure is caught uniformly with every other transport failure (RFC §3.1); the public
 * shape here — a typed [failure] on one exception type — is chosen to make that later re-parenting
 * source-compatible for callers that branch on [failure].
 */
public class WebRtcException(
    public val failure: PeerConnectionFailureReason,
    cause: Throwable? = null,
) : Exception(failure.description, cause)

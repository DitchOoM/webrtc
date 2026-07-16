package com.ditchoom.webrtc.dtls

/**
 * Why a DTLS transport failed — a sealed, exhaustive vocabulary (standing directive #3: typed errors,
 * never stringly). The session layer (webrtc root) maps these into its `PeerConnectionFailureReason.Dtls`;
 * strings live only in [Internal.diagnostic] as a human aid, never as a discriminant.
 */
public sealed interface DtlsFailureReason {
    /** The handshake did not complete — a fatal alert, bad flight, or version/cipher mismatch. */
    public object HandshakeFailure : DtlsFailureReason

    /** The peer completed the handshake but presented no certificate to fingerprint (RFC 8827). */
    public object PeerCertificateMissing : DtlsFailureReason

    /** A record-layer error after the handshake (decrypt failure / malformed record). */
    public object RecordLayerError : DtlsFailureReason

    /**
     * No DTLS backend on this platform this wave — JVM/Android/Apple DTLS is deferred to
     * `boringssl-kmp` (see EXECUTION_PLAN "W4 sequencing"); browsers delegate to `RTCPeerConnection`.
     */
    public object BackendUnavailable : DtlsFailureReason

    /** An unexpected backend/library failure; [diagnostic] is a non-discriminant human aid. */
    public data class Internal(val diagnostic: String) : DtlsFailureReason
}

/** Thrown when a DTLS backend cannot be constructed or driven; carries a typed [reason]. */
public class DtlsException(
    public val reason: DtlsFailureReason,
    message: String? = null,
    cause: Throwable? = null,
) : Exception(message ?: reason.toString(), cause)

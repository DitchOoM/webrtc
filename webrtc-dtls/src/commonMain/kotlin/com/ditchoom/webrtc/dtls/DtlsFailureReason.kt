package com.ditchoom.webrtc.dtls

/**
 * Why a DTLS transport failed — the **DTLS layer's** sealed, exhaustive vocabulary (standing directive
 * #3: typed errors, never stringly). The session layer (webrtc root) composes this unchanged as
 * `PeerConnectionFailureReason.Dtls`, exactly as it composes `IceFailureReason`/`SctpFailureReason`,
 * so a caller recovers the exact condition and every `when` stays exhaustive. Strings live only in
 * [Internal.diagnostic] as a human aid, never as a discriminant.
 *
 * The vocabulary spans the whole layer, not just the sans-io core: the [DtlsEngine] is deliberately
 * signaling-agnostic, so the `a=fingerprint` checks (RFC 8122) are made by the driver that owns the SDP
 * — but they are DTLS-layer failures, and belong in one vocabulary rather than a parallel session-layer
 * copy. Each case notes which half produces it.
 */
public sealed interface DtlsFailureReason {
    /** *(engine)* The handshake did not complete — a fatal alert, bad flight, or version/cipher mismatch. */
    public object HandshakeFailure : DtlsFailureReason

    /** *(driver)* The handshake did not complete within its budget (`DtlsConfig.handshakeTimeout`). */
    public object HandshakeTimeout : DtlsFailureReason

    /** *(engine)* The peer completed the handshake but presented no certificate to fingerprint (RFC 8827). */
    public object PeerCertificateMissing : DtlsFailureReason

    /**
     * *(driver)* The peer's certificate did not match the `a=fingerprint` its SDP advertised (RFC 8122).
     * The signaling channel and the data path are bound by that digest, so a mismatch is an attack or a
     * mis-signaled session — never recoverable, always fatal to the connection.
     */
    public object FingerprintMismatch : DtlsFailureReason

    /**
     * *(driver)* The peer's SDP carried no `a=fingerprint` we can verify against — absent entirely, or
     * only in a hash function we do not accept. RFC 8827 requires SHA-256 for WebRTC, and an
     * unverifiable peer is refused rather than trusted.
     */
    public object FingerprintMissing : DtlsFailureReason

    /** *(engine)* A record-layer error after the handshake (decrypt failure / malformed record). */
    public object RecordLayerError : DtlsFailureReason

    /**
     * *(engine)* A TLS 1.3 downgrade was detected: our 1.3-capable client offered DTLS 1.3 but received a
     * ServerHello selecting a lower version whose `Random` carries the RFC 8446 §4.1.3 downgrade sentinel
     * (`DOWNGRD\x01` / `DOWNGRD\x00`). A conformant 1.3-capable server sets that sentinel when it negotiates
     * down, so its presence after we offered 1.3 means an active attacker stripped our 1.3 offer — fatal.
     */
    public object DowngradeDetected : DtlsFailureReason

    /**
     * *(engine)* No DTLS backend on this platform this wave — JVM/Android/Apple DTLS is deferred to
     * `boringssl-kmp` (see EXECUTION_PLAN "W4 sequencing"); browsers delegate to `RTCPeerConnection`.
     */
    public object BackendUnavailable : DtlsFailureReason

    /** *(engine)* An unexpected backend/library failure; [diagnostic] is a non-discriminant human aid. */
    public data class Internal(
        val diagnostic: String,
    ) : DtlsFailureReason
}

/** Thrown when a DTLS backend cannot be constructed or driven; carries a typed [reason]. */
public class DtlsException(
    public val reason: DtlsFailureReason,
    message: String? = null,
    cause: Throwable? = null,
) : Exception(message ?: reason.toString(), cause)

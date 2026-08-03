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

    /**
     * *(driver)* A renegotiation asked us to flip DTLS roles. Per RFC 8842 §5.5 an endpoint that does not
     * want a *new* DTLS association re-offers `a=setup:actpass` and keeps its fingerprint — the
     * association's client/server roles are fixed for its lifetime, and an ICE restart deliberately runs
     * underneath a DTLS/SCTP session that never renegotiates. A re-answer whose `a=setup` implies the
     * opposite of the role we already resolved is therefore asking for a fresh association, which we do
     * not support. Refused with a reason rather than silently ignored and left to hang.
     */
    public object RoleChangeOnRenegotiation : DtlsFailureReason

    /**
     * *(driver)* A renegotiation asked for a **new** DTLS association outright: the peer's `a=tls-id`
     * (RFC 8842 §5.3) changed from the value it had already declared for the association we are on. §5.5
     * makes that the explicit signal — a tls-id is stable for the life of an association and changes only
     * when the endpoint intends a fresh one — where [RoleChangeOnRenegotiation] only ever inferred the
     * same request from a role flip. Refused for the same reason and with the same finality: an ICE
     * restart deliberately runs underneath a DTLS/SCTP session that never renegotiates, so there is no
     * such thing here as re-handshaking mid-session.
     *
     * A peer that sends **no** `a=tls-id` (which is every peer in this stack's interop matrix, and legal —
     * the attribute is optional) can never produce this: continuity is then read off the unchanged
     * `a=fingerprint`, exactly as before.
     */
    public object NewAssociationRequested : DtlsFailureReason

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
     * *(engine)* This platform cannot run the handshake. Only **js/wasmJs** ever report it, and only for
     * one primitive: the key schedule needs a *blocking* raw-ECDH premaster, and `buffer-crypto`'s key
     * agreement there is WebCrypto, which is suspend-only. Every non-browser target has the pure-Kotlin
     * engine in `commonMain`, so none of them can produce this.
     *
     * In a browser it is unreachable by construction — `peerConnectionSupport()` delegates to
     * `RTCPeerConnection` and the engine is never driven. Under **Node** it is reachable, and it is the
     * concrete reason a Node session cannot establish: there is no `RTCPeerConnection` to delegate to,
     * so the native path runs and stops here. (Node's own `crypto.createECDH()` is synchronous, so this
     * is closable upstream rather than a platform limit.)
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

package com.ditchoom.webrtc.dtls

import kotlin.jvm.JvmInline

/**
 * W4 placeholder. The real module drives BoringSSL through memory BIOs fed with `toNativeData()`
 * handles (no [ByteArray] at the FFI edge), caller-clocked via `DTLSv1_get_timeout`. Placeholder only.
 */
public object Dtls {
    public const val MODULE: String = "webrtc-dtls"
}

/** DTLS role in the handshake — exactly two, so dispatch is total and no boolean flag is needed. */
public enum class DtlsRole {
    Client,
    Server,
}

/**
 * An `a=fingerprint` certificate digest, wrapped so it can never be passed where some other hex string
 * is expected (house style: value-class every identifier). We only ever produce/verify SHA-256
 * fingerprints (the WebRTC modern profile), stored as lowercase, colon-free hex of the 32 digest bytes.
 * [sdp] renders the RFC 8122 `a=fingerprint` form (`sha-256 AB:CD:…`).
 */
@JvmInline
public value class CertificateFingerprint(
    public val sha256Hex: String,
) {
    /** The RFC 8122 SDP attribute value, e.g. `sha-256 AB:CD:EF:…` (uppercase, colon-separated). */
    public val sdp: String
        get() =
            "sha-256 " +
                sha256Hex.uppercase().chunked(2).joinToString(":")

    public companion object {
        /** Build from a lowercase/uppercase hex digest string (colons tolerated and stripped). */
        public fun ofHex(hex: String): CertificateFingerprint = CertificateFingerprint(hex.replace(":", "").lowercase())
    }
}

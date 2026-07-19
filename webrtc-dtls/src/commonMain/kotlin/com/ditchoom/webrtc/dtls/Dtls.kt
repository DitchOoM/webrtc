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
public value class CertificateFingerprint private constructor(
    public val sha256Hex: String,
) {
    /**
     * The digest half of the RFC 8122 attribute — uppercase hex, colon-separated (`AB:CD:EF:…`). This
     * is what goes in the `value` field of an SDP `a=fingerprint` line, whose hash function is always
     * `sha-256` for us (RFC 8827).
     */
    public val sdpValue: String
        get() = sha256Hex.uppercase().chunked(2).joinToString(":")

    /** The full RFC 8122 SDP attribute value, e.g. `sha-256 AB:CD:EF:…`. */
    public val sdp: String
        get() = "sha-256 $sdpValue"

    public companion object {
        private const val DIGEST_HEX_LENGTH = 64 // 32 SHA-256 bytes

        /**
         * Build from a hex digest string (case-insensitive, colons tolerated and stripped). This is the
         * ONLY way to make a [CertificateFingerprint]: the primary constructor is private so a value can
         * never hold a non-normalized or malformed digest. Equality and [sdpValue] both assume the
         * stored form is exactly 64 lowercase colon-free hex chars — the RFC 8122 `a=fingerprint`
         * comparison is a security discriminant (RFC 8827), so a casing- or format-fragile value here
         * would silently break peer authentication.
         *
         * @throws IllegalArgumentException if [hex] is not a 32-byte (64 hex-char) SHA-256 digest.
         */
        public fun ofHex(hex: String): CertificateFingerprint {
            val normalized = hex.replace(":", "").lowercase()
            require(normalized.length == DIGEST_HEX_LENGTH && normalized.all { it in "0123456789abcdef" }) {
                "not a SHA-256 digest: expected $DIGEST_HEX_LENGTH hex chars, got '$hex'"
            }
            return CertificateFingerprint(normalized)
        }
    }
}

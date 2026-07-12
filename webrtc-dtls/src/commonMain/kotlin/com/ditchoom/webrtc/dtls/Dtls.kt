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
 * An `a=fingerprint` value (hash-algorithm + digest), wrapped so a certificate fingerprint can never
 * be passed where some other hex string is expected. Digest stays a hex `String` here (placeholder);
 * the real type verifies in place over a buffer slice, never a [ByteArray].
 */
@JvmInline
public value class CertificateFingerprint(
    public val sha256Hex: String,
)

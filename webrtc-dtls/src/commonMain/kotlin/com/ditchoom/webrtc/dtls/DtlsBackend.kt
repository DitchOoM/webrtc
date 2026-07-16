package com.ditchoom.webrtc.dtls

/**
 * Backend availability probe. On Kotlin/Native Linux this returns a non-zero handle proving the
 * BoringSSL `libssl` link resolved (against buffer-crypto's `libcrypto`, one copy — the W4 linkage
 * de-risk). On targets whose real DTLS backend is deferred to `boringssl-kmp` it returns 0.
 *
 * Internal — the public surface is [DtlsEngine]; this only underpins the link-smoke test.
 */
internal expect fun dtlsBackendProbe(): Long

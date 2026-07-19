package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.ReadBuffer

// No native DTLS backend on Apple this wave. Unlike JVM/Android (where buffer-crypto is pure JCA and a
// boringssl-kmp DTLS surface would drop in clash-free), Apple additionally needs the buffer-crypto
// BoringSSL migration first — buffer-crypto is CommonCrypto here, so there is no already-linked
// libcrypto for a libssl.a to resolve against, and adding one re-creates the duplicate-symbol clash.
// See the EXECUTION_PLAN "W4 sequencing" row. Construction fails fast with a typed
// [DtlsFailureReason.BackendUnavailable]; the webrtc-root driver surfaces it as a typed
// PeerConnection failure rather than a hang.
public actual class DtlsEngine actual constructor(
    config: DtlsConfig,
) {
    init {
        throw DtlsException(
            DtlsFailureReason.BackendUnavailable,
            "DTLS backend not available on this target — Apple (boringssl-kmp Apple lane unbuilt; " +
                "requires the buffer-crypto BoringSSL migration)",
        )
    }

    public actual val localFingerprint: CertificateFingerprint get() = unavailable()

    public actual fun start(
        role: DtlsRole,
        nowMicros: Long,
    ): DtlsStep = unavailable()

    public actual fun onDatagram(
        record: ReadBuffer,
        nowMicros: Long,
    ): DtlsStep = unavailable()

    public actual fun onTimeout(nowMicros: Long): DtlsStep = unavailable()

    public actual fun send(
        applicationData: ReadBuffer,
        nowMicros: Long,
    ): DtlsStep = unavailable()

    public actual fun beginClose(nowMicros: Long): DtlsStep = unavailable()

    public actual fun nextTimeoutMicros(nowMicros: Long): Long? = unavailable()

    public actual fun close() {}

    private fun unavailable(): Nothing = throw DtlsException(DtlsFailureReason.BackendUnavailable)
}

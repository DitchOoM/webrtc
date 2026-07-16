package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.ReadBuffer

// No native DTLS backend on this target this wave — Android (boringssl-kmp prefab AAR pending). See the EXECUTION_PLAN
// "W4 sequencing" row. Construction fails fast with a typed [DtlsFailureReason.BackendUnavailable];
// the webrtc-root driver surfaces it as a typed PeerConnection failure rather than a hang.
public actual class DtlsEngine actual constructor(
    role: DtlsRole,
    config: DtlsConfig,
) {
    init {
        throw DtlsException(
            DtlsFailureReason.BackendUnavailable,
            "DTLS backend not available on this target — Android (boringssl-kmp prefab AAR pending)",
        )
    }

    public actual val localFingerprint: CertificateFingerprint get() = unavailable()

    public actual fun start(nowMicros: Long): DtlsStep = unavailable()

    public actual fun onDatagram(record: ReadBuffer, nowMicros: Long): DtlsStep = unavailable()

    public actual fun onTimeout(nowMicros: Long): DtlsStep = unavailable()

    public actual fun send(applicationData: ReadBuffer, nowMicros: Long): DtlsStep = unavailable()

    public actual fun beginClose(nowMicros: Long): DtlsStep = unavailable()

    public actual fun nextTimeoutMicros(nowMicros: Long): Long? = unavailable()

    public actual fun close() {}

    private fun unavailable(): Nothing = throw DtlsException(DtlsFailureReason.BackendUnavailable)
}

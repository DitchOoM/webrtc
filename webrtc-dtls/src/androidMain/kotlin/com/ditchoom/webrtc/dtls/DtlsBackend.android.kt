package com.ditchoom.webrtc.dtls

// Android DTLS is deferred to the boringssl-kmp prefab AAR + JNI (unpublished); see the
// EXECUTION_PLAN "W4 sequencing" row. No native backend on this target this wave.
internal actual fun dtlsBackendProbe(): Long = 0L

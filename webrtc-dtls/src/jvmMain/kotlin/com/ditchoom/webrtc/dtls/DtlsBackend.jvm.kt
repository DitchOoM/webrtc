package com.ditchoom.webrtc.dtls

// JVM DTLS is deferred to the boringssl-kmp FFM MRJAR (unpublished + DTLS surface not yet exported);
// see the EXECUTION_PLAN "W4 sequencing" row. No native backend on this target this wave.
internal actual fun dtlsBackendProbe(): Long = 0L

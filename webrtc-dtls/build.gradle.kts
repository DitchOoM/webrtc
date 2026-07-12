plugins {
    id("webrtc.multiplatform-library")
}

// Only this module's dependencies live here — targets, publishing, versioning, lint, and ABI
// validation all come from the webrtc.multiplatform-library convention (build-logic/).
kotlin {
    sourceSets {
        commonMain.dependencies {
            // The one native dependency (RFC §3): BoringSSL backends (FFM/JNI/cinterop) arrive in W4,
            // caller-clocked via DTLSv1_get_timeout. Key material lives in buffer-crypto secureFixedPool.
            api(libs.buffer)
            api(libs.buffer.crypto)
        }
    }
}

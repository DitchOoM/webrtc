plugins {
    id("webrtc.multiplatform-library")
}

// Only this module's dependencies live here — targets, publishing, versioning, lint, and ABI
// validation all come from the webrtc.multiplatform-library convention (build-logic/).
kotlin {
    sourceSets {
        commonMain.dependencies {
            // Pure-Kotlin sans-io SCTP subset (RFC §5.1). Reassembly rides buffer StreamProcessor;
            // the DataChannel mux implements buffer-flow StreamMux.
            api(project(":webrtc-dtls"))
            api(libs.buffer.flow)
        }
    }
}

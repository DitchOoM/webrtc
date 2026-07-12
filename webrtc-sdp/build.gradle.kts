plugins {
    id("webrtc.multiplatform-library")
}

// Only this module's dependencies live here — targets, publishing, versioning, lint, and ABI
// validation all come from the webrtc.multiplatform-library convention (build-logic/).
kotlin {
    sourceSets {
        commonMain.dependencies {
            // Pure text codec (RFC §3): hand-written parser/writer, zero platform code, zero I/O.
            api(libs.buffer)
            api(libs.buffer.codec)
        }
    }
}

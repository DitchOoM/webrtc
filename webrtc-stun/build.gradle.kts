plugins {
    id("webrtc.multiplatform-library")
}

// Only this module's dependencies live here — targets, publishing, versioning, lint, and ABI
// validation all come from the webrtc.multiplatform-library convention (build-logic/).
kotlin {
    sourceSets {
        commonMain.dependencies {
            // Pure codec module (RFC §3): zero platform code, zero I/O — runs everywhere including
            // browsers. STUN/TURN schemas are buffer-codec KSP-generated, decoded as views over the
            // datagram buffer (RFC §6), never extracted to arrays.
            api(libs.buffer)
            api(libs.buffer.codec)
        }
    }
}

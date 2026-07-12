plugins {
    id("webrtc.multiplatform-library")
}

// Only this module's dependencies live here — targets, publishing, versioning, lint, and ABI
// validation all come from the webrtc.multiplatform-library convention (build-logic/).
kotlin {
    sourceSets {
        commonMain.dependencies {
            // Published consumer harness (RFC §7): withWebRtcHarness { natType(); relayOnly(); impaired() }.
            // Wired into validate-artifacts from its first release (the socket #188 lesson).
            api(project(":webrtc"))
            api(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}

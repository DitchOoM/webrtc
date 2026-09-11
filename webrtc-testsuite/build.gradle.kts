plugins {
    id("webrtc.multiplatform-library")
}

// Only this module's dependencies live here — targets, publishing, versioning, lint, and ABI
// validation all come from the webrtc.multiplatform-library convention (build-logic/).
kotlin {
    sourceSets {
        commonMain.dependencies {
            // Published consumer harness (ARCHITECTURE §7): withWebRtcHarness { natType(); relayOnly(); impaired() }.
            // Wired into validate-artifacts from its first release (the socket #188 lesson).
            api(project(":webrtc"))
            api(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            implementation(libs.kotlinx.coroutines.test)
        }
        // QuicOverIceVnetTest drives two production IceAgentDrivers over THIS module's vnet (NAT +
        // STUN server) and then opens a real quiche connection on the nominated pair through
        // webrtc-quic. The vnet is `internal`, so the test has to live here; quiche is real-time and
        // JVM-hosted here, so it lives in jvmTest rather than commonTest.
        jvmTest.dependencies {
            implementation(project(":webrtc-quic"))
        }
    }
}

plugins {
    id("webrtc.multiplatform-library")
}

// Only this module's dependencies live here — targets, publishing, versioning, lint, and ABI
// validation all come from the webrtc.multiplatform-library convention (build-logic/).
kotlin {
    sourceSets {
        commonMain.dependencies {
            // The consumer API (RFC §3.1): PeerConnection as a Layer-2 session, DataChannel as StreamMux.
            // Browser/wasmJs peerConnectionSupport() delegates to RTCPeerConnection (added in W6).
            api(project(":webrtc-ice"))
            api(project(":webrtc-sctp"))
            api(project(":webrtc-sdp"))
            // The DTLS transport `PureKotlinDtls` drives. Pure Kotlin in commonMain on EVERY non-browser
            // target — there is no platform whose actual reports a missing backend. (This comment used to
            // say Native-Linux had BoringSSL and everyone else got a typed BackendUnavailable; that stopped
            // being true when the engine moved to commonMain, and BoringSSL survives only as a linuxTest
            // differential oracle.)
            api(project(":webrtc-dtls"))
            api(libs.buffer.flow)
            api(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            // runTest virtual time drives the whole session round-trip (offer/answer → ICE → SCTP → data)
            // at zero wall-clock on every platform. kotlin("test") comes from the convention.
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}

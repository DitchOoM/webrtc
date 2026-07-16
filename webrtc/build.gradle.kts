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
            api(libs.buffer.flow)
            // socket core (com.ditchoom:socket): the SocketException hierarchy every WebRTC failure maps
            // into (RFC §3.1 "one thrown vocabulary") + the SessionTransport model. Publishes all targets
            // incl. wasmJs/browser, so it is safe in commonMain (unlike socket-udp, which is real-UDP only).
            api(libs.socket)
            api(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            // runTest virtual time drives the whole session round-trip (offer/answer → ICE → SCTP → data)
            // at zero wall-clock on every platform. kotlin("test") comes from the convention.
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}

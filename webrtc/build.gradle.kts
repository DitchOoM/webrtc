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
        }
    }
}

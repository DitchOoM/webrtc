package com.ditchoom.webrtc.dtls

// Browsers never run our DTLS engine — peerConnectionSupport() delegates DTLS to the browser's
// RTCPeerConnection (RFC §1.1). No native backend on this target, by design.
internal actual fun dtlsBackendProbe(): Long = 0L

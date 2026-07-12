# Module webrtc

Zero-copy, deterministic, sans-io WebRTC data channels for Kotlin Multiplatform.

Phase 1 delivers `RTCDataChannel` semantics (ICE + DTLS + SCTP + DCEP + JSEP/SDP) built in common
Kotlin over the DitchOoM `buffer` and `socket` libraries. The protocol cores are sans-io and
caller-clocked, so the whole stack runs under virtual time. Browser targets delegate to
`RTCPeerConnection`; every other target runs our own stack over a `DatagramChannel` seam.

See `README.md` for the module map and `RFC_KMP_WEBRTC.md` for the architecture. This file is the
Dokka module descriptor (rendered into the API docs site).

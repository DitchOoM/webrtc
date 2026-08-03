# Module webrtc

WebRTC data channels for Kotlin Multiplatform — zero-copy, sans-io, and deterministic under test.

`com.ditchoom:webrtc` implements ICE, DTLS, SCTP, DCEP and JSEP/SDP in common Kotlin over the DitchOoM
`buffer` and `socket` libraries. It is not a libwebrtc wrapper: the protocol cores are ours, sans-io and
caller-clocked, so a full establishment replays under virtual time on every platform. Browsers are the
one exception — there `peerConnectionSupport()` delegates to the platform's own `RTCPeerConnection`;
every other target runs our stack over an injected `AddressedDatagramChannel`.

Start at `RtcPeerConnection` (the session API), `NativePeerConnection` (the native implementation and
its injected seams), and `udpDatagramBinder()` in `webrtc-ice` (the real-UDP seam to hand it). A data
channel is a buffer-flow `Connection<ReadBuffer>`.

Media (RTP/SRTP) is not implemented.

The project's `README.md` has a quickstart; `ARCHITECTURE.md` explains how the pieces fit and why.

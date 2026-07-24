# webrtc

**Zero-copy, deterministic, sans-io WebRTC data channels for Kotlin Multiplatform.**

`com.ditchoom:webrtc` is a WebRTC stack built in common Kotlin on top of the DitchOoM
[`buffer`](https://github.com/DitchOoM/buffer) and [`socket`](https://github.com/DitchOoM/socket)
libraries. It runs its protocol cores — ICE, DTLS, SCTP — on **our own driver over a `DatagramChannel`
seam on every platform**, rather than wrapping libwebrtc. The one exception is browsers, where there is
no raw UDP, so the implementation delegates to the platform's `RTCPeerConnection`.

> **Status: pre-release, W0 (foundations).** The module tree builds and publishes across the full
> target matrix; the protocol cores are being implemented wave by wave. See
> [`EXECUTION_PLAN.md`](./EXECUTION_PLAN.md).

## Why not wrap libwebrtc?

| | Wrap libwebrtc | Own stack over buffer + socket (this project) |
|---|---|---|
| Zero-copy | Impossible — every frame crosses a JNI/ObjC boundary as a `ByteArray`/`NSData` copy | `ReadBuffer`/`WriteBuffer` end to end |
| Determinism | None — libwebrtc owns its threads, timers, RNG | Every core caller-clocked; the whole stack runs under `runTest` virtual time |
| Testing | Black box; field bugs unreproducible | Timeline fixtures, seeded fuzz, shrinker — field bugs become committed regression tests |
| Platforms | Android/iOS only | Full KMP matrix, including JVM server-side and Linux |

The precedent is `socket-quic-quiche`: a full transport protocol (QUIC) already runs on our own driver
over a UDP seam on every platform. WebRTC is the same shape — plus ICE in front and SCTP behind — and
this time the protocol cores are ours, which is what makes deterministic replay possible.

## Scope

Phase 1 delivers `RTCDataChannel` semantics (ICE + DTLS + SCTP + DCEP + JSEP/SDP) — the part with no
codec/hardware dependencies, slotting directly into the existing `StreamMux`/`MultiplexingTransport`
world so MQTT/RPC/codec consumers can ride a peer-to-peer data channel with zero new API. Phase 2 adds
RTP/RTCP/SRTP (media *transport*); codec encode/decode stays platform-native and outside this library.

**Signaling is a seam, never an implementation.** The library exchanges `SessionDescription` /
`IceCandidate` values through an interface you supply — no HTTP, no WebSocket, no opinion. This is both
correct layering (WebRTC standardizes no signaling protocol) and what makes the offer/answer state
machines fully deterministic in tests.

## Modules

| Module | What | Wave |
|---|---|---|
| `webrtc` | PeerConnection + JSEP state machine + DataChannel — the consumer API | W6 |
| `webrtc-sdp` | SDP parse/serialize — pure `buffer-codec`, no I/O | W6 |
| `webrtc-stun` | STUN/TURN wire codec (RFC 8489/8656) + sans-io transactions | W1 |
| `webrtc-ice` | ICE agent (RFC 8445 + trickle 8838) — sans-io core + gathering seams | W3 |
| `webrtc-dtls` | DTLS 1.2/1.3 + DTLS-SRTP exporter — BoringSSL backends | W4 |
| `webrtc-sctp` | SCTP subset over DTLS (RFC 8831) + DCEP (RFC 8832) — pure Kotlin | W5 |
| `webrtc-testsuite` | Published consumer harness: vnet, timeline engine, control plane | W7 |

## Intended API (Phase 1)

```kotlin
val pc = PeerConnection(config)                       // held; use { } sugar via SessionTransport
pc.createDataChannel("chat")                          // pre-negotiated or DCEP
val offer = pc.createOffer(); pc.setLocalDescription(offer)
// your app ships the offer/candidates over ITS signaling and feeds back
// setRemoteDescription / addIceCandidate

// A data channel IS a buffer-flow StreamMux: openBidirectional() etc. Anything written against
// MultiplexingTransport-style mux code runs over WebRTC unchanged.
```

## Building

```bash
./gradlew build                 # all modules, all host-available targets
./gradlew allTests              # tests across every module + platform
./gradlew publishToMavenLocal   # publish 0.0.x to ~/.m2
```

Requires **JDK 21** (via toolchain). Apple targets build on macOS. Per-module build configuration is a
single convention plugin (`build-logic/`) — a module's own build file carries only its dependencies.

## Design

Two properties drive every decision — zero-copy throughput and deterministic replay — and both are
enforced, not aspirational. See [`DESIGN_PRINCIPLES.md`](./DESIGN_PRINCIPLES.md) (type-safety + zero-copy
manifesto), [`RFC_KMP_WEBRTC.md`](./RFC_KMP_WEBRTC.md) (architecture),
[`TESTING.md`](./TESTING.md) (unit → integration → interop strategy), and
[`CLAUDE.md`](./CLAUDE.md) (standing directives).

## Testing

Because every core is sans-io and caller-clocked, the full stack (ICE + DTLS + SCTP) integration-tests
**deterministically under virtual time on every platform** — a rarity for WebRTC. Foreign-peer interop
(Pion, headless Chrome) finds bugs; each one is demoted into a committed deterministic fixture, so it
never flakes again. Real STUN/TURN (coturn), real NAT (iptables profiles), and impairment (netem) run
in the container harness. Every Linux-only harness scenario — including v6 NAT traversal, `firewall-relay6`
forced relay, and dual-stack fallback — has a matching virtual-time fixture, so **macOS / iOS / Node /
wasm / Android inherit the same coverage**; see the L1↔L2 parity matrix and full strategy in
[`TESTING.md`](./TESTING.md).

## License

Apache 2.0 — see [`LICENSE.md`](./LICENSE.md).

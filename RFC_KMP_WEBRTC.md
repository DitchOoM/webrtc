# RFC — `com.ditchoom:webrtc`: a zero-copy, deterministic, KMP WebRTC stack

**Status:** Draft for discussion · **Date:** 2026-07-11
**Builds on:** `com.ditchoom:buffer` (zero-copy buffers, codec, crypto, flow) and `com.ditchoom:socket`
(Transport/SessionTransport model, typed error vocabulary, `NetworkMonitor`, the deterministic
simulation engine from `RFC_DETERMINISTIC_SIMULATION.md`, and the container harness from
`TESTING_STRATEGY.md`).

---

## 1. The one decision everything else follows from

**Build the protocol stack in common Kotlin; do not wrap libwebrtc.** Browsers are the sole
exception (no raw UDP in a browser — physics, not an API gap), and there the `actual` delegates to
the platform's `RTCPeerConnection`, exactly the `webTransportSupport()` precedent.

| | Wrap libwebrtc (Android/iOS SDKs) | Own stack over buffer+socket |
|---|---|---|
| Zero-copy | Impossible — every frame/message crosses a JNI/ObjC boundary as `ByteArray`/`NSData` copies | `ReadBuffer`/`WriteBuffer` end-to-end; the "No ByteArray in Production" rule holds |
| Determinism | None — libwebrtc owns its threads, timers, and RNG | Every state machine caller-clocked; whole stack runs under `runTest` virtual time |
| Testing | Black box; field bugs unreproducible | Timeline fixtures, seeded fuzz, shrinker — field bugs become committed regression tests |
| Platforms | No Linux K/N, no JVM server, no wasm | Full existing target matrix, including server-side |
| Cost | Low upfront | High upfront — mitigated by scoping (§2) and by how much already exists (§4) |

The precedent is `socket-quic-quiche`: we already run a full transport protocol (QUIC) on our own
driver over a `UdpChannel` seam on every platform. WebRTC is the same shape — plus ICE in front and
SCTP behind — and this time the protocol cores are **ours**, which fixes the one thing quiche
couldn't give us (see §5.1).

## 2. Scope: data channels first, media second

Phase 1 delivers `RTCDataChannel` semantics (ICE + DTLS + SCTP + DCEP + JSEP/SDP) — the part with
no codec/hardware dependencies, and the part that slots directly into the existing
`StreamMux`/`MultiplexingTransport` world so MQTT/RPC/codec consumers can ride a peer-to-peer data
channel with zero new API. Phase 2 adds RTP/RTCP/SRTP (media *transport* — packetization and
crypto are pure common Kotlin over `buffer-crypto`); codec integration (encode/decode) stays
platform-native and out of the transport library, permanently.

**Signaling is a seam, never an implementation.** The library exchanges `SessionDescription` /
`IceCandidate` values through an interface the app supplies. No HTTP, no WebSocket, no opinion.
This is both correct layering (WebRTC standardizes no signaling protocol) and what makes offer/answer
state machines fully deterministic in `commonTest`.

## 3. Module map (mirrors buffer's layering: one core, thin layers on top)

```
webrtc/                     PeerConnection + JSEP state machine + DataChannel (the consumer API)
├── webrtc-sdp              SDP parse/serialize — pure buffer-codec module, no I/O
├── webrtc-stun             STUN/TURN wire codec (RFC 8489/8656) — pure codec + sans-io client machines
├── webrtc-ice              ICE agent (RFC 8445 + trickle 8838) — sans-io core + gathering seams
├── webrtc-dtls             DTLS 1.2/1.3 + DTLS-SRTP exporter — BoringSSL backends (the one native dep)
├── webrtc-sctp             SCTP subset over DTLS (RFC 8831) + DCEP (RFC 8832) — pure Kotlin, sans-io
├── webrtc-rtp              (Phase 2) RTP/RTCP codec — pure buffer-codec module
├── webrtc-srtp             (Phase 2) SRTP/SRTCP — in-place AEAD via buffer-crypto
└── webrtc-testsuite        published consumer harness: vnet, timeline engine, container control plane
```

Dependency rules, same as buffer's: each layer depends only downward; the pure-codec modules
(`-sdp`, `-stun`, `-rtp`) have **zero** platform code and zero I/O — they are `commonMain`-only and
run everywhere including browsers. Platform code exists in exactly two places: `webrtc-dtls`
backends and the UDP/mDNS gathering actuals in `webrtc-ice`.

### 3.1 The consumer API surface

```kotlin
val pc = PeerConnection(config)                     // held; use { } sugar via SessionTransport convention
pc.createDataChannel("chat")                        // pre-negotiated or DCEP
val offer = pc.createOffer(); pc.setLocalDescription(offer)
// app ships offer/candidates over ITS signaling; feeds back setRemoteDescription/addIceCandidate
```

- `PeerConnection` implements the **Layer-2 session** convention from `RFC_UNIFIED_ESTABLISHMENT`
  (`establish` is signaling-shaped, not host:port-shaped, so it is *only* a session type — WebRTC
  never pretends to be a `Transport.connect(host, port)`; that would lie about addressing).
- The data-channel mux implements buffer-flow's **`StreamMux<T>`** (and the raw `ByteStreamMux`
  once that lands): a data channel *is* `openBidirectional()`. Anything written against
  `MultiplexingTransport`-style mux code runs over WebRTC unchanged.
- Capability-by-type, no stubs: media capabilities in Phase 2 arrive as an `is`-checkable interface
  on the session, exactly like `WebTransportSupport.Multiplexed`.
- **One thrown vocabulary:** everything maps into the `SocketException` sealed hierarchy with
  `ConnectionFailureReason`-style exhaustive causes; ICE failure, DTLS failure, and SCTP abort get
  their own sealed reasons (`IceFailureReason.NoCandidatePairs`, `.ConsentExpired`, …). Strings are
  diagnostics, never discriminants (#166 discipline).
- Browser/wasmJs: `peerConnectionSupport()` `expect fun` returns the RTCPeerConnection-delegating
  implementation; `networkCapabilities()` reports it, and the sans-io/native modules are simply
  absent from the browser dependency graph.

## 4. What already exists (reuse audit)

| Need | Have | Gap |
|---|---|---|
| Zero-copy buffers, slices, native handles | `buffer` (`PlatformBuffer`, `NativeData`, position/slice) | headroom/tailroom reservation helper for in-place SRTP tags (small additive API) |
| Wire codecs, KSP-generated | `buffer-codec` — `@ProtocolMessage` data classes, sealed `@PacketType`/`@DispatchOn` dispatch, generated `peekFrameSize` (already round-trips TLS/WebSocket/MQTT framings) | STUN/RTP/SCTP-chunk schemas — **generated, not hand-written**, per the buffer discipline; SDP is text so it gets a hand parser with the same T0 rigor |
| Fragmented-stream reassembly | `buffer` `StreamProcessor` (`peek`, `readBufferScoped{}` auto-release to pool) | none — this is the SCTP reassembly substrate |
| AEAD (AES-GCM), HKDF, HMAC, constant-time, CryptoRandom, `secureFixedPool` for key material | `buffer-crypto` | SRTP KDF (RFC 3711 §4.3) — derivable from existing primitives; HMAC-SHA1 only if legacy SRTP_AES128_CM_SHA1_80 is kept (prefer GCM-only) |
| Stream mux abstraction | `buffer-flow` `StreamMux`/`ByteStream`/`ReadResult.Reset` | none |
| Async UDP per platform | `socket-quic-quiche`'s `UdpChannel` + `UdpChannelFactory` (JVM NIO/io_uring, Apple NWConnection, Linux, Node) | **unconnected mode**: ICE needs `receive` to return the source address and `send` to target arbitrary candidates from one socket (the server-side `dest` param and `PathKey` are most of it). Promote a `DatagramChannel` seam into socket-core |
| Network awareness | `NetworkMonitor` (availability + `NetworkId`), `Liveness` | none — ICE restart triggers ride the same signals `ReconnectingConnection` uses |
| Deterministic engine | `TimelineInterpreter`, `TestClock` bridge, `ManualDriverClock` pattern, fixture→Kotlin codegen, ddmin shrinker, `TrackingBufferFactory` | **promote from socket-quic-quiche commonTest into a published module** (`socket-testsuite` or a new `ditchoom-simulation`) so webrtc consumes it instead of forking it |
| Container harness | `test-harness/` compose stack, toxiproxy, netem profiles, controller `/describe`, arch-matched CI matrix, Colima | add `coturn` (STUN/TURN), NAT-profile containers, interop peers (§6.4) |
| DTLS building blocks | BoringSSL already vendored + built per-platform for quiche; cinterop/JNI/FFM plumbing patterns proven | DTLS-specific surface: `SSL_CTX` with BIO pairs, `DTLSv1_get_timeout`, SRTP exporter |

## 5. Determinism architecture

### 5.1 Sans-io, caller-clocked cores — the quiche lesson, inverted

The simulation RFC's W4 finding was that quiche internally reads Rust's `Instant::now()`, so
timer-dependent scenarios (PTO, idle timeout) can never run under virtual time — Tier A stubs exist
*because* the protocol core isn't ours. This project's cores **are** ours, so the rule is absolute:

> Every protocol state machine (ICE checklist, STUN transactions, SCTP, DCEP, JSEP) is a pure
> `handle(event, now): List<Output>` function plus a `nextDeadline(now): Instant?`. No dispatcher,
> no `Clock.System`, no `Random.Default`, no I/O, no coroutine inside a core. Drivers own I/O;
> cores own truth.

Consequences:
- A **full ICE + SCTP establishment completes under `runTest` at zero wall-clock** on every target.
  A 90-second field ICE saga (consent timeouts, TURN refresh, nomination flaps) replays in
  milliseconds, forever.
- The only real-time residue in the whole stack is BoringSSL's DTLS internals — and unlike quiche,
  **BoringSSL DTLS is caller-clocked** (`DTLSv1_get_timeout` hands the deadline out; the driver
  fires `DTLSv1_handle_timeout`). Handshake retransmission is therefore virtual-time drivable too.
  The residue shrinks to BoringSSL's RNG shaping ClientHello bytes — the same measured ±1-datagram
  drift Tier B already bounds explicitly for QUIC.
- Seeded entropy from day one, not retrofitted (sim-RFC §3.1 item 3 was a retrofit): injected
  `Random` feeds ICE tie-breaker, ufrag/pwd, STUN transaction IDs, SSRC, foundation IDs; injected
  `Clock` feeds everything else. Production defaults are `CryptoRandom`/system clock via one
  constructor parameter, never a hardwired call.

### 5.2 The vnet — the WebRTC-specific addition

ICE bugs live in NAT behavior. A pure-Kotlin **virtual network** in the (published) simulation
module models routers deterministically on the virtual clock:

- NAT profiles: full-cone, address-restricted, port-restricted, symmetric; configurable mapping
  lifetimes, hairpinning on/off, per-direction filtering — each a small pure state machine.
- Topologies as data: two peers behind distinct symmetric NATs + a vnet TURN server is the
  canonical "relay-only" fixture; double-NAT, IPv6-only, and interface-change (Wi-Fi→cellular
  `NetworkId` flip mid-session) are timelines, not lab setups.
- The vnet implements the same `DatagramChannel` seam production uses, so the entire native stack —
  ICE, DTLS (real BoringSSL), SCTP — runs end-to-end through simulated NATs in `commonTest` on
  every platform. This is Tier B with the Tier A property, because the cores are caller-clocked.

### 5.3 Timelines, fixtures, invariants

Reuses the engine verbatim: input events (`DatagramIn(bytes, from)`, `AvailabilityChanged`,
`NetworkChanged`, `LivenessResult`, `ClockAdvance`, plus new `SignalingIn(sdp|candidate)`) drive the
seams; observation snapshots (ICE pair states, nomination, DTLS state, SCTP cwnd/RTO, buffer
accounting) are golden trajectories, not just crash-avoidance. `TraceRecorder` taps the
`DatagramChannel` decorator + state `StateFlow`s + the signaling seam; a field bundle from a debug
app build *is* the bug report *is* the regression test. Seeded timeline fuzz + ddmin shrinker run
over the vnet; standing invariants:

1. no buffer leaks (`TrackingBufferFactory.assertNoLeaks()`),
2. ICE pair/checklist and `PeerConnection` states never take an illegal transition,
3. every native DTLS wrapper freed; every TURN allocation released,
4. errors surface typed, never as strings,
5. liveness: the session reaches Connected or a typed terminal failure — it never hangs,
6. SCTP: no message reordered within a stream, no unacked data dropped, DCEP always converges.

## 6. Zero-copy datapath

The packet path is one pooled `PlatformBuffer` per datagram, end to end:

1. **Receive:** driver takes a buffer from the pool, `DatagramChannel.receive` fills it (direct
   ByteBuffer / `NWConnection` dispatch_data / pinned native memory — the existing per-platform
   tricks).
2. **Demux without copying (RFC 7983):** first byte routes STUN (0–3) / DTLS (20–63) / RTP (128–191).
   Routing passes the *same buffer*; parsers are positional views (`slice()`), never extractions.
3. **STUN/RTP parse = views.** `buffer-codec` schemas decode attributes as offsets into the
   datagram buffer; MESSAGE-INTEGRITY/fingerprint verify reads in place.
4. **DTLS = native-memory BIO.** The BoringSSL boundary uses memory BIOs fed with
   `toNativeData()` handles (FFM `MemorySegment` on JVM, `CPointer` under cinterop, `jbyteBuffer`
   direct on Android JNI) — no `ByteArray` at the FFI edge. Where a platform API genuinely demands
   one, the `@Suppress("NoByteArrayInProd")` + named-API-surface comment rule applies unchanged.
5. **SCTP:** user messages are `ReadBuffer` slices chained into chunks; fragmentation/reassembly is
   a list of retained slices, coalesced only at the consumer's request (the `ByteStream.read()`
   contract already allows chunked delivery).
6. **SRTP (Phase 2) = in-place AEAD.** Packets are encrypted/decrypted in the same buffer;
   allocation reserves tag tailroom up front (the one small additive `buffer` API). GCM-only
   suites keep it single-pass.
7. **Factory + pool discipline:** one `BufferFactory` constructor parameter everywhere
   (production: the size-class pool from the ART-allocator work; tests: `TrackingBufferFactory`),
   lifecycle via the uniform `use { }` / `readBufferScoped { }` idioms, so invariant 1 in §5.3 is
   enforcement, not aspiration. The buffer **slice-lifetime contract** (a slice must not outlive
   its parent's pool scope) is what makes view-based parsing safe over pooled datagrams: a parsed
   packet's views die when the driver returns the datagram buffer, and anything that must outlive
   it pays an explicit `copy*`-verb cost — cost is visible in the API name, per the buffer
   convention. Key material lives in `buffer-crypto`'s `secureFixedPool` (wiped on free).

## 7. Testing tiers (mirrors the socket strategy 1:1)

| Tier | What | Where it runs |
|---|---|---|
| **T0 — codec floor** | round-trip + property tests + committed malformed-packet corpus for STUN/SDP/SCTP/RTP parsers; assert parse-fail is a typed reject, never a throw-through or crash | commonTest, all platforms |
| **T0′ — coverage-guided fuzz** | Jazzer over the *pure-Kotlin* parsers. Unlike the quiche lanes, the JVM fuzzer finally gets real coverage feedback — the parsers are JVM bytecode, not opaque native. No cargo-fuzz lane needed for our code; BoringSSL keeps its upstream fuzzing | jvmTest, time-boxed CI lane |
| **TA — timeline replay** | fixtures + seeded fuzz + shrinker over vnet/stub seams, virtual time | commonTest, all platforms, <1s smoke + env-sized JVM deep run |
| **TB — real-stack vnet** | full native stack (real BoringSSL) through simulated NATs/impairment, seeded; strict trace-prefix invariants, RNG drift bounded explicitly | commonTest, native + JVM |
| **Integration** | container harness: `coturn`, NAT-profile containers (iptables), netem impairment profiles, toxiproxy for the signaling channel | harness CI job, arch-matched matrix (no QEMU), Colima on macOS |
| **Interop** | our native stack ⇄ real peers: a Pion echo container, and **headless Chrome via Karma driving real `RTCPeerConnection`** against our JVM stack — this doubles as the browser-delegation test | harness CI job |
| **Consumer** | `webrtc-testsuite` published: `withWebRtcHarness { natType(Symmetric); relayOnly(); impaired(loss = 5.percent) { … } }` — consumers write plain commonTest, no docker CLI | consumers' commonTest |
| **Benchmarks** | kotlinx-benchmark in a shared `commonBenchmark` source set (the buffer pattern): STUN parse, RTP header parse, SRTP seal/open ops/sec per platform, tracked in a `PERFORMANCE.md` with regression tables | named benchmark configs, on demand + release |

Assertion discipline carried over wholesale: observable state + watchdog, never wall-clock budgets;
scenario = port; `harness.env` → generated `HarnessConfig`; skip-on-unreachable probes;
green-throughout migration rule; wrapper-transparency tests (everything must work when handed a
`PooledBuffer`/`TrackedSlice`, not just a raw `PlatformBuffer`).

## 8. Build, CI, publishing (inherit, don't invent)

Same target matrix as socket (JVM, Android, JS Node, browser-delegated JS/wasmJs, Linux x64/arm64,
Apple), JDK 21 toolchain, ktlint blocking + detekt baseline-gated (detekt is the only analyzer that
sees Native/JS/WASM actuals — the buffer rationale), **binary-compat `.api` validation** with
checked-in per-module `.api` files, kover, dokka→Docusaurus, osv-scanner blocking, actions pinned
to SHAs. Versioning auto-derived from Maven Central metadata with PR-label bumps
(`major`/`minor`/patch), Keep-a-Changelog `CHANGELOG.md`, publish gated on buffer's
`prePublishCheck` aggregate (allTests + the browser/Android-host suites `allTests` skips — the
suites that masked real bugs), and — the socket-webtransport #188 lesson — every published artifact
including `webrtc-testsuite` wired into `validate-artifacts.yaml` from its first release. BoringSSL
builds reuse the quiche build infrastructure (same pinned version, same per-target scripts) rather
than a second vendoring; the JVM DTLS backend ships FFM in a multi-release JAR the way buffer packs
its Java 21 classes.

## 9. Waves

| Wave | Scope | Depends on |
|---|---|---|
| W0 | Repo skeleton from socket conventions; promote the simulation engine + `DatagramChannel` seam (unconnected UDP w/ source addresses) into published homes | — |
| W1 | `webrtc-stun` codec + sans-io transactions + T0/T0′ fuzz floor | W0 |
| W2 | vnet (NAT models, virtual TURN) in the simulation module | W0 |
| W3 | `webrtc-ice` agent, gathering actuals (srflx via STUN, relay via TURN, mDNS), TA timelines: dual symmetric-NAT relay fixture green under virtual time | W1, W2 |
| W4 | `webrtc-dtls` backends (FFM/JNI/cinterop over vendored BoringSSL), caller-clocked driver, SRTP key exporter | W0 |
| W5 | `webrtc-sctp` + DCEP + `DataChannel` as `StreamMux`; end-to-end TB: two full stacks over vnet exchange data channel messages deterministically | W3, W4 |
| W6 | `webrtc` root: JSEP/SDP (`webrtc-sdp` lands here), `PeerConnection`, browser `RTCPeerConnection` actuals, typed error sweep | W5 |
| W7 | Container harness (coturn, NAT profiles, Pion + Chrome interop), `webrtc-testsuite` publish, consumer-smoke project | W6 |
| W4b | *(candidate, §11.5)* pure-Kotlin **DTLS 1.3** core over `buffer-crypto` in `commonMain` — retires the one native dep, lights up every target, kills the duplicate-symbol class + unblocks the `SocketException` bridge. 1.3-first; 1.2 later for Pion breadth. BoringSSL stays as the differential oracle. | W4, + an additive `buffer-crypto` raw-AES-block PR (RFC 9147 §4.2.3 seq-num encryption) |
| P2 | `webrtc-rtp`/`webrtc-srtp`, media transport surface (capability-by-type), platform codec adapters *outside* this library | W6 |

## 10. Non-goals

- Wrapping libwebrtc on any non-browser platform (defeats zero-copy and determinism — §1).
- A signaling implementation (seam only — §2).
- Codec encode/decode inside the transport library (Phase-2 adapters live outside).
- Legacy interop breadth (DTLS 1.0, SDES-SRTP, RTP over TCP/ICE-TCP) — modern profile only until an
  interop matrix demands otherwise; each exception must arrive with a harness lane.

## 11. Open questions for sign-off

1. **Simulation engine home:** grow `socket-testsuite` (webrtc depends on socket anyway) vs. a new
   standalone `ditchoom-simulation` both repos consume. Recommendation: standalone — buffer-flow
   could use it too, and it decouples release cadences.
2. **SCTP scope:** dcSCTP-style data-channel subset (no multihoming, no interleaving initially) —
   recommend yes; full RFC 9260 is not needed for RTCDataChannel semantics.
3. **DTLS 1.3 (RFC 9147) from day one** with 1.2 fallback, or 1.2-first for interop breadth?
   Recommendation: implement against BoringSSL's surface so both are config, interop-test 1.2
   (what libwebrtc/Pion actually speak today).
4. **mDNS candidates (`.local` obfuscation):** gathering-side responder is platform work
   (multicast) — ship in W3 or defer behind a flag? Recommendation: resolve-only in W3 (needed to
   *reach* browser peers), responder deferred.
5. **Pure-Kotlin DTLS 1.3 over `buffer-crypto` — retire the one native dependency?** (raised
   2026-07-16, after W4-native landed.) §1 says the protocol cores are **ours**; DTLS is the single
   exception, and it is the exception that costs the most: the cinterop/`libssl` provisioning, the
   duplicate-symbol hazard against buffer-crypto's libcrypto, the deferred `SocketException` bridge
   (blocked *only* by BoringSSL colliding with socket's vendored copy), and the whole
   `boringssl-kmp` sequencing problem — **every one of which exists solely because we link
   BoringSSL.** A `commonMain` DTLS core would delete all of it at once and light up **every**
   target (JVM/Android/Apple/Linux) with no backend gap, no FFI edge, no memory-BIO copy, and no
   thread-local clock hack — i.e. true sans-io + true zero-copy, exactly like `webrtc-sctp`.
   - **What BoringSSL actually gives us is the *protocol*, not the crypto.** The whole `bd_*` surface
     is: the handshake FSM + record layer + retransmission, self-signed X.509 generation (ASN.1 DER —
     serialization, not crypto), `X509_digest` fingerprints (just SHA-256 over the DER), and the
     DTLS-SRTP exporter (Phase 2). The primitives underneath are already in `buffer-crypto`.
   - **Primitive coverage (audited 2026-07-16): essentially complete.** `Hkdf` exposes
     `extractInto`/`expandInto` **separately** — precisely the TLS 1.3 key-schedule shape (Derive-Secret
     expands an existing secret), and buffer-side so it stays zero-copy; plus AEAD (AES-GCM +
     ChaCha20-Poly1305), `KeyAgreement` (X25519 / P-256), ECDSA + Ed25519 with `EcdsaSignatureEncoding`,
     streaming SHA-256/384/512 (transcript hash), HMAC, constant-time compare, `CryptoRandom`,
     `secureFixedPool`, even an `HpkeKdf`. That covers `TLS_AES_128_GCM_SHA256` + `key_share` +
     `ecdsa_secp256r1_sha256` — the entire mandatory WebRTC profile.
   - **One gap:** no raw AES block/ECB, needed for DTLS 1.3 record **sequence-number encryption**
     (RFC 9147 §4.2.3). Additive upstream `buffer-crypto` PR — the W1 precedent (HMAC-SHA1 + `crc32`
     landed in buffer#288 and shipped *before* webrtc consumed them). DTLS 1.2 needs no such primitive.
   - **Why 1.3-first is now the tractable direction** (this inverts the earlier "you'd have to write
     the crufty 1.2 half first" objection): both browser engines ship 1.3 today (§11.3), so a
     **1.3-only** core already talks to the whole browser field, and DTLS **negotiates** — 1.2 is an
     optional later add for breadth (Pion's released v3, legacy SFUs), not a prerequisite. TLS 1.3 is
     also deliberately the *simpler, more misuse-resistant* protocol (no renegotiation, no CBC,
     AEAD-only, simplified state machine); the classic TLS footguns live in 1.2.
   - **Cost / risk:** ~3–6k lines of security-critical code — handshake FSM, key schedule, record
     layer with epochs + anti-replay, flight fragmentation/reassembly + ACKs (RFC 9147 §7), and a
     bounded ASN.1 DER slice (emit a fixed self-signed template; from the peer, extract only the
     SubjectPublicKeyInfo for CertificateVerify — the fingerprint itself needs no parsing). Rolling
     the *protocol* over vetted *primitives* is well-trodden (Pion, rustls, Go `crypto/tls`), but
     protocol bugs are vulnerabilities, not defects: this needs the T0 reject/fuzz discipline
     throughout.
   - **Recommendation: yes, as its own wave — not instead of W4.** W4-native is proven and un-gates
     the W5/W6 end-to-end TB fixture; it must land. Nothing is wasted by doing so: `DtlsEngine` is
     already a caller-clocked sans-io `expect` class, so a pure-Kotlin core satisfies that exact
     interface and simply *becomes* the `commonMain` implementation (the expect/actual disappears),
     inheriting the handshake + TB fixtures as its conformance suite on day one. And **keep the
     BoringSSL backend permanently as the differential-testing oracle** — handshaking
     pure-Kotlin ↔ BoringSSL in both directions over the vnet under virtual time is the single best
     way to validate a from-scratch TLS stack. Gate the wave on the `buffer-crypto` AES-block PR.

# Changelog

All notable changes to `com.ditchoom:webrtc` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are auto-derived from Maven Central
metadata + PR-label bumps (`major` / `minor`, else patch).

## [Unreleased]

### Added — W7 Phase 2(b): headless-browser interop lanes (Chrome + Firefox) + wasmJs browser delegation
- **`chrome-interop` + `firefox-interop` scenarios** — our native `linuxX64` offerer establishes a full
  WebRTC data channel against a real **headless browser** (Playwright, `test-harness/browser/` — one
  `BROWSER`-parameterized image, two engines) over **DTLS 1.3** (the native peer runs at its production
  default — the opposite of the Pion 1.2 lane), and echoes `ping`→`pong` bidirectionally across a
  port-restricted NAT. Two differential oracles beyond Pion: **Chrome** (Chromium's libwebrtc / BoringSSL /
  dcSCTP) and **Firefox** (a *fully independent* stack — **NSS** DTLS, **nICEr** ICE, **usrsctp** — sharing
  nothing with Chrome). **Both runtime-validated on this box** — native offerer CONNECTED at DTLS 1.3, the
  browser `received "ping" (string=false)` → `echoed "pong"` → offerer got `pong`.
- **Rendezvous HTTP face** — a browser has no raw UDP, so `rendezvous.py` grew a threaded HTTP front door
  (`POST /put` + `GET /poll`, CORS-open) onto the **same** in-memory mailbox the UDP peers use (shared under
  a lock). A browser and a native peer therefore meet in the same slot: the native offerer PUTs its offer
  over UDP, Chrome polls it over HTTP; Chrome PUTs its answer over HTTP, the native peer polls it over UDP.
  Backward-compatible — the native UDP lane still establishes unchanged.
- **wasmJs `peerConnectionSupport()` delegation** — the last open W6 browser gap closed. The wasmJs actual
  now delegates to the browser `RTCPeerConnection` for real (was `NotImplementedError`), mapped through the
  `@JsFun` / `JsString` wasm-interop bridge (opaque `external interface : JsAny` handles; data-channel
  payloads cross as byte-faithful lowercase hex — no `ByteArray`, no webgl externals). **Runtime-validated
  in a real headless Chrome** via a new `wasmJsTest` loopback (mirror of the js delegation Karma test);
  green on `wasmJsBrowserTest` (ChromeHeadless) and no-ops on `wasmJsNodeTest`.
- **Wiring:** `docker-compose.yml` adds profile-gated `chrome` + `firefox` services (drop-ins for the native
  `peer_b` on `nat_b`/`PEER_B_IP`, DTLS 1.3 default, mDNS host-candidate obfuscation disabled per engine so
  our parser is fed real-IP candidates); `run-interop.sh` gains `b_impl=chrome|firefox` cases + the two
  scenarios, plus a positional **allowlist** and a `HARNESS_SKIP` **skiplist** for scenario selection;
  `harness-l2.yaml` runs the browsers as a parallel **`{arch × browser}` matrix** (`l2-browser`) split from
  the native `l2` job (which uses `HARNESS_SKIP` to drop them) — each image builds natively per-arch inside
  its job (Playwright fetches the per-arch engine), no cross-compile, no QEMU; `README.md` documents it.
- **Fixed (harness bug this surfaced):** `run-interop.sh`'s scenario loop read the scenario list from
  **stdin**, which `docker compose exec` (the netem `impaired` lane) attaches to and drains — so the matrix
  silently stopped after the first netem scenario, running **7/9** and never reaching `pion-interop` or
  `chrome-interop` (masked until now because Phase 2(a) validated Pion via the single-scenario path). The
  loop now reads from a dedicated fd (`3<<<`), out of reach of any inner command's stdin, so the full matrix
  runs all nine — verified locally: **9/9 pass**, both interop lanes included.

### Added — W7 Phase 1: L2 container harness (native peers ⇄ real NAT kernels)
- **`:webrtc-harness-endpoint`** — a non-published Kotlin/Native executable (`linuxX64` + `linuxArm64`) that
  composes the production `NativePeerConnection` + `BoringSslDtls` over **real UDP** (`socket-udp`) and runs
  as a container endpoint. Config from `WEBRTC_*` env; offer/answer/candidates exchanged over a **UDP
  rendezvous** (a buffer-codec KSP-generated wire schema — the native peer can only link `socket-udp`, not
  socket core/quic, without a BoringSSL duplicate-symbol break); proves the data path with a `ping`/`pong`.
  Applies a new `webrtc.native-executable` build-logic convention (KGP+KSP on one classloader).
- **`test-harness/`** — a docker-compose L2 harness (mirrors socket's): real **coturn** STUN/TURN, a UDP
  **rendezvous** relay, two **NAT gateways** implementing all four RFC 4787 profiles (full-cone /
  address-restricted / port-restricted / symmetric — iptables, fidelity documented), **netem** impairment,
  and two peer containers. `run-interop.sh` drives the scenario matrix (each profile + relay-only + impaired)
  and asserts a two-peer establish + echo in each; `harness-l2.yaml` runs it arch-matched (x64 + arm64).
  **7/7 scenarios pass** locally: two peers establish real ICE → BoringSSL DTLS → SCTP → data channel across
  real Linux NAT kernels.
- **Hardened (real-network bugs the vnet never surfaced):** `webrtc-ice` gathering now threads
  `IceConfig.bufferFactory` into `gatherServerReflexive` (additive param) + `TurnAllocation` — a heap buffer
  is rejected by `socket-udp`'s io_uring `send`, so real srflx/relay gathering needs the injected native
  factory — shipped with its deterministic fixture (`GatheringBufferFactoryTest`, all platforms; proven to
  fail against the pre-fix code). Also documented: io_uring needs `seccomp=unconfined` under Docker, container-router forwarding
  needs host `bridge-nf-call-iptables=0`, and the answerer lingers before teardown so the final `pong` is
  reliably delivered.
- **Adversarial-review gate (5 parallel lanes; confirmed defects fixed + fixtures):**
  - **Signaling correlation + leak** — the UDP rendezvous replies carried no correlator, so a delayed/duplicate
    reply could offset a socket by one and mis-pair every later reply (an answer-SDP fed into `addIceCandidate`,
    a candidate silently dropped); and received datagram payloads were never freed. Fixed: a per-request
    `nonce` echoed in `MailboxResponse`, `awaitReply` drains + frees any non-matching datagram, request freed
    in `finally`, signaling sockets closed after teardown. Fixture: `SignalingCorrelationTest`.
  - **webrtc-ice fixture rigor** — added a driver-level test proving `IceAgentDriver` threads
    `config.bufferFactory` into **both** `gatherServerReflexive` (srflx) and `TurnAllocation` (relay) —
    reverting either wiring line now fails a test (the function-level tests alone did not catch it).
  - **NAT `address-restricted` fidelity** — the `recent`-module rules were dead code (a terminating baseline
    `ACCEPT` preceded them), silently degrading the profile to port-restricted; the recorder now inserts at the
    head of `FORWARD` so the profile is genuinely address-dependent.
  - **Harness hygiene** — `.dockerignore` (the peer build context was the whole repo); the host
    `bridge-nf-call-iptables` sysctl is captured and **restored** on teardown; the impaired lane now
    **fails hard** if netem can't apply (was silently running unimpaired); `no-new-privileges` added alongside
    the io_uring `seccomp=unconfined`.
  - Refuted: the TURN long-term-key concern (relay-only establishes empirically — coturn accepts the peer's
    short-term MI; the long-term-key derivation is a pre-existing, documented L3/real-TURN follow-up).

### Added — W4: `webrtc-dtls` — real BoringSSL DTLS 1.2/1.3, wired into `PeerConnection`
- **`DtlsEngine`** — a caller-clocked, sans-io DTLS endpoint (`expect class`; RFC §5.1): `start` /
  `onDatagram` / `onTimeout` / `send` / `beginClose` + `nextTimeoutMicros`, all in epoch-micros from the
  driver's injected clock. No dispatcher, no `Clock.System`, no I/O, no coroutine inside it. BoringSSL's
  DTLS timers are driven through an injected `current_time_cb`, so a whole handshake — **retransmissions
  included** — replays under `runTest` at zero wall-clock. Sealed `DtlsState`
  (Handshaking/Established/Closed/Failed) + sealed `DtlsFailureReason` (directive #3); `DtlsConfig` seams
  (`bufferFactory`, `enableDtls13`, `handshakeTimeout`).
- **The Kotlin/Native BoringSSL backend (Linux x64 + arm64)** — `webrtc-dtls` provisions a **same-commit**
  (`63893acb`) `libssl.a` and links **only** that, letting libssl's undefined `AES_*`/`SHA256_*` resolve
  against buffer-crypto's single already-linked `libcrypto` — no second copy, so no duplicate-symbol clash
  (`DtlsBackendLinkNativeTest` is the tripwire). Self-signed P-256 certificate + `X509_digest`
  fingerprints, DTLS-SRTP exporter + `use_srtp` (ready for Phase-2 media). The FFI buffer edge is a
  fast/slow split: a native-backed buffer hands BoringSSL its own address (zero staging copy — pass a
  pooled native factory in production), a GC-heap buffer stages through one reusable per-engine native
  scratch. No `ByteArray` anywhere (directive #1).
- **§11.3 resolved on evidence: min DTLS 1.2 / max 1.3, 1.3 ON by default.** Verified by search, not
  assumed: Firefox ships DTLS 1.3 in Release and Chrome/BoringSSL has it on by default (libwebrtc flipped
  in 2025). The 1.2 floor stays purely for breadth — Pion's released v3 is still 1.2-only — and negotiation
  falls back automatically. **Both versions are asserted by tests**, never assumed.
- **`BoringSslDtls`** (webrtc root) — the coroutine **driver** that replaces `PlaintextDtls`: one pump
  coroutine owns the engine and serializes every interaction with it (inbound records from the ICE seam,
  outbound application data, expired DTLS timers) through a single `select`, exactly as `IceAgentDriver`
  clocks the ICE core — which is what makes the not-thread-safe engine safe by construction. It exposes the
  established engine as the `SctpDatagramTransport` the data-channel stack already rode, so DTLS was **a
  swap, not a rewrite**: nothing above (SCTP/PeerConnection) or below (ICE) changed shape.
- **`a=fingerprint` verification (RFC 8122/8827) — the check the whole security model rests on.** BoringSSL
  accepts any certificate by design (WebRTC verifies by fingerprint, never by CA chain), so the driver holds
  the peer's certificate to the digest its SDP advertised and fails the session typed if it differs; a peer
  advertising no usable SHA-256 digest is refused rather than trusted. Certificate identity now lives on the
  **DTLS factory** (`DtlsTransportFactory.localFingerprint`), not in `PeerConnectionConfig`, so advertising
  one fingerprint while presenting another is unrepresentable (DESIGN §4) — this also resolves an ordering
  constraint, since the digest must exist at `createOffer` time but the role only at `a=setup`. Accordingly
  the DTLS **role moved from the `DtlsEngine` constructor to `start(role, now)`**: an endpoint has an
  identity from birth and learns its role from signaling later, as WebRTC models it.
- **One DTLS vocabulary.** The root module's W6-era duplicate `DtlsFailureReason` is **removed**;
  `PeerConnectionFailureReason.Dtls` now composes webrtc-dtls's sealed reason unchanged, exactly as `Ice`
  and `Sctp` compose theirs. `DtlsConfig.handshakeTimeout` closes a liveness hole: DTLS retransmits a lost
  flight forever, so without a budget a peer that goes silent mid-handshake would hang the session (RFC
  §5.3 #5 — reach a state or a typed failure, never hang).
- **Tests.** **The W4 exit fixture** (`webrtc/linuxTest`): two `NativePeerConnection`s complete a full
  session over the vnet with **real DTLS in the seam** — ICE nomination → DTLS handshake → SCTP association
  → data channels both ways, under virtual time — the end-to-end gate W5 and W6 could only prove with the
  plaintext stand-in. Plus: the two-stack handshake fixture (each side verifying the *other's* real cert
  fingerprint, negotiated 1.3) + the 1.2-fallback/Pion interop lane + app-data round-trip; the
  **dropped-flight retransmission** fixture (a timer must arm, not fire early, and the retransmitted flight
  must actually complete the handshake); the fingerprint-**mismatch** and **absent-fingerprint** negatives
  (both fail typed, never connect); the injected-factory/bounded-allocation invariant (directive #6); and
  the libssl/libcrypto single-copy link tripwire.
- **Platform reality (V6_MAC_VALIDATION):** Linux K/N is the only target with a DTLS backend this wave.
  JVM/Android/**Apple** get typed `BackendUnavailable` actuals and are **compile-faithful only** — Apple has
  **no** DTLS backend. JVM/Android/Apple DTLS is deferred to the `boringssl-kmp` binary factory, which
  cannot serve today: it is unpublished, its JVM FFM shim is crypto-only, its Apple lane is unbuilt, and its
  quiche-anchored API-21 pin has no `DTLS1_3_VERSION` (it would ship a 1.2-only stack) and would
  duplicate-symbol against buffer-crypto's BoringSSL on native. See EXECUTION_PLAN "W4 sequencing".

#### Hardened — adversarial-review gate (4 parallel lanes: native/FFI, driver/lifecycle, types/API, tests)
Each confirmed defect ships its regression fixture (directive #5):
- **`CertificateFingerprint` is now unforgeable-by-construction** — the primary constructor is **private**
  and `ofHex` is the only builder; it validates the digest is exactly 64 hex chars and normalizes case +
  colons. Previously a public constructor could store a non-normalized string, making the RFC 8122
  `a=fingerprint` equality check (a security discriminant, RFC 8827) casing-fragile and `sdpValue` render
  garbage. `.api` changed (constructor removed) — cheap now, binary-breaking after release.
  (`CertificateFingerprintTest`.)
- **A fatal record-layer error on the read path now surfaces `Failed(RecordLayerError)`** instead of being
  swallowed as end-of-data — a post-handshake fatal alert can no longer leave a dead transport
  masquerading as `Established`.
- **The GC-heap FFI staging path is bounded** — a datagram larger than the 64 KiB scratch is rejected up
  front rather than read past the buffer's end (native-backed buffers keep the copy-free path).
  (`…rejected_not_over_read`.)
- **The driver-enforced `handshakeTimeout` liveness bound is now covered** — a silent peer fails typed
  (`HandshakeTimeout`) under virtual time rather than hanging. (`DtlsHandshakeTimeoutTest`.)
- **Buffer-leak sources closed** — the memory-BIO leak on a partial-allocation failure in `bd_new`, the
  native-engine leak if construction throws after `bd_new`, and the driver dropping (not releasing) a
  decrypted app-data buffer on a teardown race are all fixed; the allocation test's invariant is scoped
  honestly to bounded-allocation (matching the W3/W5 posture).
- **Read-path T0 robustness** — a malformed datagram fed mid-handshake is dropped, never wedges or crashes
  the engine. (`…malformed_datagrams…`.)

### Added — W6: `webrtc` root — `PeerConnection` + browser delegation + typed error sweep
- **`RtcPeerConnection` + `NativePeerConnection`** (the consumer session API, RFC §3.1) — a caller-clocked,
  seam-injected driver composing the sans-io cores: the `JsepSession` offer/answer machine (webrtc-sdp),
  the `IceAgentDriver` (webrtc-ice) over an injected `IceGatheringPolicy`, the injected
  `DtlsTransportFactory` (`PlaintextDtls` while W4 is parked — the same seam W5 proved SCTP over), and the
  `SctpDataChannelStack` (webrtc-sctp) over the nominated pair. Descriptions and candidates cross as **SDP
  text / `candidate:` lines** (the exact currency `RTCPeerConnection` and the wire speak, so one interface
  backs both native and browser); a data channel **is** a buffer-flow `Connection<ReadBuffer>`
  (`createDataChannel` / `incomingDataChannels`, DESIGN §7). Sealed `PeerConnectionState` carries the typed
  failure reason (no boolean/nullable soup, DESIGN §4). The DTLS/SCTP role is **negotiated from `a=setup`**
  (RFC 8842), not assumed from who offered.
- **ICE→SCTP composition promoted to production** — `IceAgentDriver` (+ the `DatagramBinder` network seam
  and the `IceDataTransport` app-data seam over the selected pair, RFC 7983 STUN/app demux) in
  `webrtc-ice/commonMain`, so the session and a future media layer compose the same transport the W5
  `IceSctpEndToEndTest` proved. `IceCandidateLine` — the RFC 8839 §5.1 `candidate` ↔ typed `IceCandidate`
  codec (typed-reject on malformed, phase-1 UDP/IPv4).
- **Browser delegation (js, Karma-tested)** — `peerConnectionSupport()` (`expect`/`actual`); on a browser
  the js actual maps our API onto the native `RTCPeerConnection` (RFC §1.1: the one target we wrap), with
  a real in-browser loopback Karma test in headless Chrome. Non-browser targets report `Native` and build
  `NativePeerConnection` directly; wasmJs reports `BrowserDelegated` with the external-interface mapping as
  the one documented remaining follow-up.
- **Typed error sweep** — `PeerConnectionFailureReason` (sealed `Ice`/`Dtls`/`Sctp`/`Unknown`, composing
  each layer's typed reason unchanged) + `DtlsFailureReason` (defined ahead of W4) + `WebRtcException`;
  signaling-API misuse is typed `JsepStateException`/`SdpFormatException` (directive #3). Mapping into
  socket's `SocketException` hierarchy (RFC §3.1) is **deferred**: depending on `com.ditchoom:socket`
  duplicate-symbols socket's vendored BoringSSL against buffer-crypto's on every native target — gated on
  an upstream BoringSSL dedup, exactly as DTLS is gated on W4.
- **Tests (all platforms, `runTest` virtual time):** the full offer/answer → ICE → (plaintext DTLS) → SCTP
  → data-channel round-trip with scripted signaling (the W6 exit fixture) — green on
  jvm/linuxX64/jsNode/**jsBrowser (Karma)**/wasmJsNode/wasmJsBrowser/androidHost; lifecycle-liveness
  regressions (close-before-connect terminates, typed signaling errors); the candidate-codec T0; the
  error-sweep mapping. Adversarial-review gate (3 parallel reviewers) ran — every confirmed defect
  (role-negotiation deadlock, five lifecycle/liveness hangs/leaks, six API-surface findings, four
  browser-delegation defects) fixed with a regression fixture. `.api` committed as the public commitment.

### Added — W5: `webrtc-sctp` association + DataChannel (SCTP RFC 4960 subset + RFC 3758 + DCEP 8832 + RFC 8831)
- **Sans-io SCTP association (`SctpAssociation`)** — a pure `handle(event, now): List<Output>` plus
  `nextDeadline(now): Instant?`, **no dispatcher, clock, RNG, or I/O inside** (RFC §5.1). It owns the
  **four-way handshake** (INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK with a stateless State Cookie),
  TSN assignment and **SACK**-driven reliability, **RTO** estimation (RFC 4960 §6.3.1), **congestion
  control** (slow start / congestion avoidance / T3 + fast-retransmit collapse, §7.2), message
  **fragmentation** and ordered/unordered **reassembly**, **RFC 3758 partial reliability** (FORWARD-TSN,
  `maxRetransmits` / `maxPacketLifeTime` abandonment), and graceful + abort **shutdown** (§9). Entropy is
  one injected `Random` seam (directive #2) seeding the Verification Tag + initial TSN, so a full
  session replays bit-for-bit under `runTest` virtual time on every platform. §11.2 resolved: the
  dcSCTP-style subset (no multihoming, no stream interleaving).
- **Type model, illegal states unrepresentable:** sealed `SctpAssociationState` (Closed → CookieWait →
  CookieEchoed → Established → the four shutdown phases), sealed `SctpEvent` / `SctpOutput`, sealed
  `SctpReliability` (Reliable | MaxRetransmits | MaxLifetime — never a nullable pair), and exhaustive
  `SctpFailureReason` (`AbortReceived`, `RetransmissionLimitReached`, `HandshakeTimeout`,
  `ProtocolViolation(ProtocolViolationKind)`) — typed reasons, never strings (directive #3).
- **DCEP (RFC 8832) + `DataChannel` as a buffer-flow `StreamMux`** — `SctpDataChannelStack` implements
  `StreamMux<ReadBuffer>`: `openBidirectional()` gives a `Connection<ReadBuffer>` whose `send` is one
  data-channel message and whose `receive` is the inbound message flow (DESIGN §7 — the consumer
  contract is the mux). It drives the association over an injected **`SctpDatagramTransport`** (the
  clean DTLS-shaped seam where W4 slots in), an injected `CoroutineScope`, and an injected clock;
  DATA_CHANNEL_OPEN/ACK are wired to the association, even/odd stream ids follow RFC 8832 §6, and empty
  messages ride the RFC 8831 §6.6 empty-marker PPIDs.
- **Tests (all platforms, `runTest` virtual time):** a deterministic sans-io two-endpoint conductor
  (handshake, ordered-reliable **no-reorder / no-drop under 30 % loss**, unordered, fragment/reassemble,
  partial-reliability convergence, shutdown); a coroutine DataChannel end-to-end over an impaired
  in-memory transport (bidirectional, lossy-reliable, empty-message); and the **W5 composition** — the
  real `SctpDataChannelStack` running over the actual **W3 `IceAgent` nominated pair** across the vnet
  (`IceDriver.sctpTransport` + RFC 7983 STUN/app demux). A **loop-until-dry invariant campaign**
  (260 seeds of randomized loss/dup/delay/jitter) upholds the SCTP invariants — no crash, liveness, no
  intra-stream reorder, no unacked drop, no duplicate delivery. The **Jazzer `sctpCodecFuzz` lane** now
  also feeds hostile bytes into `association.handle` (T0 totality at the association layer); a 3 M-run
  campaign was clean. `CountingBufferFactory` proves the `BufferFactory` is threaded through the hot
  paths and an idle association allocates nothing per tick (directive #6).
- **Adversarial-review gate (5 parallel reviewers) — confirmed defects fixed, each with a regression
  fixture** (directive #5): a lone FORWARD-TSN now elicits a SACK (RFC 3758 §3.6); T3 retransmits are
  **paced by cwnd** (§6.3.3 E3) instead of dumping the whole flight; a fast-retransmitted chunk resets
  its missing-report count (no infinite re-fast-retransmit); partial-reliability abandonment runs on the
  SACK path too (a timed message is no longer retransmitted forever when T3 never fires); a **reflected
  T-bit ABORT** from a peer that lost its TCB is accepted (§8.5.1) so a dead-peer restart tears us down;
  a gap-ack-block offset beyond a `u16` is **omitted** rather than wrapped into a malformed `end < start`
  block; ordered delivery **wraps the SSN** (no stall after 65535 ordered messages); the RFC 7053 I-bit
  and gap-fill now force a prompt SACK; a cross-stream/SSN fragment splice is rejected; the DataChannel
  driver **completes pending `open`/`send` deferreds exceptionally on teardown** (was: caller hangs
  forever), stops the loop on a received ABORT, validates incoming-OPEN stream-id parity, and buffers
  data that races ahead of its DCEP OPEN. The Jazzer lane was strengthened to re-stamp a valid CRC so
  the association handlers are actually exercised (edge coverage 1052 → 1472); the invariant campaign was
  split into an all-platform smoke set + a JVM deep-run (hundreds of seeds + fragmentation-under-loss),
  and the sim conductor now throws on non-convergence so a livelock can never pass silently.

### Added — W3: `webrtc-ice` (ICE agent — RFC 8445 + trickle 8838 + consent 7675)
- **Sans-io ICE agent core (`IceAgent`)** — a pure `handle(event, now): List<Output>` plus
  `nextDeadline(now): Instant?`, with **no dispatcher, clock, RNG, or socket inside** (RFC §5.1). It
  owns the checklist, the connectivity-check state machine (retransmission via the W1 `StunTransaction`),
  Ta-paced scheduling, triggered checks, peer-reflexive learning, **regular nomination**, RFC 7675
  **consent freshness**, **role-conflict** resolution (487 + tie-breaker), and **ICE restart**. Entropy
  is one injected `Random` seam (directive #2) seeding the tie-breaker, credentials, and every STUN
  transaction id, so a full establishment (and a 90-second field saga) replays bit-for-bit under
  `runTest` virtual time on every platform.
- **Type model, illegal states unrepresentable:** `IceCandidate` (host/srflx/prflx/relay) with RFC 8445
  §5.1.2 priority; `CandidatePair` + §6.1.2.3 pair priority (computed in `ULong` — the `2^32·min` term
  exceeds a signed `Long`); `CandidatePairState`; `Foundation` (§5.1.1.3); value-class `ComponentId`,
  `IceRole`, unsigned `TieBreaker`, `NetworkId`; `IceCredentials.random` (ICE-char ufrag/pwd); a sealed
  `IceConnectionState` and exhaustive `IceFailureReason`.
- **ICE STUN attributes** (PRIORITY / USE-CANDIDATE / ICE-CONTROLLING / ICE-CONTROLLED) built on the
  additive public `RawAttribute.ofRaw(type, value)` / `ofXorAddress(type, addr, txid)` escape-hatches
  added to `webrtc-stun` — the ICE checks reuse the W1 STUN client and MESSAGE-INTEGRITY/FINGERPRINT.
- **Gathering drivers (production, over injected seams):** `gatherServerReflexive` (STUN Binding →
  srflx); `TurnAllocation` — a full RFC 8656 relay client presented **as a `DatagramChannel`** (Allocate
  with 401 challenge, CreatePermission, Send/Data encapsulation, response demux) so the relay's
  complexity stays out of the core; `NetworkMonitor` / `MdnsResolver` seams (mDNS **resolve-only**, RFC
  §11.4). Trickle (RFC 8838) falls out of the driver's single-inbox design.
- **The vnet grew a NAT layer** (`webrtc-ice` commonTest): the four RFC 4787 profiles (full-cone /
  address-restricted / port-restricted / symmetric as mapping × filtering), a **virtual TURN server**
  bound as an ordinary endpoint, a **virtual STUN server**, and a **seeded impairment pipe**
  (loss/reorder/dup/delay on virtual time) — topologies-as-data builders (`Vnets`).
- **Canonical fixtures + invariants (all under `runTest`, all platforms):** two-agent host-to-host,
  role-conflict glare, full-cone srflx hole-punch, **dual-symmetric-NAT → relay** (the RFC §5.2
  load-bearing case), candidate-flap mid-check, `NetworkId`-change → restart, consent expiry, and a
  typed `AllPairsFailed` terminal; RFC-formula conformance for priority/foundation; a pinned-seed
  **timeline fuzz smoke** (establishes under 20% loss + jitter, deterministic replay, every NAT profile
  reaches a terminal state — the liveness/determinism invariants). NAT-model property tests prove each
  profile filters per its RFC 4787 definition.
- **One core bug found + fixed with its fixture** (directive #5): consent expiry used a strict `>`
  while `nextDeadline` armed exactly `lastResponse + consentTimeout`, spinning the driver at that
  instant without advancing virtual time — now `>=`, with `consent_expiry` as the regression.
- **Adversarial review gate (EXECUTION_PLAN §1) — 5 parallel reviewers; confirmed defects fixed, each
  with a regression fixture:** the role-conflict comparison was **inverted** in the Controlled branch
  (RFC 8445 §7.3.1.1 — the larger tie-breaker ends up controlling in *both* directions), so
  controlled-vs-controlled glare thrashed; added a one-shot resolution latch + pacing re-arm on a 487
  retry. A **global establishment failsafe** closes three liveness hangs (nomination-check failure,
  a peer that never nominates, zero compatible candidates → the now-emitted typed `NoCandidatePairs`).
  The `nominationInFlight` latch is released on any nominating-check outcome (+ an on-timer retry). The
  connectivity check reads only the **MESSAGE-INTEGRITY-covered prefix** (RFC 8489 §14.5), defeating a
  USE-CANDIDATE splice. `pruneRedundant` is state-aware (never evicts an in-flight/valid/selected pair).
  Driver/vnet hardening: `select`-based drive loop (no lost trickled candidate), `close()` unbinds the
  vnet endpoint (flap frees it; no false delivery/leak), the vnet TURN server validates REALM/NONCE
  like coturn, srflx gathering retransmits, `toTransportAddress` typed-rejects non-v4.
- **BufferFactory injectable end-to-end (directive #6):** the whole datagram build path uses the
  caller's `IceConfig.bufferFactory` (a consumer can hand in a `buffer` pool); `BufferLifecycleTest`
  validates pool-injectability and **steady RSS** (allocations grow with messages, not per timer tick).
- Green on **JVM, JS-node, wasmJs-node, Linux/native, and Android host**; Apple lanes CI-validated on
  the macOS runner. Nothing published to Central (`skip-release`).

### Added — W5 (codec floor): `webrtc-sctp` (SCTP chunk codec + DCEP messages)
- **SCTP common header (RFC 4960 §3.1)** as a `buffer-codec` KSP `@ProtocolMessage` schema
  (`SctpCommonHeaderCodec`) — a straight-line 12-byte network-order decode; the chunk TLV framing
  (type/flags/length, pad to a 4-byte boundary) and the nested parameter/error-cause sub-TLVs are
  hand-written, because SCTP's "length counts the 4-byte header + value but not the trailing pad" is
  outside what the declarative codec expresses (the STUN attribute discipline).
- **Sealed chunk hierarchy (`SctpChunk`):** DATA, INIT, INIT-ACK, SACK, HEARTBEAT, HEARTBEAT-ACK,
  ABORT, SHUTDOWN, SHUTDOWN-ACK, ERROR, COOKIE-ECHO, COOKIE-ACK, SHUTDOWN-COMPLETE, FORWARD-TSN
  (RFC 3758), plus an `Unrecognized` variant that preserves an unknown chunk verbatim (RFC 4960 §3.2
  forward-compat). A receiver's `when(chunk)` is exhaustive with no `else`. Variable regions (user
  data, cookies, parameter/cause values) are **zero-copy slice views** over the datagram (RFC §6).
- **CRC32c (RFC 4960 §6.8 / RFC 3309):** the Castagnoli checksum, self-contained (`Crc32c`) — a
  256-entry table held in a **managed `ReadBuffer`, not an `IntArray`** (directive #1), word-batched
  input read matching buffer's `crc32`. Stored little-endian per RFC 4960 Appendix B; verified/placed
  in-place without mutating the datagram. Validated against the published `0xE3069283` known answer and
  cross-checked against an independent bitwise reference over thousands of random inputs.
- **Typed identifiers (value classes):** `Tsn` (with RFC 1982 serial arithmetic), `StreamId`,
  `StreamSequenceNumber`, `PayloadProtocolId` (WebRTC PPID constants), `VerificationTag`; bitwise
  fields wrapped behind named accessors (`DataChunkFlags` I/U/B/E, `SctpChunkType.unrecognizedAction`).
- **DCEP (RFC 8832):** `DataChannelMessage` sealed pair — `Open` (channel type, priority, reliability,
  UTF-8 label/protocol) and `Ack`. `ChannelType` exposes an exhaustive typed projection (`ordered` +
  sealed `Reliability`) over the preserved wire byte. Decode is total with typed rejects; invalid UTF-8
  in a label/protocol is a typed miss, never a throw.
- **Typed rejects (T0):** `SctpPacket.decode` and `DataChannelMessage.decode` are total — a hostile or
  truncated datagram yields a sealed `SctpRejectReason` / `DataChannelRejectReason`, never a throw.
- **Tests:** every chunk type round-trips (typed fields + byte-exact re-encode + checksum), frozen
  RFC-layout golden wire vectors (INIT, SACK, DCEP-over-DATA), a malformed corpus + a 20k-input
  totality property + single-byte-mutation totality, wrapper-transparency (non-zero-offset slice), and
  the CRC32c conformance suite — **green on JVM, JS, wasmJs, Linux/native, and Android host**.
- **Coverage-guided Jazzer fuzz lane** (`sctpCodecFuzz`, time-boxed at 120s in CI) with a committed
  seed corpus; a 90s local run was ~26M executions crash-free. One find during bring-up — a
  `valueSize` computed from the untruncated padded length of a malformed final sub-TLV, which shrank
  the re-encode buffer under the checksum's read — is fixed with its committed regression fixture.
- SCTP decode / checksum-verify throughput benchmark tracked in `PERFORMANCE.md`. Committed `.api` +
  detekt baseline.
- **Scope:** this is the pure codec + DCEP-message floor only (commonMain, zero I/O). The SCTP
  association state machine (handshake, TSN/SACK/RTO, congestion control, reassembly) and the
  `DataChannel` `StreamMux` are the rest of W5 — they sit above this on the DTLS/UDP track.

### Added — W6 (partial): `webrtc-sdp` (SDP text codec + sans-io JSEP machine)
- **SDP parser/serializer (RFC 8866):** a hand-written line codec (SDP is text — no `buffer-codec`
  schema). The datagram is decoded to a `CharSequence` exactly once and parsed index-based into a
  round-trip-faithful model (`SessionDescription` → session lines + `MediaDescription`s), each line
  kept verbatim so parse→encode reproduces a canonical CRLF document **byte-for-byte** (the text
  analogue of STUN's view-based decode).
- **Typed rejects (T0):** `SessionDescription.parse` is total — a hostile or non-UTF-8 datagram yields
  a sealed `SdpRejectReason`, never a throw. Semantic breakage of a single line (`o=`/`m=`/
  `a=fingerprint`) is a null typed-reader miss, not a whole-document reject (the `RawAttribute`
  discipline for text).
- **Typed field surface:** value-class `Mid`; `Origin`, `MediaLine`, `Fingerprint`, `SetupRole`,
  `SdpType`, `SignalingState`; on-demand interpreters for the JSEP data-channel attributes
  (`ice-ufrag`/`ice-pwd`/`fingerprint`/`setup`, `sctp-port`/`max-message-size`, `candidate`/
  `end-of-candidates`, `group:BUNDLE`) at session or media level (RFC 8829 §5.2.1 fallback).
- **`SessionDescriptionBuilder`** + `dataChannelDescription` — programmatic offer/answer assembly
  (RFC 8841 data-channel shape); a built document round-trips through `parse` unchanged.
- **Sans-io JSEP offer/answer machine:** `JsepSession.handle(event, now)` + `nextDeadline()` (always
  null — JSEP arms no timers), enforcing the RFC 8829 §3.5.1 signaling transition table with rollback;
  illegal edges are typed `JsepError.InvalidTransition` outputs that leave state untouched. Entropy is
  injected (`Random`) — the `o=` session id is `CryptoRandom` in production, replayable in tests.
- **Tests:** real-world Chrome/Firefox/Pion data-channel offer/answer vectors (parse + typed fields +
  byte-exact round-trip), malformed corpus + two 20k-input totality properties + single-line-drop
  mutation, wrapper-transparency (pooled buffer / non-zero-offset slice), builder round-trips, and the
  full JSEP transition table incl. rollback/pranswer/close — **36 tests green on JVM, JS, wasmJs,
  Linux/native, and Android host**.
- **Coverage-guided Jazzer fuzz lane** (`sdpCodecFuzz`, time-boxed in CI) with a committed seed corpus
  (7 seeds); a 30s local run turned 1M+ executions crash-free.
- SDP parse/encode throughput benchmark tracked in `PERFORMANCE.md`.

### Added — W1: `webrtc-stun` (STUN/TURN codec + sans-io transactions)
- **STUN message codec (RFC 8489):** the 20-byte header (bit-interleaved message type, magic cookie,
  96-bit transaction id) as a `buffer-codec` KSP `@ProtocolMessage` schema (`StunHeaderCodec`); the
  TLV attribute layer hand-written for STUN's 4-byte value padding and the in-place MESSAGE-INTEGRITY /
  FINGERPRINT computations. Attributes decode as **zero-copy slice views** over the datagram (RFC §6).
- **Typed attribute surface:** value-class `StunMessageType` / `StunMethod` / `StunAttributeType` /
  `TransactionId`; MAPPED-ADDRESS + XOR-MAPPED-ADDRESS (IPv4/IPv6, array-free `IpAddress`), USERNAME /
  REALM / NONCE / SOFTWARE, ERROR-CODE, plus TURN (RFC 8656) attribute types (codec-only).
- **MESSAGE-INTEGRITY (HMAC-SHA1) + FINGERPRINT (CRC-32)** verified/appended in place over buffer
  slices, using the new `buffer-crypto` `hmacSha1` and `ReadBuffer.crc32` (DitchOoM/buffer#288).
  MESSAGE-INTEGRITY is compared **constant-time** (`constantTimeEquals` — a MAC compare is a timing
  oracle otherwise); **MESSAGE-INTEGRITY-SHA256** (RFC 8489 §14.6, truncation-aware) via `hmacSha256`.
- **Typed rejects (T0):** `StunMessage.decode` is total — a hostile datagram yields a sealed
  `StunRejectReason`, never a throw.
- **Sans-io transaction machine:** `StunTransaction.handle(event, now)` + `nextDeadline()` with the
  RFC 8489 §6.2.1 retransmission schedule (RTO doubling, `Rc`/`Rm`), injected clock + seeded
  transaction ids — runs under virtual time on every platform.
- **Tests:** RFC 5769 §2.1–2.3 interop vectors (decode + MI/FINGERPRINT recompute + XOR-address +
  byte-exact round-trip), malformed corpus + 20k-input totality property, wrapper-transparency
  (pooled buffer / non-zero-offset slice), builder round-trips — **34 tests green on JVM, JS, wasmJs,
  Linux/native, and Android host**.
- **Coverage-guided Jazzer fuzz lane** (`stunCodecFuzz`, time-boxed in CI) with a committed seed
  corpus; the two bugs it found in W1 (non-UTF-8 text throwing; short MESSAGE-INTEGRITY/FINGERPRINT
  length reading past the datagram) are fixed with committed regression fixtures + corpus seeds.
- Parse-throughput benchmark tracked in `PERFORMANCE.md`.

**Depends on** DitchOoM/buffer#288 (`hmacSha1` + `ReadBuffer.crc32`); pinned to `6.10.0-SNAPSHOT` from
mavenLocal during development — swap to the released `buffer` before merge.

### Added — W0: foundations (repo skeleton)
- Multi-module Gradle build across the full KMP target matrix (JVM, Android, JS Node/Browser, wasmJs,
  Linux x64/arm64, Apple), JDK 21 toolchain.
- `build-logic` convention plugin (`webrtc.multiplatform-library`) owning all per-module build config —
  targets, publishing, signing, versioning, ktlint, dokka, kover, binary-compatibility validation — so
  a module build file carries only its dependencies.
- Phase-1 module tree (placeholders): `webrtc`, `webrtc-sdp`, `webrtc-stun`, `webrtc-ice`,
  `webrtc-dtls`, `webrtc-sctp`, `webrtc-testsuite`.
- kotlinx-benchmark wired into the convention (shared `src/commonBenchmark/kotlin`, JVM + Linux K/N,
  `main`/`quick` profiles), tracked in `PERFORMANCE.md`.
- CI: `review.yaml` (PR build/test/validate), `merged.yaml` (label-driven release), reusable
  `build-linux` / `build-apple` / `validate-artifacts`, `publish-to-central` / `release` / `released`
  (Central Portal), and `standing-directives.yaml` (No-array + seamed-entropy greps).
- PR labels (`.github/labels.yml` + sync workflow), dependabot.
- Docs: `RFC_KMP_WEBRTC.md`, `EXECUTION_PLAN.md`, `CLAUDE.md`, `DESIGN_PRINCIPLES.md`, `TESTING.md`
  (unit → integration → interop strategy, harness, external vectors, per-wave test exit criteria),
  `PERFORMANCE.md`, `README.md`.

_No published release yet; the first `publishToMavenLocal` produces `0.0.1`._

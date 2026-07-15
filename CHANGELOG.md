# Changelog

All notable changes to `com.ditchoom:webrtc` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are auto-derived from Maven Central
metadata + PR-label bumps (`major` / `minor`, else patch).

## [Unreleased]

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

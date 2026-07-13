# Changelog

All notable changes to `com.ditchoom:webrtc` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are auto-derived from Maven Central
metadata + PR-label bumps (`major` / `minor`, else patch).

## [Unreleased]

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

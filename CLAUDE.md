# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Project Overview

`com.ditchoom:webrtc` — a **zero-copy, deterministic, sans-io WebRTC stack** for Kotlin Multiplatform,
built on the DitchOoM `buffer` (zero-copy buffers, codec, crypto, flow) and `socket` (transport model,
typed errors, `NetworkMonitor`, deterministic simulation engine) libraries.

Phase 1 delivers **data channels** (ICE + DTLS + SCTP + DCEP + JSEP/SDP); media (RTP/SRTP) is Phase 2.
The protocol cores are **ours**, built in common Kotlin — we do **not** wrap libwebrtc on any non-browser
target. Browsers are the sole exception: there `peerConnectionSupport()` delegates to `RTCPeerConnection`.

**Read these first, in order** (a resumed session starts here):
1. `RFC_KMP_WEBRTC.md` — the architecture (the *what* and *why*).
2. `EXECUTION_PLAN.md` — wave sequencing W0–W7, orchestration, exit criteria.
3. `DESIGN_PRINCIPLES.md` — the type-safety + zero-copy manifesto, with code patterns.
4. `TESTING.md` — unit → integration → interop strategy, the harness, external vectors, per-wave test exit criteria.

Current state: **the pure-codec / socket-free track is complete** — W1 (`webrtc-stun`), W6-partial
(`webrtc-sdp`), and W5-codec-floor (`webrtc-sctp` chunk codec + DCEP) are all merged to `main` (all
`skip-release`; nothing on Central yet). The transport prerequisites now exist in the **socket sibling**:
the UDP `DatagramChannel` `commonMain` seam (`socket-udp`, socket PR #239) + the deterministic vnet/sim
harness (socket #225) — so **W2 (vnet) is a socket deliverable, not a webrtc wave**, and **W3
(`webrtc-ice`) is next**. Transport dev is unblocked against a socket `publishToMavenLocal` build, but
`socket-udp` is **not yet on Central** (latest socket 3.10.1 predates #239) — so webrtc transport code
must not merge until it is. See `EXECUTION_PLAN.md`.

## Standing directives (every session, every wave)

These are non-negotiable. The first two are enforced by CI (`.github/workflows/standing-directives.yaml`);
all are checked in the per-wave adversarial review gate.

1. **No `ByteArray` — and no primitive array of any kind** (`IntArray`, `LongArray`, `ShortArray`, …) —
   in production (`*Main/`) source sets. A primitive array in a hot path is a guaranteed copy; this
   library exists to avoid that. Use `ReadBuffer` / `WriteBuffer` / `PlatformBuffer` and slice views.
   Genuine platform edges (an FFI call that demands a `ByteArray`) annotate the line
   `@Suppress("NoByteArrayInProd")` with a comment naming the specific API surface.
2. **No hardwired `Clock.System` / `Random.Default` / `Dispatchers.*` inside cores.** Every source of
   time, entropy, and concurrency is a constructor-injected seam with a production default. This is
   what lets the whole stack run under `runTest` virtual time. A genuine production-default
   construction annotates the line `@Suppress("UnseamedEntropy")`.
3. **Errors are typed, never stringly.** Everything maps into the `SocketException` sealed hierarchy
   with exhaustive sealed reasons (`IceFailureReason.NoCandidatePairs`, `.ConsentExpired`, …). Strings
   are diagnostics, never discriminants.
4. **Assert observable state + a watchdog, never wall-clock budgets.**
5. **Every bug fix ships with its deterministic fixture in the same PR.** The corpus only grows.
6. **Buffers are factory-injected, pooled in hot paths, `use {}`/scoped lifecycle**, with
   `TrackingBufferFactory` in every test harness (invariant: no leaks).
7. **The PR description states which platform lanes were runtime-validated vs compile-faithful**
   (the `V6_MAC_VALIDATION` convention: Apple/Android runtime-validated on runners).

## Type-safety house style (make illegal states unrepresentable)

The cores are state machines; the type system is the first line of correctness. See
`DESIGN_PRINCIPLES.md` for worked examples. In short:

- **Value classes wrap every identifier.** A `TransactionId`, `Ufrag`, `StreamId`, `Tsn`,
  `DataChannelId`, `Mid`, `CertificateFingerprint` are each `@JvmInline value class` around their
  payload — zero runtime cost, but the compiler refuses to pass a `Ufrag` where an `IcePassword` is
  expected. IDs are never bare `String`/`Int`/`Long` at an API boundary.
- **Sealed hierarchies + exhaustive `when`, no `else`.** Message classes, connection states, and
  failure reasons are sealed. A `when` over them compiles without an `else`; adding a case is a
  compile error at every call site until handled. Prefer this to enums when variants carry data.
- **No boolean or nullable soup.** Do not model a state as `connected: Boolean` + nullable
  `failureReason` (which can encode "connected AND failed"). Model it as a sealed
  `PeerConnectionState` where each state carries exactly the data valid in it — the illegal
  combinations are simply unrepresentable.
- **Nullability is a deliberate signal, not a default.** A nullable type means "genuinely absent";
  it is never a stand-in for an error (that's a typed reason) or an uninitialized field (that's a
  different state in the sealed hierarchy). `nextDeadline(now): Instant?` returns null to mean
  "no timer armed" — a real, single meaning.
- **Parse failures are typed rejects, never throws-through or crashes** (T0 discipline).

## Build commands

```bash
./gradlew build                 # build all modules, all host-available targets
./gradlew allTests              # tests across every module + platform
./gradlew apiCheck              # binary-compatibility validation against checked-in .api files
./gradlew apiDump               # regenerate .api files after an intentional public-API change
./gradlew ktlintCheck           # lint  (ktlintFormat to auto-fix)
./gradlew detektAll             # multiplatform static analysis (non-blocking; sees Native/JS/WASM)
./gradlew publishToMavenLocal   # publish 0.0.x to ~/.m2  (runs prePublishCheck first)
./gradlew :webrtc-stun:jvmTest --tests "com.ditchoom.webrtc.stun.StunTest"
```

Requires **JDK 21** (enforced via toolchain). Apple targets build on macOS only.

## Architecture

### Module map (`RFC_KMP_WEBRTC.md` §3) — one core, thin layers, each depends only downward

```
webrtc            PeerConnection + JSEP state machine + DataChannel (the consumer API)   [W6]
├── webrtc-sdp    SDP parse/serialize — hand-written text codec, no I/O                  [W6]
├── webrtc-stun   STUN/TURN wire codec (RFC 8489/8656) + sans-io client machines         [W1]
├── webrtc-ice    ICE agent (RFC 8445 + trickle 8838) — sans-io core + gathering seams   [W3]
├── webrtc-dtls   DTLS 1.2/1.3 + DTLS-SRTP exporter — BoringSSL backends (the one native dep) [W4]
├── webrtc-sctp   SCTP subset over DTLS (RFC 8831) + DCEP (RFC 8832) — pure Kotlin, sans-io  [W5]
└── webrtc-testsuite  published consumer harness: vnet, timeline engine, control plane    [W7]
```

Pure-codec modules (`-sdp`, `-stun`) have **zero** platform code and zero I/O — `commonMain`-only,
run everywhere including browsers. Platform code exists in exactly two places: `webrtc-dtls` backends
and the UDP/mDNS gathering actuals in `webrtc-ice`.

### Sans-io, caller-clocked cores (the determinism architecture — `RFC_KMP_WEBRTC.md` §5)

Every protocol state machine (ICE checklist, STUN transactions, SCTP, DCEP, JSEP) is a pure
`handle(event, now): List<Output>` plus a `nextDeadline(now): Instant?`. **No dispatcher, no
`Clock.System`, no `Random.Default`, no I/O, no coroutine inside a core.** Drivers own I/O; cores own
truth. Consequence: a full ICE + SCTP establishment completes under `runTest` at zero wall-clock on
every target, and a 90-second field saga replays in milliseconds, forever.

Testing against real UDP is **not** needed until W7 interop. Everything from W1–W6 tests against an
in-memory `DatagramChannel` (the vnet) — the same seam production uses — exactly as socket's QUIC
stack already does with its `TimelineUdpChannel`.

## Build logic — the convention plugin (no copy-paste)

All per-module build configuration lives in **one** convention plugin,
`build-logic/src/main/kotlin/webrtc.multiplatform-library.gradle.kts`. It owns the KMP target matrix,
the JDK-21 toolchain, Android, ktlint, dokka, kover, binary-compatibility validation, Maven Central
publishing, signing, and version derivation. A module's own `build.gradle.kts` therefore contains
**only its dependencies**:

```kotlin
plugins { id("webrtc.multiplatform-library") }
kotlin { sourceSets { commonMain.dependencies { api(libs.buffer); api(libs.buffer.codec) } } }
```

Structural identity is derived from the module name (artifactId, JS module name `<name>-kt`, Android
namespace `com.ditchoom.<name-dots>`). Per-module POM prose lives in `<module>/gradle.properties`
(`POM_NAME`, `POM_DESCRIPTION`); shared POM/developer/license fields are in the root `gradle.properties`.
Plugin versions are declared once in `gradle/libs.versions.toml`.

To add a module: create the dir + `src/commonMain`+`src/commonTest`, add a `build.gradle.kts` (as
above) and a `gradle.properties`, and `include(":…")` it in `settings.gradle.kts`. Nothing else.

## CI/CD

- **PR** (`review.yaml`): `standing-directives` greps → `build-linux` + `build-apple` → `validate-artifacts`.
- **Release** (`merged.yaml`): version bump controlled by PR labels (`major` / `minor`, else patch;
  `skip-release` / `draft-release` change the flow) → build → validate → `publish-to-central` → finalize
  (tag + GitHub release). `release.yaml` completes/cancels a draft; `released.yaml` mirrors a pushed tag.
- Version is auto-derived from Maven Central metadata + the label bump; greenfield starts at 0.0.1.
- Every published artifact (including `webrtc-testsuite`) goes through `validate-artifacts` from its
  first release (the socket #188 lesson).

## Source docs in sibling repos to consult

`socket`: `RFC_DETERMINISTIC_SIMULATION.md`, `TESTING_STRATEGY.md`, `RFC_UNIFIED_ESTABLISHMENT.md`,
`CLAUDE.md`. `buffer`: `CLAUDE.md`, `MODULE.md`, `ANDROID_ART_ALLOCATOR.md`. Sibling repos live at
`../git/buffer` and `../git/socket`.

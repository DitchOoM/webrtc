# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Project overview

`com.ditchoom:webrtc` — WebRTC **data channels** for Kotlin Multiplatform: zero-copy, sans-io, and
deterministic under test. Built on DitchOoM `buffer` (buffers, codec, crypto, flow) and `socket`
(transport model, typed errors, `NetworkMonitor`, real UDP actuals). The protocol cores are **ours**, in
common Kotlin — we do not wrap libwebrtc on any non-browser target. Browsers are the sole exception:
there `peerConnectionSupport()` delegates to `RTCPeerConnection`. Media (RTP/SRTP) is not implemented.

**Read these first, in order** (a resumed session starts here):

1. [`ARCHITECTURE.md`](./ARCHITECTURE.md) — how the pieces fit and why. Sections are cited from KDoc
   throughout the source as `ARCHITECTURE §n`, so keep the numbering stable.
2. [`DESIGN_PRINCIPLES.md`](./DESIGN_PRINCIPLES.md) — the type-safety + zero-copy manifesto, with code
   patterns.
3. [`TESTING.md`](./TESTING.md) — the tiers, the harness, the L1↔L2 parity matrix, external vectors.
4. [`README.md`](./README.md) — what a consumer sees. Its quickstart is compiled and diff-checked by
   `ReadmeQuickstartTest`; edit the two together or the build fails.

## Current state

Released on Maven Central; the data-channel stack is complete. It establishes and carries data channels
against Chrome, Firefox, WebKit, Pion and werift over real NAT kernels in CI across
`{x64, arm64} × {v4, v6, dual}`, and every lane also gates on the data-channel *semantics* sequence
(fragmentation, unordered, PR-SCTP, multiplexing, reverse-direction, per-channel close, graceful
shutdown). Pinned at socket 4.0.0 + buffer 6.23.0.

What works that is easy to under-estimate:

- **ICE restart survives the session.** `restartIce()` records intent; the next `createOffer()` carries a
  fresh generation; a peer's own restart is detected from an offer whose ufrag *and* pwd both changed;
  `setLocalDescription(Rollback)` restores the retained generation. DTLS and SCTP never renegotiate
  (RFC 8842 §5.5), open channels keep their stream ids, and data keeps riding the old pair until the new
  one nominates.
- **Trickled candidates carry their generation** (RFC 8838 §3.1), stamped inside the driver's serialized
  loop so a candidate cannot be tagged with a generation it is not in. An incoming candidate is *routed*
  by that tag: one for a superseded generation is discarded with a typed reason, one for a generation
  whose offer has not arrived is held (bounded, oldest evicted) and released by the credentials event —
  never by a timer, so the core stays sans-io. Untagged candidates apply to the current generation
  exactly as before. Opt out with `TrickleGenerationPolicy.Untagged`.
- **mDNS goes both ways** (RFC 8828) — opt-in, and it also redacts the `raddr` and the foundation, both
  of which would otherwise spell the host address out on the same line.
- **`systemNetworkMonitor()` is push-first**, composing socket's *reactivity* with our own *address
  enumeration* (see ARCHITECTURE §4 — they answer different questions). A platform with no interface
  table says so in the type (`NetworkMonitorSupport.Unavailable`); one that can enumerate but has nothing
  pushing returns `Degraded(monitor, reason)`, so "it will be slower, and here is why" is answerable at
  config time rather than by inspecting a live session.
- **`PeerConnection.diagnostics`** is a sealed, non-fatal observation stream (watcher stopped, remote
  candidate discarded, interface probe failed). Channel-backed rather than a `SharedFlow` on purpose: a
  Channel buffers from construction, and the most important diagnostic is emitted during start-up, which
  no caller can reliably subscribe ahead of.
- **`IceRestartPolicy` defaults to `Manual`** deliberately — an automatic restart is a renegotiation only
  the app's signaling channel can carry, so it is opt-in rather than a default flip.

Renegotiation is proven in **both** directions: `carrier-switch` lanes prove a production stack correctly
answers a restart we initiate, and the `foreign-restart` lanes (issue #87, shipped in `d727189`) prove we
detect and answer one that Pion, Chrome, Firefox or WebKit originates — five lanes, plus the role flip that
exercise exposed.

What is genuinely left, and why the data-channel stack is not yet something a stranger can pick up:

- **The native entry point now exists** (#136, and #135's secure-defaults half): `nativePeerConnection()`
  in `webrtc`'s `socketMain` over `systemIceGathering()` in `webrtc-ice`'s. Both take the `DatagramBinder`
  as a **required** parameter, so neither can own a socket (§11.6) — that is what the two earlier
  deferrals were waiting for. `IceGatheringPolicy`, `IceServer` and `IceServerCredentials` moved down into
  `webrtc-ice` for it; `com.ditchoom.webrtc` keeps typealiases, but Kotlin cannot reach a *nested*
  classifier through one, so `IceServerCredentials.LongTerm` must be imported from the new package.
  mDNS defaults **on** in the factory only; a hand-built `NativePeerConnection` is unchanged. What it
  still cannot honour is refused by typed reason rather than dropped: `turns:`, `?transport=tcp`, a
  credential-free `turn:`, an unresolvable name.
- **No shippable native `bufferFactory` default** (#125), and no fail-fast when an injected one cannot back
  real socket I/O (#131). The workaround is real — `BufferPool(factory = BufferFactory.deterministic())` is
  native-backed *and* refcounted — but it only reclaims what the stack releases, and `webrtc-stun` releases
  nothing (see the #125 discussion).
- **TURN is short-lived and single-server-proven.** No allocation Refresh or permission re-installation, so
  a relayed session dies at the server's LIFETIME (#137); and the long-term-credential key is the raw
  password rather than `MD5(user:realm:pass)`, never exercised against a commercial provider (#138).
- **Platforms:** tvOS/watchOS publish but cannot establish, blocked upstream on `socket-udp` packaging
  (#127); Node needs blocking raw-ECDH plus a shipped binder (#133).
- **Media** (RTP/SRTP), which remains out of scope.

## Traps and standing corrections

Things that have cost real time here. Read before acting on a premise that sounds settled.

- **"socket core vendors a second BoringSSL" is FALSE, and has been for a long time.** It was true once,
  outlived its truth in four separate comments, and acting on it produced a hand-rolled implementation of
  something already published. socket's `LinuxSockets` cinterop klib embeds only `liburing.a`, and socket
  and `buffer-crypto` resolve to the *same* `boringssl-canonical`, which Gradle dedupes. Verified by
  linking the native peer on linuxX64 **and** linuxArm64 with socket core present.
- **Stale premises are this codebase's recurring failure mode** — five separate instances so far, each
  costing between a wrong comment and ~1000 wrong lines. When a comment explains why something *cannot*
  be done, check whether it still can't before building around it. The fifth instance was **this file**:
  it claimed foreign-initiated renegotiation was unexercised for months after #87 shipped five lanes
  proving otherwise. A document that is read first is the worst place for a stale premise — correct this
  section as soon as the state it describes changes.
- **`linkTopology()` erases the reachability verdict on purpose.** socket's `NetworkState` ladder carries
  `Routable(id, Pending|Confirmed)`, and on real hardware Android grants `INTERNET` ~1s before
  `VALIDATED` on *every* reassociation. Forwarding that transition as an interface change would
  re-enumerate on a link whose addresses never moved, so the trigger projects the verdict away and keeps
  everything else. `LinkTopologyTest` pins both halves.
- **`InterfaceSnapshot` is sealed for one specific reason:** a failed `getifaddrs` reported as an *empty*
  interface set reads to `pathRidesOneOf` as "the selected pair's interface is gone", which would restart
  a healthy session on every probe failure. A failure is `Unavailable(reason)`, never an empty
  `Enumerated`.
- **A deterministic "flake" is usually a harness observation bug, not a stack bug.** A red lane whose peer
  logs show success has, more than once, been the harness reading `docker compose logs` twice or matching
  only RUNNING containers.
- **`webrtc-ice`'s `socketMain` is the only place `socket-udp` may appear in production code**, and the
  cores must never depend on socket in `commonMain` (ARCHITECTURE §11.6). A binder that owns its socket
  forecloses sharing one demuxed UDP socket with QUIC-P2P.

## Standing directives

Non-negotiable. The first two are enforced by CI (`.github/workflows/standing-directives.yaml`); all are
checked in the adversarial review gate.

1. **No `ByteArray` — and no primitive array of any kind** (`IntArray`, `LongArray`, `ShortArray`, …) in
   production (`*Main/`) source sets. A primitive array in a hot path is a guaranteed copy; this library
   exists to avoid that. Use `ReadBuffer` / `WriteBuffer` / `PlatformBuffer` and slice views. Genuine
   platform edges (an FFI call that demands a `ByteArray`) annotate the line
   `@Suppress("NoByteArrayInProd")` with a comment naming the specific API surface.
2. **No hardwired `Clock.System` / `Random.Default` / `Dispatchers.*` inside cores.** Every source of
   time, entropy and concurrency is a constructor-injected seam with a production default. This is what
   lets the whole stack run under `runTest` virtual time. A genuine production-default construction
   annotates the line `@Suppress("UnseamedEntropy")`.
3. **Errors are typed, never stringly.** Everything maps into the `SocketException` sealed hierarchy with
   exhaustive sealed reasons (`IceFailureReason.NoCandidatePairs`, `.ConsentExpired`, …). Strings are
   diagnostics, never discriminants.
4. **Assert observable state + a watchdog, never wall-clock budgets.**
5. **Every bug fix ships with its deterministic fixture in the same PR.** The corpus only grows.
6. **Buffers are factory-injected, pooled in hot paths, `use {}`/scoped lifecycle**, with a tracking
   factory in every test harness (invariant: no leaks).
7. **The PR description states which platform lanes were runtime-validated vs compile-faithful** (the
   `V6_MAC_VALIDATION` convention: Apple/Android runtime-validated on runners).

## Type-safety house style (make illegal states unrepresentable)

The cores are state machines; the type system is the first line of correctness. See
[`DESIGN_PRINCIPLES.md`](./DESIGN_PRINCIPLES.md) for worked examples. In short:

- **Value classes wrap every identifier.** `TransactionId`, `Ufrag`, `StreamId`, `Tsn`, `DataChannelId`,
  `Mid`, `CertificateFingerprint` are each `@JvmInline value class` around their payload — zero runtime
  cost, but the compiler refuses to pass a `Ufrag` where an `IcePassword` is expected. IDs are never bare
  `String`/`Int`/`Long` at an API boundary.
- **Sealed hierarchies + exhaustive `when`, no `else`.** Message classes, connection states and failure
  reasons are sealed. A `when` over them compiles without an `else`; adding a case is a compile error at
  every call site until handled. Prefer this to enums when variants carry data.
- **No boolean or nullable soup.** Do not model a state as `connected: Boolean` + nullable
  `failureReason` (which can encode "connected AND failed"). Model it as a sealed `PeerConnectionState`
  where each state carries exactly the data valid in it — the illegal combinations are unrepresentable.
- **Nullability is a deliberate signal, not a default.** A nullable type means "genuinely absent"; never a
  stand-in for an error (that is a typed reason) or an uninitialized field (that is a different state in
  the sealed hierarchy). `nextDeadline(now): Instant?` returns null to mean "no timer armed" — one real
  meaning.
- **Parse failures are typed rejects, never throws-through or crashes** (T0 discipline).

## Build commands

```bash
./gradlew build                 # build all modules, all host-available targets
./gradlew allTests              # tests across every module + platform
./gradlew apiCheck              # binary-compatibility validation against checked-in .api files
./gradlew apiDump               # regenerate .api files after an intentional public-API change
./gradlew ktlintCheck           # lint  (ktlintFormat to auto-fix)
./gradlew detektAll             # multiplatform static analysis (non-blocking; sees Native/JS/WASM)
./gradlew publishToMavenLocal   # publish to ~/.m2  (runs prePublishCheck first)
./gradlew :webrtc-stun:jvmTest --tests "com.ditchoom.webrtc.stun.StunTest"
```

Requires **JDK 21** (enforced via toolchain). Apple targets build on macOS only.

## Build logic — the convention plugin (no copy-paste)

All per-module build configuration lives in **one** convention plugin,
`build-logic/src/main/kotlin/webrtc.multiplatform-library.gradle.kts`. It owns the KMP target matrix, the
JDK-21 toolchain, Android, ktlint, dokka, kover, binary-compatibility validation, Maven Central
publishing, signing and version derivation. A module's own `build.gradle.kts` therefore contains **only
its dependencies**:

```kotlin
plugins { id("webrtc.multiplatform-library") }
kotlin { sourceSets { commonMain.dependencies { api(libs.buffer); api(libs.buffer.codec) } } }
```

Structural identity is derived from the module name (artifactId, JS module name `<name>-kt`, Android
namespace `com.ditchoom.<name-dots>`). Per-module POM prose lives in `<module>/gradle.properties`
(`POM_NAME`, `POM_DESCRIPTION`); shared POM/developer/license fields are in the root `gradle.properties`.
Plugin versions are declared once in `gradle/libs.versions.toml`.

To add a module: create the dir + `src/commonMain` + `src/commonTest`, add a `build.gradle.kts` (as
above) and a `gradle.properties`, and `include(":…")` it in `settings.gradle.kts`. Nothing else.

## CI/CD

- **PR** (`review.yaml`): `standing-directives` greps → `build-linux` + `build-apple` →
  `validate-artifacts` → `consumer-smoke` (`.ci/consumer-smoke`, a standalone build resolving
  `com.ditchoom:webrtc` + `webrtc-testsuite` by coordinate; compiles, K/N-links, and runs
  `withWebRtcHarness { natType(); relayOnly(); impaired() }` against a **cold** resolve — throwaway
  `GRADLE_USER_HOME`, no build cache).
- **Release** (`merged.yaml`): version bump controlled by PR labels (`major` / `minor`, else patch;
  `skip-release` / `draft-release` change the flow) → build → validate → `consumer-smoke` (maven-local,
  both hosts — `publish` needs it, so a consumer-breaking release never reaches Central) →
  `publish-to-central` → finalize (tag + GitHub release). `release.yaml` completes/cancels a draft;
  `released.yaml` mirrors a pushed tag **and then re-runs `consumer-smoke` against Maven Central only**
  (no `mavenLocal()` fallback), which is what proves the publish itself.
- Version is auto-derived from Maven Central metadata + the label bump.
- Every published artifact (including `webrtc-testsuite`) goes through `validate-artifacts` from its
  first release.

## Source docs in sibling repos to consult

`socket`: `RFC_DETERMINISTIC_SIMULATION.md`, `TESTING_STRATEGY.md`, `RFC_UNIFIED_ESTABLISHMENT.md`,
`CLAUDE.md`. `buffer`: `CLAUDE.md`, `MODULE.md`, `ANDROID_ART_ALLOCATOR.md`. Sibling repos live at
`../git/buffer` and `../git/socket`.

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
  real socket I/O (#131). This is the sharpest remaining gap: on the 7 native targets the README calls
  "Full", a session built with the documented defaults dies on its **first connectivity check**, because
  `BufferFactory.Default` is a GC-heap buffer on K/N and io_uring rejects it. Nothing caught it because
  everything that touches a real native socket injects its own factory.
  The workaround — `BufferPool(factory = BufferFactory.deterministic())`, native-backed *and* refcounted —
  is now genuinely usable: the "it only reclaims what the stack releases, and `webrtc-stun` releases
  nothing" caveat that used to sit here is **obsolete**, because releasing is exactly what the ownership
  work did. Two things still bound it, and neither is ours alone:
  * **The receive side is unowned.** Nothing releases a received datagram — not the driver's loop, not
    TURN's demux, not the gather. It is not a bug site so much as a missing half: the buffer is shared by
    *reference* (decoded attributes are slices of it), so "release when done" needs a last-reader rule
    first, or it turns a leak into a use-after-free. `LeakTrackingFactory` cannot see it either — the
    receive buffer comes from the *channel's* factory, not `IceConfig`'s.
  * **DitchOoM/socket#277:** socket's own JVM/NIO and Node send paths slice the payload and drop the
    `TrackedSlice` without releasing it, so on those backends one send costs one pool chunk, permanently,
    however exact this repo is. Linux and Apple are clean. Proven with pool stats, not inferred.
- **TURN is no longer short-lived**, as of #137/#138: the allocation refreshes at a fraction of the
  *granted* LIFETIME, permissions are re-installed (§9), every request retransmits, and the
  long-term-credential key is the RFC 8489 §9.2.2 `MD5(user:realm:pass)` — pure-Kotlin MD5 in
  `webrtc-stun`, pinned by the RFC 5769 §2.4 vector, with the relay lanes now authenticating for real
  (see the coturn `-n` entry below). What remains is exposure, not capability: still unexercised against a
  **commercial** provider, whose realm/nonce rotation and quota behaviour we have never seen.
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
- **Stale premises are this codebase's recurring failure mode** — seven separate instances so far, each
  costing between a wrong comment and ~1000 wrong lines. When a comment explains why something *cannot*
  be done, check whether it still can't before building around it. The fifth instance was **this file**:
  it claimed foreign-initiated renegotiation was unexercised for months after #87 shipped five lanes
  proving otherwise. A document that is read first is the worst place for a stale premise — correct this
  section as soon as the state it describes changes.
- **A config file the server never read: coturn's `-n` meant every relay lane tested an OPEN RELAY.**
  `entrypoint.sh` ended `exec turnserver -c "$CONF" -n`, and in coturn **`-n` means "do not use a
  configuration file"** — so `lt-cred-mech`, `user`, `realm` and `min-port`/`max-port` were all inert and
  the server accepted unauthenticated allocations. Fixed alongside #138. Two lessons worth keeping:
  * **The reason it survived review:** stock `coturn/coturn:4.6`'s own `docker-entrypoint.sh` re-expands
    args with `eval "echo $i"`, and `echo -n` prints nothing, so `-n` is *silently deleted* there. Every
    `docker run coturn/coturn:4.6 -c cfg -n` example online therefore *does* read the config while our
    direct `exec` did not — same flags, opposite server.
  * **The tell was in the data all along:** `harness.env` pins `TURN_MIN_PORT=49160`/`MAX=49200` and CI's
    green runs handed out ports in 49546…64453 — coturn's *default* 49152–65535 range. A configured
    value that never shows up in the output is evidence the config is not being read. Post-fix runs
    allocate inside the pinned range, which is now the cheapest regression check.
  * Generalization of the above bullet: a *premise* can be stale, and so can a *dependency's
    configuration*. "The setting is in the file" is not evidence the process applied it.
- **The same trap, third instance: a bare `external-ip` is accepted ONCE and then applied to every
  family.** The entrypoint appended one per family; coturn kept the FIRST (v4), logged `ERROR: You cannot
  define external IP more than once in the configuration`, and then reported every **IPv6** allocation at
  the **v4** address with the v6 relay port. The dual `relay-only` lane therefore advertised a relay
  candidate whose family did not match its own base, and every permission on it drew `443: Peer Address
  Family Mismatch`. Fixed by deleting `external-ip` outright — coturn is not behind NAT in the harness, so
  the only mapping it could express was the identity. Two things worth keeping:
  * **The error was in the startup log all along, 40 lines above the failure.** What made it unreadable
    was that the log never left the container (fixed in the same PR, #149) — the diagnostics landed and
    the very first thing they explained was this.
  * **Our stack was not wrong anywhere.** `TurnAllocation` already sends REQUESTED-ADDRESS-FAMILY=IPv6 on
    a v6 server (RFC 8656 §7.2), coturn allocated a v6 relay, and the candidate carried exactly what the
    response said. Confirmed by running coturn's OWN client (`turnutils_uclient -x`) against the same
    image, which fails identically — reach for the dependency's own client before suspecting ours.
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
- **`send` does not consume.** socket's datagram channels transmit the window `[position, limit)` without
  advancing it, on **all four** backends — io_uring reads `nativeAddress + position()` and names the
  contract in a comment, the NIO and Node paths take their own internal `slice()`, Apple reads
  `position()`/`remaining()` directly. So re-sending one encoded request across retransmissions is
  correct, and "slice it per attempt or the second send goes out empty" is a hazard socket does not have.
  Defending against it is not free: `PooledBuffer.slice()` takes a **reference**, so a slice per
  retransmission that nobody releases pins the chunk for good. Slice when something else needs a second
  live view (`StunTransaction` emits `SendRequest` outputs a driver may hold) — not to survive a send.

  The converse is the open half, filed as **DitchOoM/socket#277**: socket's own JVM/NIO `stage()` and Node
  `sendPayload()` slice the payload internally and drop the `TrackedSlice` without releasing it, so on
  **those** backends a pooled buffer never returns to the pool no matter how diligent this repo's release
  paths are. The vnet cannot see it, and neither can `LeakTrackingFactory` — `freeNativeMemory()` marks a
  buffer freed whichever way the refcount went, so only `pool.stats().currentPoolSize` discriminates,
  which is how it was proven rather than argued. Anything claiming pool-exactness on a real
  JVM/Android/Node socket is claiming it about socket too.

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

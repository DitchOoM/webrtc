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
shutdown). Pinned at socket 4.1.0 + buffer 6.25.0 — the pair that carries
`DatagramCapabilities.requiresNativeMemoryBuffers`, which is what the send-side buffer check consumes.
They move together: socket-udp 4.1.0's POM pins buffer 6.25.0.

### Capabilities that are easy to under-estimate

- **ICE restart survives the session.** `restartIce()` records intent; the next `createOffer()` carries a
  fresh generation; a peer's own restart is detected from an offer whose ufrag *and* pwd both changed;
  `setLocalDescription(Rollback)` restores the retained generation. DTLS and SCTP never renegotiate
  (RFC 8842 §5.5), open channels keep their stream ids, and data keeps riding the old pair until the new
  one nominates. Proven in **both** directions: the `carrier-switch` lanes prove a production stack
  answers a restart we initiate, and the `foreign-restart` lanes prove we detect and answer one that
  Pion, Chrome, Firefox or WebKit originates.
- **Trickled candidates carry their generation** (RFC 8838 §3.1), stamped inside the driver's serialized
  loop so a candidate cannot be tagged with a generation it is not in. An incoming candidate is *routed*
  by that tag: one for a superseded generation is discarded with a typed reason, one for a generation
  whose offer has not arrived is held (bounded, oldest evicted) and released by the credentials event —
  never by a timer, so the core stays sans-io. Untagged candidates apply to the current generation. Opt
  out with `TrickleGenerationPolicy.Untagged`.
- **mDNS goes both ways** (RFC 8828) — opt-in, and it also redacts the `raddr` and the foundation, both
  of which would otherwise spell the host address out on the same line.
- **`systemNetworkMonitor()` is push-first**, composing socket's *reactivity* with our own *address
  enumeration* (ARCHITECTURE §4 — they answer different questions). A platform with no interface table
  says so in the type (`NetworkMonitorSupport.Unavailable`); one that can enumerate but has nothing
  pushing returns `Degraded(monitor, reason)`, so "it will be slower, and here is why" is answerable at
  config time rather than by inspecting a live session.
- **`PeerConnection.diagnostics`** is a sealed, non-fatal observation stream: watcher stopped, remote
  candidate discarded, interface probe failed, transmit failed, relay permission refused. Channel-backed
  rather than a `SharedFlow` on purpose — a Channel buffers from construction, and the most important
  diagnostic is emitted during start-up, which no caller can reliably subscribe ahead of. The last two
  exist because the alternative is a *silent* failure that looks like the network: a socket refusing
  every send and a TURN server answering `443 Peer Address Family Mismatch` both otherwise present
  identically to a peer that stopped answering. `RelayPermissionRefused.error` is a protocol code and
  therefore a real discriminant, unlike the `Throwable` payloads beside it.
- **`IceRestartPolicy` defaults to `Manual`** deliberately — an automatic restart is a renegotiation only
  the app's signaling channel can carry, so it is opt-in rather than a default flip.
- **TURN is long-lived.** The allocation refreshes at a fraction of the *granted* LIFETIME, permissions
  are re-installed (§9), every request retransmits, and the long-term-credential key is the RFC 8489
  §9.2.2 `MD5(user:realm:pass)` — pure-Kotlin MD5 in `webrtc-stun`, pinned by the RFC 5769 §2.4 vector.
- **The native entry point exists**: `nativePeerConnection()` in `webrtc`'s `socketMain` over
  `systemIceGathering()` in `webrtc-ice`'s. Both take the `DatagramBinder` as a **required** parameter,
  so neither can own a socket (ARCHITECTURE §11.6). `IceGatheringPolicy`, `IceServer` and
  `IceServerCredentials` live in `webrtc-ice`; `com.ditchoom.webrtc` keeps typealiases, but Kotlin cannot
  reach a *nested* classifier through one, so `IceServerCredentials.LongTerm` must be imported from the
  new package. mDNS defaults **on** in the factory only; a hand-built `NativePeerConnection` is
  unchanged. What it cannot honour is refused by typed reason rather than dropped: `turns:`,
  `?transport=tcp`, a credential-free `turn:`, an unresolvable name.

### Buffer ownership: every seam is owned, and gated at zero

The rule is written once on `IceProtocol.releaseReceived` and restated at each module's seam. A buffer
has exactly one owner; a loop that receives one either **consumes** it (release before the next
iteration) or **transfers** it (the receiver then owes it). A decoded attribute or wire field is
neither — it is a **borrow**, a slice that must not outlive its owner. On a pooled buffer a borrow is
also an `addRef`, so it has to be handed back too, which is why `assertNoLeaks` is not sufficient
anywhere: it proves `freeNativeMemory()` was *called*, and is structurally blind to a refcount that
never reached zero. **`assertPoolDrained` is the gate.**

| seam | fixture |
|---|---|
| received datagrams | `PooledReceiveChunkTest`, `ReceivedDatagramOwnershipTest` |
| ICE send | `SessionSeamOwnershipTest` |
| SCTP send | `SctpSendSeamOwnershipTest` |
| DTLS record (both 1.2 and 1.3) | `DtlsRecordSeamOwnershipTest`, `DtlsSessionBufferOwnershipTest` |
| mDNS responder, TURN relay | `MdnsTurnSeamOwnershipTest` |

**The one outstanding gap is upstream, not ours.** buffer-crypto's Apple AEAD `open` takes two
`absoluteView` slices of the ciphertext it is handed (`Aead.apple.kt` / `AeadBridge.apple.kt`) and
releases neither, so on Apple every opened DTLS record pins the *receive* chunk twice. Nothing here can
reach those slices; `DtlsRecordSeamOwnershipTest` therefore gates its two record seams at zero on every
target and asserts only `assertNoLeaks` on its wire stand-in, with the raise-it-back condition written at
the assertion. The receive seam itself is still gated at zero on the target the blast radius covers.

Blast radius is **Kotlin/Native Linux only**: it is the sole target where `BufferFactory.Default` is a
GC-heap buffer, so `networkBuffer()` falls back to `deterministic()` there and a buffer nobody releases
stays allocated. Everywhere else `Default` is native *and* auto-reclaimed. `BufferPool(factory =
BufferFactory.deterministic())` — native-backed *and* refcounted — is the recommended consumer shape.

Two things about measuring it, both learned expensively:

- **Measure at the pool's backing factory** (`created - currentPoolSize`). Every formula derived from
  `PoolStats` has been wrong, in both directions. A *decorating* tracker perturbs its own measurement,
  because the liveness probe takes a slice.
- **One tracker per seam per peer**, and never a seam shared with harness scenery. A single tracker
  pointed at two seams produces a number that cannot be attributed to either.

Two facts about buffer-crypto that a caller has to know, because the types do not say them:
`AesGcmKey.of`, `VerifyKey.ecdsaP256` and `HmacSha256Mac` **copy** their input, so the source buffer is
spent at the call; `KeyAgreementPublicKey.of` **slices** it and the type it returns is not
`AutoCloseable`, so the caller has to hand `peer.encoded` back itself. Release also implies **wipe** for
anything derived: both key schedules allocate through `BufferFactory.secure()`, because an unwiped
traffic secret handed to a shared pool is a chunk the next `allocate()` gets — a leak traded for key
disclosure, which is worse.

An injected factory the send path cannot transmit from is refused at the bind that precedes the first
send, as a typed `UnsendableBufferFactoryException` naming the `WireBufferSeam` to change. The question
is put to the **channel** (`DatagramCapabilities.requiresNativeMemoryBuffers`), never to a platform table
and never as "is this buffer native": the JVM/NIO and Node send paths take a heap buffer happily, so the
buffer-side phrasing would break three working configurations to fix one. The 1-byte probe only runs once
a channel has said it needs a raw address, so a vnet run costs nothing. Checked at both `IceAgentDriver`
binds and at `MdnsEndpoint.socketFor` — the last deliberately *outside* `SocketUdpMdnsBinder`, whose
catch-all maps every exception to "mDNS is unavailable here" and would swallow the diagnosis.

### What is left

- **TURN against a commercial provider** — unexercised. Realm/nonce rotation and quota behaviour under a
  real provider is the exposure we have never seen.
- **Platforms:** tvOS/watchOS publish but cannot establish, blocked upstream on `socket-udp` packaging
  (#127); Node needs blocking raw-ECDH plus a shipped binder (#133).
- **Media** (RTP/SRTP), which remains out of scope.

## Traps

Things that have cost real time here. Read before acting on a premise that sounds settled.

- **Stale premises are this codebase's recurring failure mode** — eight instances so far, each costing
  between a wrong comment and ~1000 wrong lines. When a comment explains why something *cannot* be done,
  check whether it still can't before building around it. One instance was **this file**, which is the
  worst place for one; correct this document as soon as the state it describes changes, and keep the
  correction itself in git history rather than here.
- **A fix reaches a release as *content*, not as a commit.** Rebases, squashes and merge commits all
  detach a subject line from the sha that shipped it, so `git tag --contains <sha>` answers "was this
  object released", which is a different question. **Check the tree at the tag** (`git show v<x>:<file>`)
  before writing down that something is unreleased — and before building a workaround around the belief.
- **"The setting is in the file" is not evidence the process applied it.** coturn's `-n` means "do not
  use a configuration file", so `exec turnserver -c "$CONF" -n` ran an **open relay** for months while
  `lt-cred-mech`, `user`, `realm` and the port range sat inert. It survived review because stock
  `coturn/coturn:4.6`'s own entrypoint re-expands args with `eval "echo $i"`, where `echo -n` prints
  nothing — so every `docker run … -c cfg -n` example online *does* read the config while our direct
  `exec` did not. The tell was in the data: `harness.env` pins `TURN_MIN_PORT=49160`/`MAX=49200` and
  green runs handed out ports in coturn's *default* 49152–65535 range. **A configured value that never
  shows up in the output is evidence the config is not being read**, and checking the allocated port
  range is now the cheapest regression check there is.
- **Read the dependency's own startup log, and reach for its own client before suspecting ours.** A bare
  `external-ip` is accepted ONCE and then applied to every family: coturn kept the first (v4), logged
  `ERROR: You cannot define external IP more than once`, and reported every **IPv6** allocation at the
  **v4** address, so every permission drew `443: Peer Address Family Mismatch`. The error sat in the
  startup log 40 lines above the failure — unreadable only because the log never left the container.
  Our stack was not wrong anywhere, which `turnutils_uclient -x` confirmed by failing identically.
- **`send` does not consume.** socket's datagram channels transmit the window `[position, limit)` without
  advancing it, on **all four** backends — io_uring reads `nativeAddress + position()`, the NIO and Node
  paths take their own internal `slice()`, Apple reads `position()`/`remaining()` directly. So re-sending
  one encoded request across retransmissions is correct. Defending against a hazard socket does not have
  is not free: `PooledBuffer.slice()` takes a **reference**, so a slice per retransmission that nobody
  releases pins the chunk for good. Slice when something else needs a second live view — not to survive a
  send.
- **A slice is safe to release on a pool and unsafe to hold on a bare `deterministic()`, and the reverse
  for its parent.** `NativeBufferSlice.freeNativeMemory()` is a no-op and every read `checkOpen()`s the
  parent, so freeing a parent while a slice is live is a use-after-free there while a pool's refcount
  hides it. **Both regimes have to be right**, and a fixture that only runs on one will not tell you.
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
  only RUNNING containers. The same applies to leak fixtures: a harness that slices without releasing, or
  measures before a cancelled coroutine's `finally` has had a dispatch, has invented a production leak
  three times.
- **`webrtc-ice`'s `socketMain` is the only place `socket-udp` may appear in production code**, and the
  cores must never depend on socket in `commonMain` (ARCHITECTURE §11.6). A binder that owns its socket
  forecloses sharing one demuxed UDP socket with QUIC-P2P.
- **socket core does not vendor a second BoringSSL.** It was true once, outlived its truth in four
  separate comments, and acting on it produced a hand-rolled implementation of something already
  published. `LinuxSockets`'s cinterop klib embeds only `liburing.a`, and socket and `buffer-crypto`
  resolve to the *same* `boringssl-canonical`, which Gradle dedupes.

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
   factory in every test harness. The invariant is `assertPoolDrained` — every chunk back in the pool —
   not `assertNoLeaks`, which cannot see an unreleased borrow.
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
  `publish-to-central` → finalize (tag + GitHub release). `release.yaml` completes/cancels a draft.
- **What proves the publish is `consumer-smoke-central`, a job inside `merged.yaml`** — it resolves the
  just-pushed version from Maven Central and nothing else (no `mavenLocal()` fallback), both hosts, cold.
  **Not `released.yaml`**, which hangs off a tag *push* and therefore never fires: the tag is created
  through the REST API with `secrets.GITHUB_TOKEN`, for which GitHub dispatches no workflow events. An
  empty run list there is **expected and not a broken gate**; reading it as one costs an investigation.
- Version is auto-derived from Maven Central metadata + the label bump.
- Every published artifact (including `webrtc-testsuite`) goes through `validate-artifacts` from its
  first release.

## Source docs in sibling repos to consult

`socket`: `RFC_DETERMINISTIC_SIMULATION.md`, `TESTING_STRATEGY.md`, `RFC_UNIFIED_ESTABLISHMENT.md`,
`CLAUDE.md`. `buffer`: `CLAUDE.md`, `MODULE.md`, `ANDROID_ART_ALLOCATOR.md`. Sibling repos live at
`../git/buffer` and `../git/socket`.

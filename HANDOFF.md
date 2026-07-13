# HANDOFF

Live state of the current wave. A resumed session reads `RFC_KMP_WEBRTC.md` → `EXECUTION_PLAN.md` →
this file. Update it whenever you stop mid-wave.

## Where we are: **the pure-codec / socket-free track is COMPLETE — next work needs the transport, which is blocked on a deterministic UDP `commonMain`**

All three Phase-1 protocol codecs are **merged to `main`** and green on every lane. Nothing is released
to Central yet (every merge was `skip-release`; a `v0.0.1` tag exists from an earlier release exercise).

| Wave | What | Status |
|---|---|---|
| **W0** | foundations (repo, convention plugin, CI, publish pipeline) | ✅ merged |
| **W1** | `webrtc-stun` — STUN/TURN codec + sans-io transactions | ✅ merged (PR #4) |
| **W6 (partial)** | `webrtc-sdp` — SDP text codec + sans-io JSEP machine | ✅ merged (PR #5) |
| **W5 (codec floor)** | `webrtc-sctp` — SCTP chunk codec + DCEP messages | ✅ merged (PR #6) |

`main` history: `14a4f07` W5 (#6) → `72535bb` W6 no-op (#7, empty — see the git note below) →
`59397c2` W6 (#5) → `17e04d6` W1 (#4). Both modules present once (`webrtc-sdp` 14 files,
`webrtc-sctp` 13); `webrtc-sctp` deps are `buffer` + `buffer-codec` only.

### The blocker for everything next: a deterministic UDP `commonMain`
The pure codecs (stun/sdp/sctp) were buildable and testable **without any I/O**. Everything that remains
— W2 (vnet), W3 (ice), W4 (dtls), the rest of W5 (SCTP association + `DataChannel`), the rest of W6
(`PeerConnection`), W7 (harness) — needs a **transport seam**: an **unconnected, deterministic UDP
`DatagramChannel` in `commonMain`** (per-datagram source address on receive, arbitrary dest on send),
runnable under `runTest` virtual time on every target. That is W0's still-open socket promotion
(RFC §11.1 simulation-engine home + the `DatagramChannel` seam into socket-core) and is being built
**separately, with the socket sibling repo / socket agent** (`../git/socket`). **Until that lands
upstream and is released to Central, W2+ cannot start** — webrtc must not depend on an unpublished
sibling snapshot (the W0 discipline). Open cross-repo decisions to settle alongside it: §11.1 (sim
home — recommend standalone `ditchoom-simulation`), §11.3 (DTLS 1.2-vs-1.3, before W4), §11.4 (mDNS,
before W3).

### Recommended next wave once the UDP seam is available: **W2 (vnet)**
Pure-Kotlin, sans-io, fully local-testable under `runTest` (no native deps) — NAT models
(full-cone / address-restricted / port-restricted / symmetric, mapping lifetimes, hairpinning) +
seeded impairment pipe (loss/reorder/dup/delay) + topology-as-data builders, implementing the W0
`DatagramChannel` seam. Exit: NAT-model property tests + two-peer echo over each topology under virtual
time, all platforms. W2 unblocks W3 (ICE), the integration spine. W4 (`webrtc-dtls`, BoringSSL) is
parallelizable but is the one native dep and needs Apple/Android runtime validation on runners — a
worse fit for local iteration.

### Small socket-free follow-ups still possible in-repo (optional, low-value)
- Thread the deferred `BufferFactory` seam through `webrtc-stun` / `webrtc-sctp` decode/verify/builder
  hot paths (they hardwire `BufferFactory.Default`/`.managed()`; additive/non-breaking). The
  `TrackingBufferFactory` no-leak half is blocked on the §11.1 sim-engine promotion.
- A fast/native CRC32c belongs upstream in `buffer` core (the `ReadBuffer.crc32` precedent) if a hot
  bulk-checksum path ever appears — additive; noted in `PERFORMANCE.md`.

### Standing reminders for the next session
- **`git fetch` and check remote tips via `gh api …/branches/main` before reasoning about what's
  merged.** A stale local `origin/main` tracking ref this session caused a redundant, empty W6 re-merge
  (PR #7, `72535bb`, 0 changes — harmless but avoidable).
- **Apple lanes are compile-faithful on this Linux box** — runtime-validate on the macOS runner and say
  so in the PR (`V6_MAC_VALIDATION`). W1/W6/W5 were all Apple-validated on the runner at merge.
- **Release trap:** merging a code PR auto-publishes to Central unless `skip-release` is applied via the
  REST API (`gh api repos/DitchOoM/webrtc/issues/<n>/labels -f 'labels[]=skip-release'`) and verified —
  `gh pr edit --add-label` fails silently here.

---

## Landed wave detail (history)

### W5 (codec floor) `webrtc-sctp` — merged (PR #6)
- **SCTP common header (RFC 4960 §3.1)** as a KSP `@ProtocolMessage` schema (`SctpCommonHeaderCodec`);
  chunk TLV framing + INIT/INIT-ACK parameter and ERROR/ABORT cause sub-TLVs hand-written, decoded as
  **zero-copy slice views**.
- **Sealed `SctpChunk`** — DATA, INIT, INIT-ACK, SACK, HEARTBEAT(/ACK), ABORT, SHUTDOWN(/ACK), ERROR,
  COOKIE-ECHO(/ACK), SHUTDOWN-COMPLETE, FORWARD-TSN (RFC 3758), + `Unrecognized`. `SctpPacket.decode`
  is **total** → typed `SctpRejectReason`.
- **CRC32c** self-contained (`Crc32c`) — 256-entry table in a **managed `ReadBuffer` (no `IntArray`)**,
  word-batched, little-endian field per App. B; validated vs the `0xE3069283` KAT + a bitwise reference.
- **Value-class ids** (`Tsn` w/ RFC 1982 arithmetic, `StreamId`, `StreamSequenceNumber`,
  `PayloadProtocolId`, `VerificationTag`); wrapped bit fields (`DataChunkFlags`, `unrecognizedAction`,
  DCEP `ChannelType` → sealed `Reliability`). **DCEP** `DataChannelMessage.{Open,Ack}`.
- **T0 floor** — round-trips, frozen golden vectors, malformed corpus + 20k totality + mutation,
  wrapper-transparency, CRC32c conformance. **Jazzer** `sctpCodecFuzz` (in `review.yaml`, 120s); a CI
  run was clean.
- **Two bugs found + fixed with fixtures** (directive #5): (1) a Jazzer find — `valueSize` from the
  *untruncated* `paddedLength` of a malformed final sub-TLV shrank the re-encode buffer under the
  checksum read → now from actual padded-view sizes (`regression-abort-cause-overrun.bin`); (2) a
  wire-correctness review find — `utf8Size` miscounted non-BMP (emoji) DCEP labels → now measures the
  actual UTF-8 bytes. Reviewer's "chunk length includes final pad" flag was confirmed RFC 4960
  §3.2-sanctioned (both forms accepted; decoder round-trips both) and documented.

---

## Prior wave: **W6 (partial) `webrtc-sdp` — merged (PR #5)**

Built on the **socket-free / non-UDP track** (the pure codecs + sans-io cores that build and unit-test
standalone, exactly as W1's `webrtc-stun` did) — **no** vnet, ICE gathering, DTLS, or DatagramChannel
dependency, so none of the deferred RFC §11.1 (sim-engine home) / §11.3 (DTLS) decisions are on this
path. Branched off the W1 branch (released `buffer 6.10.0`); `webrtc-sdp` deps are `buffer` core only
(SDP is text — no `buffer-codec` KSP schema, no crypto). **36 tests green on JVM, JS node+browser,
wasmJs node+browser, Linux/native, Android host** (`:webrtc-sdp:check` EXIT 0).

What landed (`webrtc-sdp/src/commonMain`):
- **SDP parser/serializer (RFC 8866)** — a hand-written line codec. The datagram is decoded to a
  `CharSequence` once (`parseText` accepts any `CharSequence` — no re-copy) and parsed index-based
  into a **round-trip-faithful** model: `SessionDescription` (session lines + `MediaDescription`s),
  every line (`SdpLine`) kept verbatim so parse→`encode` reproduces a canonical CRLF document
  byte-for-byte. `SessionDescription.parse` is **total** — hostile/non-UTF-8 bytes yield a sealed
  `SdpRejectReason`, never a throw. Structural failures are rejects; a broken single line
  (`o=`/`m=`/`a=fingerprint`) is a null typed-reader miss (the `RawAttribute` discipline for text).
- **Typed surface** — value-class `Mid`; `Origin`/`MediaLine`/`Fingerprint`/`SetupRole`/`SdpType`/
  `SignalingState`; on-demand interpreters (`SdpSection` extensions + `MediaDescription` methods) for
  the JSEP data-channel attributes, with session↔media fallback (RFC 8829 §5.2.1).
- **`SessionDescriptionBuilder`** + `dataChannelDescription` (RFC 8841 data-channel shape).
- **Sans-io JSEP machine** — `JsepSession.handle(event, now)` + `nextDeadline()` (always null: JSEP
  arms no timers). Enforces the RFC 8829 §3.5.1 signaling transition table + rollback; illegal edges
  are typed `JsepError.InvalidTransition` outputs that leave state untouched. Entropy injected
  (`Random` → `o=` session id); driven by a scripted signaling seam (direct `handle` calls in tests),
  no sockets.
- **T0 floor** — real Chrome/Firefox/Pion offer/answer vectors (parse + typed fields + byte-exact
  round-trip), malformed corpus + two 20k-input totality properties + single-line-drop mutation,
  wrapper-transparency (pooled / non-zero-offset slice), builder round-trips, full JSEP table. **Jazzer
  lane** (`sdpCodecFuzz`, wired into `review.yaml` at 120s) with a 7-seed committed corpus — a 30s
  local run was 1M+ execs clean. Benchmark in `PERFORMANCE.md`; `.api` committed; committed detekt
  baseline; ktlint + apiCheck + standing-directive greps green.

### W6-SDP notes / next steps
- **Not started (rest of W6, gated on the transport):** `PeerConnection` session API, browser/wasmJs
  `peerConnectionSupport()` `RTCPeerConnection` delegation, the `SocketException`-hierarchy error
  sweep. Those need the ICE/DTLS/SCTP stack beneath them (see the top-of-doc UDP-seam blocker). The
  browser delegation shell is the one piece nominally doable socket-free (it wraps the browser's own
  `RTCPeerConnection`), but it needs the `PeerConnection` API surface defined first.
- W6 was Apple-validated on the macOS runner at merge (`V6_MAC_VALIDATION`).

---

## Prior wave: **W1 `webrtc-stun` — merged (PR #4)**

W1 is **green on all 7 local lanes** (JVM, JS node+browser, wasmJs node+browser, Linux/native,
Android host — 34 tests each) and Apple-validated on the macOS runner. What landed:

- **STUN codec (RFC 8489):** header via a KSP `@ProtocolMessage` schema (`StunHeaderCodec`); the TLV
  attribute layer hand-written (STUN's 4-byte padding + MI/FINGERPRINT span-with-rewritten-length are
  outside the declarative codec). Attributes are **zero-copy slice views** over the datagram. Typed
  attributes: MAPPED / XOR-MAPPED-ADDRESS (v4/v6, array-free `IpAddress`), USERNAME/REALM/NONCE/SOFTWARE,
  ERROR-CODE, UNKNOWN-ATTRIBUTES; TURN (RFC 8656) types codec-only. Typed `StunRejectReason` (decode is
  total — never throws).
- **MESSAGE-INTEGRITY (HMAC-SHA1) + FINGERPRINT (CRC-32)** verified/appended in place via the new
  `buffer-crypto` `hmacSha1` + `buffer` `ReadBuffer.crc32`.
- **Sans-io `StunTransaction`** — `handle(event, now)` + `nextDeadline()`, RFC 8489 §6.2.1 retransmit
  schedule, injected clock + seeded transaction ids.
- **T0/T0′:** RFC 5769 §2.1–2.3 vectors (decode + MI/FINGERPRINT recompute + XOR-address + byte-exact
  round-trip), malformed corpus + 20k-input totality property, wrapper-transparency, builder round-trips.
  **Jazzer lane** (`stunCodecFuzz`, wired into `review.yaml`, 25M+ execs clean) with committed seed corpus.
- Benchmark numbers in `PERFORMANCE.md`; `.api` committed; ktlint/apiCheck/standing-directive greps green.

**The two Jazzer finds are fixed with committed fixtures** (directive #5): (1) `asText()` threw on
non-UTF-8 bytes → now returns `null` (must `catch (Throwable)`, not `Exception` — Kotlin/JS's TextDecoder
throws a raw JS error); (2) a short MESSAGE-INTEGRITY/FINGERPRINT declared length made the fixed-size
verify read past the datagram → both `verify*` now guard the attribute length.

### The cross-repo dependency (resolved)
STUN MI/FINGERPRINT needed HMAC-SHA1 + CRC-32, which `buffer-crypto`/`buffer` lacked. Added upstream in
**DitchOoM/buffer#288** (`HmacSha1Mac` + `hmacSha1`; `ReadBuffer.crc32`), **released as `buffer 6.10.0`**
(minor bump; on Maven Central). The catalog now pins the released `buffer = "6.10.0"` and the mavenLocal
dev-pin has been removed from the convention — a clean `:webrtc-stun:allTests` against Central passes on
all local lanes. The W0 discipline held: cross-repo primitive landed upstream + released *before* webrtc
consumes it (no unpublished-snapshot dependency on `main`).

**Release decision (resolved):** W1, W6, and W5 all merged with `skip-release` — no Central publish yet.
The first real `com.ditchoom:webrtc` release is still deferred (a `v0.0.1` tag exists from an earlier
release exercise). Trap (from W0): `gh pr edit --add-label skip-release` fails silently here — apply via
`gh api repos/DitchOoM/webrtc/issues/<n>/labels -f 'labels[]=skip-release'` and verify before merging.

### W1 adversarial-review gate (pre-merge)
A subagent review pass (the EXECUTION_PLAN §1 gate) found **no wire-correctness or crash defects** — it
independently re-verified the type bit-interleaving, XOR-address (v4/v6), the MI/FINGERPRINT
length-rewrite + constant-time compare, decode totality, and the retransmit schedule against RFC
8489/8656. Six hardening findings; five fixed before 0.0.1:
- exposed `attributesCoveredByMessageIntegrity()` — only attributes *before* MI are authenticated
  (RFC 8489 §14.5; FINGERPRINT is unkeyed, so a spliced post-MI attribute must not be trusted);
- builder now guards MI-before-FINGERPRINT ordering and supports truncated MI-SHA256 (16..32), with tests;
- `StunTransaction` hands out a fresh `request.slice()` per (re)transmit so a position-advancing driver
  can't exhaust it; non-default-policy + `Rc=1` schedule tests added.

**Deferred to a post-0.0.1 follow-up (tracked):** thread a `BufferFactory` seam through the
`decode`/`verify*`/builder hot paths (they hardwire `BufferFactory.Default`; additive/non-breaking to
add later) and add a `TrackingBufferFactory` no-leak harness (directive #6). The leak-harness half is
**blocked on the deferred W0 simulation-engine promotion** (`TrackingBufferFactory` isn't a published
artifact webrtc can consume yet) — so it lands with, or after, the §11.1 resolution.

---

## W0 (foundations) — skeleton landed, **CI green on the 3-runner matrix**

Repo is live and public: **https://github.com/DitchOoM/webrtc** (org `DitchOoM`, default branch `main`,
settings mirror socket, auto-delete-branch-on-merge on). The W0 skeleton + all CI fixes are merged to
`main` (`e43e637`). **Nothing published to Central yet** (by design — see next steps). The greenfield
repo has been bootstrapped from buffer/socket conventions. What exists:

- **Gradle**: root `settings.gradle.kts` (includes `build-logic` + 7 modules), root `build.gradle.kts`
  (detekt allprojects + aggregate tasks), `gradle.properties`, `gradle/libs.versions.toml`, the Gradle
  9.5.1 wrapper (copied from socket).
- **Build logic (the convention plugin)**: `build-logic/` is a standalone included build providing
  `webrtc.multiplatform-library`. It owns the KMP target matrix, JDK-21 toolchain, Android, ktlint,
  dokka, kover, binary-compat validation, Central publishing, signing, and version derivation
  (`Versioning.kt`, greenfield-safe: starts at 0.0.1 when Central has no metadata). Each module build
  file is just `plugins { id("webrtc.multiplatform-library") }` + its dependencies; POM prose is in
  `<module>/gradle.properties`.
- **Modules** (placeholder sources only): `webrtc`, `webrtc-sdp`, `webrtc-stun`, `webrtc-ice`,
  `webrtc-dtls`, `webrtc-sctp`, `webrtc-testsuite`. Each has a marker object + a house-style demo type
  (value-class ids, sealed exhaustive states) and a smoke test.
- **CI**: `review.yaml`, `merged.yaml` (label-driven release), reusable `build-linux` / `build-apple` /
  `validate-artifacts`, `publish-to-central` / `release` / `released` (Central Portal, copied from
  socket), `standing-directives.yaml` (No-array + seamed-entropy greps), `labels.yaml` + `labels.yml`,
  `dependabot.yml`.
- **Benchmarks**: kotlinx-benchmark wired into the convention (shared `src/commonBenchmark/kotlin`,
  JVM + Linux K/N, `main`/`quick` profiles); sample in `webrtc-stun`; tracked in `PERFORMANCE.md`.
- **Docs**: `README.md`, `CLAUDE.md`, `DESIGN_PRINCIPLES.md`, `TESTING.md` (unit→integration→interop
  strategy + per-wave test exit criteria), `PERFORMANCE.md`, `CHANGELOG.md`, `MODULE.md`, `docs/`.

## Verified vs. NOT yet verified

**Verified green on this Linux box** (`./gradlew`, Gradle 9.5.1, JDK 21, Android SDK present):
- `build-logic` convention plugin compiles + resolves; all 7 modules configure.
- `jvmTest` — all modules compile for JVM and every placeholder test passes.
- `apiDump` — all modules compile for **JVM + JS + wasmJs + Linux K/N**; committed `.api` files
  generated under `<module>/api/jvm/`. `apiCheck` passes against them.
- `ktlintCheck` passes on all sources. Standing-directive greps are clean.
- `:webrtc-stun:testAndroidHostTest` passes (new AGP KMP-library DSL host-test path works).
- Version derivation yields `0.0.1-SNAPSHOT` locally (greenfield fallback correct).

A real bug was caught + fixed during this: `@JvmInline` needs an explicit `import kotlin.jvm.JvmInline`
for the JS/Native targets (JVM auto-imports it) — `jvmTest` alone masked it; `apiDump` (all targets)
surfaced it.

**Confirmed green on CI (PR #3, three-runner matrix — the real proof):**
- `build-linux` (JVM/JS/WASM/Android/Linux K/N), `build-apple` (macOS/iOS K/N), `standing-directives`,
  and `validate` all pass. This closes the Apple + browser + Android lanes that couldn't run locally.
- CI produces **`maven-local-merged`** (~63 MB) every green run — the combined all-platform Maven repo.
  Download + test a consumer against it: `gh run download <run> -n maven-local-merged -D /tmp/webrtc-m2`
  then `cp -r /tmp/webrtc-m2/com ~/.m2/repository/`.

Three CI-only issues were found + fixed on the smoke PR (none in library code): (1) ktlint choked on
kotlinx-benchmark's *generated* source set (Gradle 9 implicit-dependency validation) → ktlint disabled
on benchmark sources; (2) `prePublishCheck` re-ran on CI where a single lane lacks the cross-platform
toolchain (macOS has no Chrome) → gated behind `-PskipPrePublishCheck`; (3) the Apple target matrix was
broader than `buffer-crypto` publishes (it omits `watchosArm64`) → **matched buffer-crypto's exact Apple
set** (restored the x64 tiers, dropped `watchosArm64`; the target matrix is now bounded by buffer-crypto,
not chosen freely). Earlier local find: `@JvmInline` needs an explicit `import kotlin.jvm.JvmInline` for
JS/Native (JVM auto-imports it).

The **full release pipeline is proven** end-to-end via a `flow=draft` dispatch: build → validate → GPG
sign → bundle → upload → **Central VALIDATED** → draft GitHub release. Two more fixes came out of it:
CI **caching** improved (`gradle/actions/setup-gradle` on both lanes + `~/.konan` cache on Linux —
build-linux 8→5 min, build-apple 11→4.8 min warm); and a **POM bug** (every POM shipped with no
`<description>` → Central rejected it) fixed — `providers.gradleProperty()` ignores *subproject*
`gradle.properties`, so `POM_NAME`/`POM_DESCRIPTION` must be read via `findProperty` (now fail-fast).
The draft `0.0.1` was **cancelled** (dropped from staging, draft release deleted) — the first real
Central release is deliberately deferred until W1 ships actual code, so `0.0.1` isn't a public placeholder.

Net: **W0 is complete** — CI green on the three-runner matrix, mavenLocal + all-platform signed-bundle
publish paths both proven. Org secrets (`GPG_KEY_CONTENTS`, `SIGNING_PASSWORD`, `MAVEN_CENTRAL_*`,
`RELEASE_PAT`) are confirmed wired to this repo (the draft's GPG import + Central upload succeeded).

## Immediate next steps — **W1 `webrtc-stun` is the active wave**

W1 is pure codec with zero seam dependency — buildable and testable today, no real UDP, no vnet.
Recommended path (RFC §7 + EXECUTION_PLAN W1 exit criteria):
1. **STUN message codec (RFC 8489)** as `buffer-codec` KSP schemas (`@ProtocolMessage`), not hand-written
   — header (type/length/magic-cookie/txid) + TLV attributes, decoded as *views* over the datagram
   buffer (RFC §6), never extracted to arrays. Add the `ksp` + `buffer-codec-processor` deps to
   `webrtc-stun` (already in the version catalog). Replace the placeholder `Stun.kt`.
2. **T0 floor**: round-trip + property tests + committed malformed-corpus + the **RFC 5769 sample
   vectors** (MESSAGE-INTEGRITY / FINGERPRINT) — an interop-grade corpus on day one. Parse-fail must be
   a typed reject, never a throw-through.
3. **Sans-io transaction machine**: `handle(event, now)` + `nextDeadline` retransmit schedule; seeded
   `Random` for transaction IDs from day one (standing directive #2).
4. **TURN message extensions (RFC 8656)** codec-only.
5. **Jazzer fuzz lane** (`jvmTest`, time-boxed) with a committed seed corpus; a parse-throughput
   benchmark in `PERFORMANCE.md` (the benchmark wiring is ready — replace the placeholder benchmark).
   Wrapper-transparency tests (works on `PooledBuffer`/`TrackedSlice`).

Deferred (not W1): commit per-module `config/detekt/baseline.xml` after a first `detektAll`; resolve
RFC §11.1 (simulation-engine home → recommend standalone `ditchoom-simulation`) before W2; the first
real Central release rides W1's merge (dispatch `merged.yaml -f flow=release`, or a PR whose label is
verified — see the release trap).

## Traps / notes

- Real socket UDP is **not** on the critical path until W7 interop; W1–W6 test against the in-memory
  vnet `DatagramChannel`, mirroring socket's `TimelineUdpChannel`.
- Apple lanes are compile-faithful on this Linux box; runtime-validate on the macOS runner and say so in
  the PR (the `V6_MAC_VALIDATION` convention).
- The standing-directive greps are live from day one — new production code must respect No-array +
  seamed-entropy or annotate the documented allowance.
- **Release trap (bit us once):** `merged.yaml` treats a merged PR that touched *code* files as
  `flow=release` and auto-publishes to Central. `gh pr edit --add-label skip-release` **fails silently**
  on this repo (deprecated Projects-classic GraphQL in `gh`), so the label doesn't apply and the merge
  publishes. PR #3's merge triggered a real release run; it was **cancelled before the publish job ran**
  (nothing shipped). Lessons: (a) prefer `gh workflow run merged.yaml -f flow=dry-run|release` (dispatch)
  over relying on merge+label; (b) if you must label, use the REST API:
  `gh api repos/DitchOoM/webrtc/issues/<n>/labels -f 'labels[]=skip-release'`; (c) verify the label is
  actually present (`gh api repos/.../issues/<n>/labels`) before merging a code PR.
- The Apple target matrix is **bounded by `buffer-crypto`** (webrtc-dtls depends on it): it omits
  `watchosArm64`. Do not add Apple targets the buffer deps don't publish, or resolution breaks on CI.
- **Per-module Gradle properties trap:** `providers.gradleProperty(name)` does NOT read a *subproject's*
  `gradle.properties` (only root / `-P` / user-home); use `findProperty(name)` for per-module values.
  This silently emptied every POM's `<description>` and Central rejected the deployment. The convention
  now reads `POM_NAME`/`POM_DESCRIPTION` via `findProperty` and **fails fast** if a module lacks
  `POM_DESCRIPTION`. Every new module needs a `gradle.properties` with `POM_NAME` + `POM_DESCRIPTION`.

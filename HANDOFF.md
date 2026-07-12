# HANDOFF

Live state of the current wave. A resumed session reads `RFC_KMP_WEBRTC.md` → `EXECUTION_PLAN.md` →
this file. Update it whenever you stop mid-wave.

## Where we are: W0 (foundations) — skeleton landed, **CI green on the 3-runner matrix**

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

Net: the EXECUTION_PLAN W0 exit criterion "CI green on the three-runner matrix" is **met**. The only
remaining W0 item is the first actual Central publish (`0.0.x`), which is deliberately deferred.

**NOT yet done:** the Central publish / release flow — needs the org signing + Central secrets wired to
this repo, and a *deliberate* release (see next steps + the label trap below).

## Immediate next steps

1. **Cut the first release, deliberately.** Confirm the org secrets (`GPG_KEY_CONTENTS`,
   `SIGNING_PASSWORD`, `MAVEN_CENTRAL_USERNAME`/`PASSWORD`, `RELEASE_PAT`) are wired to this repo, then
   dry-run then release via dispatch (NOT by merging a PR — see the label trap):
   `gh workflow run merged.yaml -R DitchOoM/webrtc -f flow=dry-run`, then `-f flow=release`.
2. Add committed `config/detekt/baseline.xml` per module once `detektAll` runs (currently referenced but
   absent — detekt tolerates a missing baseline, but commit real ones after first run).
3. Resolve RFC §11.1 (**simulation-engine home** — recommend standalone `ditchoom-simulation`) — this is
   the W0 cross-repo decision that unblocks W2 (vnet). The two upstream promotions (unconnected
   `DatagramChannel` seam into socket-core; TimelineInterpreter/vnet into the published sim home) are
   separate PRs against socket, released to Central *before* webrtc consumes them.
4. First substantive code wave is **W1 `webrtc-stun`** — pure codec, zero seam dependency, buildable and
   testable today without real UDP.

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

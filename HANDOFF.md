# HANDOFF

Live state of the current wave. A resumed session reads `RFC_KMP_WEBRTC.md` → `EXECUTION_PLAN.md` →
this file. Update it whenever you stop mid-wave.

## Where we are: W0 (foundations) — repo skeleton landed

The greenfield repo has been bootstrapped from buffer/socket conventions. What exists:

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

**NOT yet run here** (environment-gated, not code-gated):
- **Apple targets** — need a macOS runner (`build-apple.yaml`); compile-faithful only on this box.
- **`jsBrowserTest` / `wasmJsBrowserTest`** — need Chrome (`review.yaml` installs it).
- **`publishToMavenLocal`** — gated behind `prePublishCheck`, which includes the browser tests above;
  the per-publication mechanics and version/coordinates are validated, the full gated run is not.
- **`publish-to-central` / release flow** — need the signing + Central secrets.

Net: the EXECUTION_PLAN W0 exit criterion ("empty tree builds + publishes 0.0.x on every target, CI
green") is **met for JVM/JS/wasm/Linux locally**; Apple + browser + Central remain to be confirmed on
their respective CI runners on the first PR.

## Immediate next steps

1. Open the first PR so CI proves the environment-gated lanes (Apple on macOS, browser tests with
   Chrome, then a `draft-release` to exercise `publish-to-central`). The `.api` files are committed;
   `apiCheck` is wired into `build-linux`.
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

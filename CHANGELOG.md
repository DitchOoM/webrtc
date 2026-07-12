# Changelog

All notable changes to `com.ditchoom:webrtc` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are auto-derived from Maven Central
metadata + PR-label bumps (`major` / `minor`, else patch).

## [Unreleased]

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

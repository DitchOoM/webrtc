# Execution plan — `com.ditchoom:webrtc`

**Companion to:** [`RFC_KMP_WEBRTC.md`](./RFC_KMP_WEBRTC.md) (the *what* and *why*). This file is
the *how*: sequencing, orchestration, exit criteria, and the working conventions each wave runs
under. Update the status column as waves land; this file plays the role `TODO.md` + `HANDOFF.md`
play in the socket repo.

---

## 0. Decision log

| Date | Decision | Rationale |
|---|---|---|
| 2026-07-11 | **Own stack, not libwebrtc**, on every non-browser target | libwebrtc is a framework (owns threads/timers/RNG/sockets) — no seam for deterministic replay, copies at every SDK boundary, Android/iOS only. Quiche worked because it is sans-io; libwebrtc is its opposite. See RFC §1. |
| 2026-07-11 | Data channels first, media (RTP/SRTP) Phase 2 | No codec/hardware deps; slots into `StreamMux` immediately. RFC §2. |
| 2026-07-11 | Signaling is an injected seam, never implemented | Correct layering + deterministic offer/answer tests. RFC §2. |
| 2026-07-11 | Every protocol core sans-io + caller-clocked | The quiche `Instant::now()` lesson, inverted — the whole stack must run under `runTest` virtual time. RFC §5.1. |
| 2026-07-11 | `webrtc-libwebrtc` bootstrap backend **parked, not planned** | Legitimate only if time-to-first-ship dominates; three behaviors to reconcile and throwaway wrapper code otherwise. Revisit only with an explicit deadline driver. |
| 2026-07-13 | **Codec track complete; transport track gated on a deterministic UDP `commonMain`** | W1/W6-sdp/W5-sctp (the pure codecs) are merged. W2+ needs an unconnected, deterministic UDP `DatagramChannel` in `commonMain`, runnable under `runTest` — W0's open socket promotion, being built in the socket sibling. |
| 2026-07-15 | **Transport prerequisites landed in socket; W3 is next (dev-unblocked, merge-gated)** | socket merged the `socket-udp` UDP `commonMain` seam (PR #239) + the deterministic vnet/sim harness (#225). So **W2 is a socket deliverable, not a webrtc wave** — webrtc consumes it. Develop W3 (`webrtc-ice`) now against a socket `publishToMavenLocal`; **do not merge webrtc transport code until `socket-udp` is on Central** (it is not — latest socket 3.10.1 predates #239, whose deploy failed). |
| resolved 2026-07-15 | RFC §11.1 — simulation-engine home → **lives in the socket sibling** (the #225 deterministic-simulation harness), not a standalone `ditchoom-simulation` | webrtc consumes socket's vnet; no separate sim module needed |
| *open* | RFC §11.2 — SCTP subset scope (recommend: dcSCTP-style, no multihoming/interleaving) | must resolve before W5 |
| *open* | RFC §11.3 — DTLS 1.2-first interop vs 1.3 (recommend: both via BoringSSL config, interop-test 1.2) | must resolve before W4 |
| *open* | RFC §11.4 — mDNS (recommend: resolve-only in W3, responder deferred) | must resolve before W3 |

## 1. Orchestration model

How the work actually gets driven, based on what has worked in buffer/socket:

- **One wave = one focused Claude Code session (or a small chain of them) = one PR.** Each wave
  below is sized to be completable with full context of its own scope. The sim RFC's
  "W1–W7 in one PR" worked because the waves shared one engine; here the waves cross module
  boundaries, so **PR-per-wave** with the label-driven version bump (`minor` for each new module).
- **Session handoff discipline.** Every session that stops mid-wave writes/updates a
  `HANDOFF.md` at repo root: what landed, what's verified on which platforms, exact next steps,
  known traps. Sessions start by reading `RFC_KMP_WEBRTC.md` → this file → `HANDOFF.md`.
- **Cross-repo pre-work lands upstream first.** W0's two promotions are PRs against
  **socket** (and possibly a new repo), released to Maven Central *before* webrtc consumes them —
  the webrtc repo never depends on unpublished sibling snapshots (the validate-artifacts lesson:
  every consumer-facing artifact goes through the release loop).
- **Parallelism is between waves, not inside protocol cores.** W2 (vnet), W4 (DTLS backends), and
  W1 (STUN) are mutually independent once W0 lands — they can run as parallel sessions/worktrees.
  Never parallelize *within* a state-machine module: an ICE checklist written by four agents is
  worse than one written by one. Fan out subagents only for mechanical breadth: platform-actual
  sweeps, test-migration sweeps, `.api` file generation, doc passes, and adversarial review of a
  finished wave.
- **Adversarial review gate per wave.** Before a wave's PR merges: a review pass (code-review at
  high effort or a multi-agent review) specifically hunting (a) `ByteArray` in prod source sets,
  (b) unseamed `Clock.System`/`Random.Default`/`Dispatchers.*` in cores, (c) buffer
  alloc/free imbalance, (d) stringly-typed errors. These four are the project's standing
  directives; automated greps for (a)/(b) belong in CI from W0.
- **Platform validation lanes.** Development happens on this Linux box (JVM, Linux x64/arm64, JS
  lanes verified locally). Apple lanes are compile-faithful locally and **runtime-validated on the
  macOS runner before merge** — the `V6_MAC_VALIDATION.md` convention: the PR description lists
  exactly which lanes ran where. Android instrumented runs on the emulator matrix job.
- **Green-throughout rule** (from TESTING_STRATEGY §6): every wave lands with its tests passing on
  all lanes before the next wave starts; no "fix it in the next wave" debt on the main branch.
- **Fixtures are append-only.** Every field bug, fuzz find, or interop failure becomes a committed
  timeline fixture in the same PR that fixes it. The corpus only grows.

## 2. Wave plan

Legend: **Exit** = merge criteria. All waves also require: ktlint/detekt clean, `.api` files
checked in, CHANGELOG entry, standing-directive greps green.

> **Status snapshot (2026-07-15):** the pure-codec / socket-free track is **complete** — W1 (`webrtc-stun`),
> W6-partial (`webrtc-sdp`), and W5-codec-floor (`webrtc-sctp`) are all merged to `main` (all
> `skip-release`; nothing on Central yet). The transport prerequisites now **exist in the socket
> sibling**: the UDP `DatagramChannel` `commonMain` seam (`socket-udp`, socket PR #239, 2026-07-15) and
> the deterministic vnet/sim harness (socket #225). **So W2 (vnet) is a socket deliverable, not a webrtc
> wave** — webrtc consumes it. **Dev on the transport track (W3 next) is unblocked** against a socket
> `publishToMavenLocal` build; **but `socket-udp` is not yet on Central** (latest published socket is
> 3.10.1, which predates #239; #239's deploy failed), so webrtc transport code must **not merge to
> `main`** until socket lands a green `socket-udp` release. §11.1 (sim home) is answered (lives in
> socket); resolve §11.4 before W3 and §11.3 before W4. See `HANDOFF.md`.

### W0 — Foundations (cross-repo) · status: ✅ merged
Two upstream PRs + repo bootstrap. **Resolves RFC §11.1 first.**
1. **socket PR:** promote an unconnected `DatagramChannel` seam (per-datagram source address on
   receive, arbitrary destination on send — generalizing `UdpChannel`'s server-side `dest`/`PathKey`)
   into socket-core with actuals on all platforms; keep `UdpChannel` as the connected view.
2. **simulation PR:** promote `TimelineInterpreter`, `TestClock` bridge, fixture→Kotlin codegen,
   ddmin shrinker, `TrackingBufferFactory` into the published home decided by §11.1.
3. **webrtc repo bootstrap:** `git init`; gradle skeleton cloned from socket conventions (targets,
   JDK 21 toolchain, ktlint/detekt baseline, binary-compat validator, kover, dokka, workflows:
   `review.yaml`, `merged.yaml`, arch-matched harness matrix stub); root `CLAUDE.md` carrying the
   No-ByteArray rule **plus** the no-unseamed-clock/random/dispatcher rule; CI greps for both.
- **Exit:** both upstream artifacts on Central; empty webrtc module tree builds and publishes a
  0.0.x to mavenLocal on every target; CI green on the three-runner matrix.

### W1 — `webrtc-stun` · status: ✅ merged (PR #4) · *parallel-ok with W2, W4 after W0*
STUN codec (RFC 8489) as buffer-codec KSP schemas; sans-io transaction machine (retransmit
schedule as `nextDeadline`); MESSAGE-INTEGRITY/FINGERPRINT verified in place over slices; TURN
message extensions (RFC 8656) codec-only.
- **Exit:** T0 round-trip + malformed-corpus floor green on all platforms; Jazzer lane wired and
  time-boxed in CI with committed seed corpus; parse throughput benchmark in `PERFORMANCE.md`;
  wrapper-transparency tests pass.

### W2 — vnet · status: ✅ **delivered in the socket sibling (not a webrtc wave)** — `socket-udp` UDP seam (socket PR #239) + deterministic vnet/sim harness (socket #225); webrtc consumes it · *parallel-ok with W1, W4*
In the simulation module: NAT models (full-cone/address-restricted/port-restricted/symmetric,
mapping lifetimes, hairpinning), virtual TURN server, impairment pipe (loss/reorder/dup/delay,
seeded), topology-as-data builders. Implements the W0 `DatagramChannel` seam.
- **Exit:** NAT model property tests (each NAT type provably filters per its definition);
  a two-peer echo over each NAT topology runs under `runTest` virtual time on all platforms.

### W3 — `webrtc-ice` · status: ☐ **NEXT — dev-unblocked (consume socket `socket-udp` + vnet); merge gated on `socket-udp` reaching Central** · *needs W1 (done) + W2 (socket, done); resolves §11.4 first*
First wire socket into webrtc's `gradle/libs.versions.toml` (no socket entry yet) — dev against a socket
`publishToMavenLocal` build, flip the pin to the released version before merge — and prove the seam from
webrtc `commonTest` (two-peer datagram echo over the vnet under `runTest`) before the ICE core.
Sans-io agent core: candidate pairing, checklist scheduling, triggered checks, nomination,
keepalive/consent (RFC 7675), restart. Gathering drivers: host + srflx (STUN) + relay (TURN
client) + mDNS resolve-only, over `DatagramChannel`/`NetworkMonitor`. Trickle (RFC 8838) via the
signaling seam. Seeded `Random` for tie-breaker/ufrag/pwd/foundations from day one.
- **Exit:** canonical fixtures green under virtual time on all platforms — including
  dual-symmetric-NAT→relay, candidate-flap mid-check, `NetworkId` change→restart; timeline fuzz
  smoke lane (pinned seeds) + JVM deep-run lane wired with shrinker; ICE state invariants in the
  fuzz invariant set; typed `IceFailureReason` surface complete.

### W4 — `webrtc-dtls` · status: ☐ · *parallel-ok with W1–W3; resolves §11.3 first*
BoringSSL backends reusing quiche build infra: cinterop (Apple/Linux), JNI (Android), FFM (JVM,
multi-release JAR). Memory-BIO driver, caller-clocked (`DTLSv1_get_timeout` →
`nextDeadline`), native handles via `toNativeData()`, wrapper alloc/free tracked. DTLS-SRTP key
exporter (unused until P2, but the surface is cheap now). Certificate/fingerprint generation +
verification (a=fingerprint model, not CA validation).
- **Exit:** handshake between two of our stacks over the vnet completes under virtual time
  (RNG-drift bounds asserted, the Tier-B discipline); retransmission fixture (dropped flight)
  green; wrapper-free invariant in fuzz set; Apple/Android lanes runtime-validated on runners.

### W5 — `webrtc-sctp` + DCEP + DataChannel · status: ◑ codec floor merged (PR #6); association FSM + DataChannel remain · *needs W3+W4; resolves §11.2 first*
The **chunk codec + DCEP messages** (pure, sans-io, commonMain) are done and merged. The **SCTP
association state machine** (4-way handshake, TSN/SACK/RTO, congestion control, fragmentation/
reassembly over `StreamProcessor`), RFC 3758 partial-reliability, and the `DataChannel` implementing
buffer-flow `StreamMux` remain — they need DTLS (W4) + the transport seam.
Pure-Kotlin sans-io SCTP subset over DTLS: chunks as buffer-codec schemas, TSN/SACK, RTO calc,
congestion control, fragmentation/reassembly over `StreamProcessor`, orderly+abort shutdown. DCEP
(RFC 8832) open/ack. `DataChannel` implementing buffer-flow `StreamMux` (+ `ByteStreamMux` when it
lands); partial-reliability (RFC 3758) for maxRetransmits/maxPacketLifeTime.
- **Exit:** end-to-end deterministic fixture — two full stacks (ICE+DTLS+SCTP) over
  dual-NAT vnet exchange ordered/unordered/lossy-channel messages under virtual time, all
  platforms; SCTP invariants (no intra-stream reorder, no unacked-drop, DCEP converges) in fuzz
  set; loop-until-dry fuzz campaign run once with all finds fixed or filed.

### W6 — `webrtc` root: JSEP + PeerConnection + browser actuals · status: ◑ SDP codec + JSEP machine merged (PR #5); PeerConnection + browser actuals remain · *needs W5*
`webrtc-sdp` (hand-written text codec, T0 + fuzz) and the **sans-io JSEP offer/answer machine** are
done and merged. The **`PeerConnection` session API**, the browser/wasmJs `peerConnectionSupport()`
`RTCPeerConnection` delegation, and the `SocketException`-hierarchy error sweep remain — they need the
ICE/DTLS/SCTP stack (and thus the transport seam) beneath them.
`webrtc-sdp` parser/writer (hand-written text codec, T0 rigor + fuzz); JSEP offer/answer state
machine (sans-io); `PeerConnection` session API (SessionTransport `use{}` convention,
capability-by-type); browser/wasmJs `peerConnectionSupport()` delegating to `RTCPeerConnection`;
error sweep — everything maps into the `SocketException` hierarchy with exhaustive sealed reasons.
- **Exit:** full API round-trip fixture (signaling seam scripted) green on all platforms; browser
  target compiles + delegation unit-tested under Karma; `.api` surface reviewed as *the* public
  API commitment (this is the wave where API mistakes become expensive — extra review pass).

### W7 — Harness, interop, testsuite publish · status: ☐ · *needs W6; container work parallel-ok earlier*
Extend the socket-style compose harness: `coturn`, NAT-profile containers (iptables), netem
profiles, controller `/describe` entries. Interop lane: Pion echo peer container + headless
Chrome (Karma) driving real `RTCPeerConnection` against our JVM stack. `webrtc-testsuite`
published (`withWebRtcHarness { natType(); relayOnly(); impaired() }`) + consumer-smoke project;
testsuite wired into release + validate-artifacts from its first version.
- **Exit:** interop green: our stack ⇄ Pion and our stack ⇄ Chrome establish + exchange data
  channel messages in CI on the arch-matched matrix; consumer-smoke passes from a clean checkout;
  first public release cut.

### P2 — Media transport · status: ☐ · *after W6; separate RFC addendum before starting*
`webrtc-rtp` (codec module), `webrtc-srtp` (in-place AEAD, tag tailroom API upstream in buffer),
BUNDLE/rtcp-mux, media surface as `is`-checkable capability. Codec adapters live outside the
library, permanently.

## 3. Dependency graph

```
W0 ──► W1 (stun) ──► W3 (ice) ──► W5 (sctp+dc) ──► W6 (pc+jsep) ──► W7 (harness/interop)
  ├──► W2 (vnet) ──┘               ▲                                   ▲
  └──► W4 (dtls) ──────────────────┘             (container builds can start any time) 
```

Max useful parallel sessions after W0: three (W1, W2, W4). W3 is the first integration point and
should be a single session chain.

## 4. Standing directives (every session, every wave)

1. No `ByteArray` in `*Main/` — `@Suppress("NoByteArrayInProd")` + named API surface at genuine
   platform edges only.
2. No `Clock.System` / `Random.Default` / hardwired `Dispatchers.*` inside protocol cores —
   constructor-injected seams with production defaults.
3. Errors typed, never strings-as-discriminants.
4. Assert observable state + watchdog, never wall-clock budgets.
5. Every bug fix ships with its deterministic fixture in the same PR.
6. Buffers: factory-injected, pooled in hot paths, `use{}`/scoped lifecycle,
   `TrackingBufferFactory` in every test harness.
7. PR description states which platform lanes were runtime-validated vs compile-faithful.

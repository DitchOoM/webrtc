# HANDOFF

Live state of the current wave. A resumed session reads `RFC_KMP_WEBRTC.md` → `EXECUTION_PLAN.md` →
this file. Update it whenever you stop mid-wave.

---

## START HERE — W4b + W7 Phase 3 (fresh session). Branch `w4b-dtls-kotlin` off `main` @ `1518e8a`.

### ⇢ LIVE PROGRESS (2026-07-20, session 3) — task #5 THE FLIP done + differential-tested; whole project green

**Three commits on `w4b-dtls-kotlin` (`753747f`, `2212a21`, `fc338e8`). `./gradlew build` SUCCESSFUL — all
modules, all host targets. The pure-Kotlin DTLS engine is now the ONLY DTLS on every non-browser target.**

- **Task #5 (the flip) DONE ✅ (`753747f`).** `DtlsEngine` is now a concrete `commonMain` class delegating to
  `Dtls12Handshake`, running on **JVM/Android/Apple/Linux** over buffer-crypto with **no native dependency**.
  Deleted the 6 `expect`/`actual` `DtlsEngine.*.kt` + the `DtlsBackend` expect/actuals + the commonTest
  link-smoke. The cert identity is hoisted to `DtlsEngine` (fingerprint readable pre-role) and threaded into
  the handshake; added `beginClose` (close_notify). **BoringSSL demoted out of the published klib**: it moved
  to `linuxTest` as `BoringSslDtlsEngine` (a plain class) and the `boringsslssl` cinterop is now scoped to the
  **test** compilation (`build.gradle.kts`: `compilations.getByName("test").cinterops...`). `.api` unchanged
  (same public surface). **JVM/Android/Apple now have real DTLS** — a capability unlock (W7 interop could now
  run a JVM peer, not only linuxX64).
- **Differential testing DONE ✅ (the owner's ask — close the self-loopback gap).**
  - **linuxTest = our engine ⇄ BoringSSL oracle** (`DtlsHandshakeTest`/`DtlsRetransmissionTest` rewritten,
    1.2-pinned): both roles, app data both ways, malformed-drop, timer retransmission, allocation bound. A
    `DtlsConductor` + `DtlsEndpoint` adapter (`DifferentialDriver.kt`) drives either engine type. 9/9 green.
  - **jvmTest = our engine ⇄ `openssl s_client -dtls1_2`** (`DtlsOpensslDifferentialJvmTest`, `2212a21`): our
    server over a **real loopback UDP socket** vs OpenSSL 3.0.13 (a SECOND independent stack), full handshake +
    both app-data directions + fingerprint cross-checked against the actual cert file. Skips if openssl absent.
  - **⭐ It immediately caught a real interop bug the loopback structurally couldn't:** our ClientHello/ServerHello
    omitted the **RFC 5746 `renegotiation_info`** extension → OpenSSL aborted (`unsafe legacy renegotiation
    disabled`). BoringSSL tolerated it; OpenSSL (and browsers) enforce it. **Fixed** (advertise empty in
    ClientHello; echo in ServerHello when the peer signals support via the extension or the SCSV) — ships with
    its fixture (directive #5).
  - **SRTP-exporter OUTPUT differential vs BoringSSL is still deferred to #7** (the `bd_export_srtp_keys`
    wrapper exists but our engine has no exporter yet — 1.2 uses the TLS-1.2 PRF exporter).
- **A latent pre-existing failure fixed (`fc338e8`):** the engine-crypto **commonTests** (`EcdheKeyExchangeTest`,
  `Dtls12RecordProtectionTest`, `Dtls12HandshakeTest`) construct buffer-crypto's **blocking** primitives, which
  don't exist on js/wasmJs (async WebCrypto) — they'd never been run under full-build `allTests` on browsers.
  They now gate on `engineCryptoAvailable()` (`commonTest/TestEngineCrypto.kt`) and no-op on browser targets
  (the engine is never constructed there). `:webrtc-dtls:allTests` green on jvm/android/linuxX64/js{Node,Browser}/
  wasmJs{Node,Browser}.
- **NEXT = task #6 (DTLS 1.3) then #7.** #7 = **(a)** rename the webrtc-root `BoringSslDtls` driver — it's now a
  **misnomer** (drives the pure-Kotlin engine, not BoringSSL) and its class doc still says "throws
  BackendUnavailable on a target with no backend" (stale — JVM/Apple now work); **(b)** PeerConnection interop
  (Chrome/Firefox/Pion) as the real acceptance bar; **(c)** the SRTP-exporter output differential vs BoringSSL.
- **Traps for the fresh session:** the K/Wasm `compileTestDevelopmentExecutableKotlinWasmJs` throws a
  **flaky "Internal compiler error"** (hit `:webrtc-dtls` then `:webrtc-sctp` on consecutive `build` runs, both
  passed on retry) — it is a toolchain flake, **re-run `build` before diagnosing**. Our client still stubs
  inbound HelloVerifyRequest (server skips HVR); PMTU outbound fragmentation, anti-replay window still deferred
  to interop. Our engine is **DTLS 1.2 only** until #6 — the BoringSSL/openssl differentials are 1.2-pinned.

### ⇢ LIVE PROGRESS (2026-07-20, session 2) — W4b crypto/wire foundation done + tested; W7 Phase 3 landed

**Two commits on `w4b-dtls-kotlin` (after the buffer bump). All `commonMain`/`commonTest`, JVM-verified,
build green. The pure-Kotlin DTLS internals are built as `internal` in `commonMain` ALONGSIDE the intact
`expect`/`actual` `DtlsEngine` — the risky `expect`→class flip happens only once a full handshake passes.**

- **W4b tasks 1–3 DONE + tested (JVM):**
  - **Wire codec** (`webrtc-dtls/commonMain/.../wire/`): `DtlsWire` (helpers + `ContentType`/`ProtocolVersion`/
    `HandshakeType`), `DtlsRecord` (13B header, coalesced-record walk, `RecordSequence`), `DtlsHandshakeMessage`
    (12B header; **`transcriptInto` emits the normalized full-header form** — the spike gotcha), `HandshakeReassembler`
    (in-`message_seq`-order delivery + reorder window + DoS bound), `TlsExtension`, `HandshakeBodies`
    (ClientHello/HelloVerifyRequest/ServerHello/Certificate/ServerKeyExchange/ClientKeyExchange/CertificateVerify).
    Test `DtlsWireTest` (round-trips + T0 rejects).
  - **TLS 1.2 key schedule** (`crypto/Tls12KeySchedule`): P_SHA256 PRF, ext-master-secret, key block, verify_data —
    **pinned byte-exact to the canonical TLS 1.2 PRF-SHA256 KAT** (`Tls12KeyScheduleTest`).
  - **Record protection** (`crypto/Dtls12RecordProtection`): AES-128-GCM explicit-nonce (12B nonce=4B IV‖8B explicit),
    13B DTLS AAD, `explicit‖ct‖tag` framing — seal⇄open + tamper/wrong-seq drop (`Dtls12RecordProtectionTest`).
  - **Self-signed cert** (`crypto/Der` + `crypto/SelfSignedCertificate`): hand-written TBSCertificate DER, ECDSA-P256,
    SHA-256 fingerprint — validated against JVM `java.security` (`SelfSignedCertificateJvmTest`: parses + `verify(pubKey)`
    + fingerprint==SHA256(DER)). Same class of proof as the openssl spike.
- **THE ONE ARCHITECTURE DECISION (see scratchpad `w4b-decisions.md`, reproduce it if resuming fresh):** buffer-crypto's
  crypto is all **blocking** on the 4 targets that actually run the engine (JVM/Android/Apple/Linux — browsers delegate),
  **except `deriveTlsPremasterSecret` (raw ECDH) which is `suspend`-only**. So the engine stays **synchronous** (preserves
  the sans-io contract + existing fixtures) and that ONE primitive gets a single `internal expect fun rawEcdhSecret(...)`
  blocking bridge (`runBlocking` on jvm/android/linux/apple; throw on js/wasm) — the *only* per-platform seam; all engine
  LOGIC stays commonMain. NOT YET BUILT (needs `kotlinx-coroutines-core` added to those source sets) — it's the first step of task #4.
- **Task #4 DONE ✅ (commit `a9adce6`) — the pure-Kotlin DTLS 1.2 handshake completes end-to-end on JVM.** Two engines do a
  full **mutually-authenticated** handshake (RFC 8827: both send Certificate+CertificateVerify; server sends
  CertificateRequest) over an in-memory pipe under virtual time, then exchange encrypted app data. `handshake/Dtls12Handshake`
  (sans-io FSM), `handshake/TranscriptHash`, `crypto/EcdheKeyExchange`+`crypto/RawEcdh.{6 targets}` (the ONE per-platform
  seam — `deriveTlsPremasterSecret` is suspend-only → `runBlocking` bridge; js/wasm throw), `crypto/DerReader` (X.509 SPKI
  extractor). `DtlsConfig` gained an injected `random` seam (apiDump'd). Tests `Dtls12HandshakeTest`, `EcdheKeyExchangeTest`.
  **Traps that cost debugging (carry in):** WebRTC needs MUTUAL auth or the server has no peer cert; EMS `session_hash` is
  computed BEFORE appending CertificateVerify; `onDatagram` must NOT short-circuit on `Established` (only Failed/Closed) or
  post-handshake app data is dropped. **Deferred to interop (#7):** client HelloVerifyRequest handling (server skips HVR),
  PMTU outbound fragmentation, anti-replay window, a retransmit-under-loss commonTest.
- **NEXT = task #5, the flip:** make `DtlsEngine` a concrete `commonMain` class delegating to `Dtls12Handshake` (+ later
  `Dtls13Handshake`); delete the 6 `expect`/`actual` `DtlsEngine.*.kt`; move the BoringSSL cinterop + native engine to
  **`linuxTest`** as a differential oracle (out of the published klib) — edit `webrtc-dtls/build.gradle.kts` to scope the
  cinterop to the test compilation; keep the existing `linuxTest` `DtlsHandshakeTest`/`DtlsRetransmissionTest` as the oracle.
  Best done fresh (structural, touches the public engine + build). THEN #6 DTLS 1.3; #7 PeerConnection wiring + interop +
  SRTP-exporter differential.
- **⚠️ COVERAGE GAP — make differential testing a first-class goal of the fresh session (owner asked, 2026-07-20).** The
  primitives ARE independently validated (PRF vs canonical KAT; cert vs JVM `java.security`; buffer-crypto Wycheproof-vetted),
  BUT the handshake is only a **self-loopback** (our client ⇄ our server) — a *consistent* bug on both sides passes it. Close
  the gap, ranked by value/effort: **(1)** openssl differential — our engine ⇄ `openssl s_server -dtls1_2` over a local UDP
  socket in `jvmTest` (openssl 3.0.13 is on the box; doable now, no flip needed; may need
  `-cipher ECDHE-ECDSA-AES128-GCM-SHA256` + `-verify` for our client cert; 1.3 interop wants newer openssl). **(2)** the flip
  (#5) turns the existing `linuxTest` `DtlsHandshakeTest` into an **our-engine ⇄ BoringSSL** differential — the oracle W4b was
  designed around. **(3)** SRTP-exporter OUTPUT differential vs BoringSSL (the spike left this reachable-but-unchecked).
  **(4)** robustness in-suite: retransmit-under-loss, a fragmented-flight test, wire-parser Jazzer fuzz (mirror SCTP/STUN),
  replay/malformed rejects, the HelloVerifyRequest path. **(5)** #7 interop (Chrome/Firefox/Pion) = the real acceptance bar.

**W7 Phase 3 DONE (parallel, same 2 commits):** `webrtc-testsuite` filled — `withWebRtcHarness { natType(); relayOnly();
impaired() }` DSL + typed config (`NatType`/`NetworkImpairment`/`HarnessManifest`) + jvmMain `HarnessController` (L2
naming-parity bridge) + a clean-checkout **consumer-smoke** (`.ci/consumer-smoke/`, passes vs `publishToMavenLocal`). All
`:webrtc-testsuite` gates green (10/10 tests JVM/Android/linuxX64/js/wasm; `.api` dumped). **Design note to weigh:** the
vnet/NAT/STUN/TURN sim is `internal` to `webrtc-ice/commonTest`, unusable from a *published* commonMain module, so it was
**ported into `webrtc-testsuite/commonMain` (internal)** — a 2nd copy (follows the `webrtc/commonTest/TestNet.kt` precedent +
RFC §7 "vnet is a testsuite deliverable"). **Do NOT lift `webrtc-ice`'s copy to production-public** (pollutes a prod module's
ABI with a test sim) and the naive dedup (`webrtc-ice` test → `webrtc-testsuite`) is a **project cycle** (`webrtc-testsuite →
:webrtc → :webrtc-ice`). True DRY would need a dedicated shared `webrtc-testkit` module — deferred; keep the 2 copies for now.
Deferred by W7: wiring consumer-smoke into `review.yaml`, asymmetric per-peer NAT, CHANGELOG.

---

**W4b (pure-Kotlin DTLS 1.3 over buffer-crypto) is now a GO — the earlier "do not start W4b, pending
spikes" guidance below is STALE.** As of 2026-07-20:

- **The 3 de-risking spikes were RUN and are ALL GREEN** (`~/git/cinterop-issues/09-dtls-over-buffer-crypto-SPIKE-RESULTS.md`):
  key schedule/exporter 26/26 byte-exact vs RFC 8448; self-signed ECDSA-P256 cert openssl-verifies; a **live
  DTLS 1.2 handshake vs `openssl s_server` + app data on the wire**. The crypto risk is retired. Full plan +
  primitive audit: `08-dtls-over-buffer-crypto.md` + `W4B-DTLS-SPIKE-PLAN.md` (same dir).
- **buffer 6.16.0 (on Maven Central) ships every prerequisite:** AES-ECB single block (`buffer#301`, DTLS 1.3
  record-number enc), **`deriveTlsPremasterSecret`** raw (EC)DHE secret (`#302`, the load-bearing ECDHE
  primitive — gates BOTH versions), public `exportSpki()`/`exportEncoded()` (cert SPKI). **DONE this session:**
  webrtc bumped `6.11.0`→`6.16.0` (commit `6d0c0ba` on `w4b-dtls-kotlin`); compiles clean JVM+LinuxX64 all modules.

**Two decisions made this session (owner-confirmed):**
1. **`DtlsEngine` becomes a single pure-Kotlin `commonMain` implementation on ALL targets** (today it's
   `expect`/`actual` with `BackendUnavailable` off-Linux). **BoringSSL-native is demoted to a `linuxTest`
   differential oracle** — remove it from production. This retires the one native dep + the cinterop/dup-symbol
   hazard and lights up JVM/Android/Apple.
2. **Build the W4b DTLS 1.2 core AND W7 Phase 3 (`webrtc-testsuite`) in parallel** — they don't overlap.

**W4b build order:** (1) ✅ buffer bump. (2) Refactor `webrtc-dtls`: sans-io `DtlsEngine` → `commonMain` core;
add an **injected `Random` seam to `DtlsConfig`** (ECDHE ephemerals / ClientHello.random — `cryptoRandom` isn't
seedable, the Tier-B residue W4 accepts). Reuse the existing sans-io interface + W4 fixtures
(`DtlsRetransmissionTest`, the linuxX64 end-to-end handshake) — the BoringSSL fixture becomes the oracle.
(3) **DTLS 1.2 FIRST** (spike-proven on the wire, lowest risk): record layer, handshake FSM (ClientHello→…→
Finished), ECDHE via `deriveTlsPremasterSecret`, AES-128-GCM (`sealWithNonceBlocking`/`openWithNonceBlocking`),
self-signed cert (`exportSpki` + a ~40–150-LOC TBSCertificate DER template — buffer-crypto has no X.509
builder), inbound fragment reassembly. (4) **DTLS 1.3**: key schedule (RFC 8446/9147 `HKDF-Expand-Label` over
`Hkdf.extractInto`/`expandInto`), record-number encryption via AES-ECB. (5) Wire into `PeerConnection`; run the
interop harness with a **JVM/Kotlin peer ⇄ Chrome/Firefox/Pion** as conformance (BoringSSL stays the oracle).

**Protocol gotchas the spikes cost real debugging on (carry these in):** the DTLS Finished/PRF transcript
hashes the **FULL 12-byte DTLS handshake header** (message_seq + fragment fields, normalized to offset=0/
length=full), NOT the TLS 4-byte header. Explicit-nonce AEAD maps 1:1 to TLS GCM (12-byte nonce = 4-byte
write_IV ‖ 8-byte explicit; 13-byte TLS-1.2 AAD; bare `ciphertext‖tag`). ECDSA is DER-native (drops into the
cert BIT STRING / wire sigs with zero conversion). `Salt.None` = RFC 5869 zero-block. Inbound handshake
fragmentation is real (reassemble); outbound can stay unfragmented for a first cut (PMTU frag later).
buffer-crypto APIs (all verified present): `Hkdf.extractInto`/`expandInto`, `Sha256Digest`, `HmacSha256Mac`,
`deriveTlsPremasterSecret`, `KeyAgreementCurve.P256`, ECDSA `signBlocking`/`verifyBlocking` (Der),
`CryptoCapabilities.aesEcb`, `exportSpki`/`exportEncoded`, `cryptoRandom`.

**Also open (not W4b):** **PR #21** (`w7-browser-ci-tuning`, off `main`) — Node 24 slim browser base + gha
layer cache + build-then-up ordering fix; `skip-release`; **open, awaiting CI green + merge** (its `l2-browser`
jobs are the first real exercise of the gha cache). **W7 Phase 3:** `webrtc-testsuite` is still a 9-line
placeholder — build `withWebRtcHarness { natType(); relayOnly(); impaired() }` + a clean-checkout
consumer-smoke; decouple the first Central release from interop-green.

**Release posture:** nothing mechanical blocks a Central `0.0.1` (pipeline+validate green). The gates are
product: the DTLS platform gap (W4b closes it) + W7 Phase 3. Owner chose **Path B** — land cross-platform DTLS
+ Phase 3, THEN cut a broad `0.0.1`.

---

## Where we are: **W7 Phase 2(b) — headless-browser interop (Chrome + Firefox) + wasmJs delegation — BUILT + runtime-validated on this box (x64). Branch off `main` @ `6838258` (Phase 2(a) / PR #18 merged). Our native `linuxX64` offerer establishes a full WebRTC data channel against real **headless Chrome** (Chromium libwebrtc) AND real **headless Firefox** (fully independent NSS/nICEr/usrsctp stack), both via Playwright — real ICE hole-punch → real BoringSSL **DTLS 1.3** (production default) → SCTP → bidirectional ping/pong — across a port-restricted NAT. `chrome-interop` + `firefox-interop` scenarios PASS (offerer rc=0, answerer rc=0). The last W6 browser gap is closed: **wasmJs `peerConnectionSupport()` delegation is real** (was `NotImplementedError`) and passes in a real headless Chrome (`wasmJsBrowserTest`). Full matrix now **9/9 native lanes** green (a stdin-drain harness bug fixed). NEXT: Phase 3 (testsuite publish).**

### Phase 2(b) landed (this session) — what exists, runtime-validated on this box:
- **`test-harness/browser/`** — a headless-**browser** interop echo-peer (answerer), one `BROWSER`-parameterized image (Chromium | Firefox): `driver.mjs` launches the engine via **Playwright**, drives a real `RTCPeerConnection` (accept the native offer, accept the DCEP data channel, echo `ping`→`pong`), and signals over the rendezvous **HTTP face**. `Dockerfile` (`ARG BROWSER` → `playwright install --with-deps ${BROWSER}` fetches only the selected per-arch engine, no cross-compile) + `entrypoint.sh` (NAT default-route rewrite, mirrors the native/Pion peers). Both engines negotiate DTLS 1.3 → the native peer runs at its **default** (`WEBRTC_DTLS13` untouched), the opposite of the Pion 1.2 lane. mDNS host-candidate obfuscation disabled per engine (Chrome `--disable-features=WebRtcHideLocalIpsWithMdns`; Firefox `media.peerconnection.ice.obfuscate_host_addresses=false`) so our parser sees real-IP candidates, not `.local`; srflx/relay carry connectivity across the NATs regardless. **Firefox is the highest-value oracle** — NSS DTLS + nICEr ICE + usrsctp, sharing nothing with Chrome's libwebrtc.
- **Rendezvous HTTP face** — `rendezvous/rendezvous.py` grew a threaded `ThreadingHTTPServer` (`POST /put` + `GET /poll`, CORS-open, port `RENDEZVOUS_HTTP_PORT=9998`) sharing the **same** in-memory `mailboxes` dict as the UDP face under a `threading.Lock`. A browser (HTTP) and a native peer (UDP) meet in the same slot. Refactored the mailbox mutation into `store_record`/`contiguous_records` used by both faces. **UDP lane backward-compatible** (native port-restricted re-verified).
- **wasmJs delegation** — `webrtc/src/wasmJsMain/.../PeerConnectionSupport.wasmJsMain.kt` now delegates to the browser `RTCPeerConnection` for real, via `@JsFun`/`JsString` opaque-`JsAny`-handle bridges (the buffer-crypto wasm-interop idiom). Data-channel payloads cross the wasm↔JS boundary as **byte-faithful lowercase hex** (no `ByteArray`, no webgl externals). New `webrtc/src/wasmJsTest/.../PeerConnectionDelegationTest.kt` (mirror of the js loopback) **passes in a real ChromeHeadless** (`wasmJsBrowserTest`) and no-ops under Node.
- **Wiring:** `docker-compose.yml` adds profile-gated `chrome` + `firefox` services; `run-interop.sh` gains `b_impl=chrome|firefox` cases + the two scenarios, plus a positional **allowlist** and a `HARNESS_SKIP` **skiplist** (filter logic unit-tested); `harness-l2.yaml` runs the browsers as a parallel **`{arch × browser}` matrix** (`l2-browser`) split from the native `l2` job (which sets `HARNESS_SKIP="chrome-interop firefox-interop"`); `README.md` + `CHANGELOG.md` document it. **Validated locally:** `chrome-interop` + `firefox-interop` both PASS (native ⇄ Chromium and native ⇄ Firefox, DTLS 1.3, bidirectional echo).
- **CI cost tuning:** browser image on a **`-slim` base** (~43% smaller: chrome 2.0→1.2 GB, firefox 1.8→0.9 GB) + a persistent **buildx/gha layer cache** in `l2-browser` (`docker/build-push-action` `cache-from/to: type=gha`, `load`) so the engine-download layer is restored from cache after the first run. `run-interop.sh` now **builds the images first, then starts both peers together in one `up`** (`HARNESS_NO_BROWSER_BUILD=1` reuses the cache-warmed image). **Trap fixed here:** starting the offerer + answerer in two *separate* `up` commands made the offerer skip publishing its offer (rendezvous saw only its answer-poll `op=2`, never the offer `op=1`) → both sides timed out; one combined `up` restores the proven ordering. The gha-cache backend itself is only exercisable in CI, not locally.
- **A real harness bug this found + fixed:** `run-interop.sh`'s scenario loop read the list from **stdin**, which `docker compose exec` (the netem `impaired` lane) drains — so the full matrix silently stopped after `impaired-loss-delay`, running **7/9** and never reaching `pion-interop`/`chrome-interop` (masked because Phase 2(a) validated Pion via the single-scenario path). Fixed: the loop reads from a dedicated fd (`3<<<`). **Full matrix now 9/9** (both interop lanes) — the fd fix is what makes the chrome (and pion) lane actually run in the CI l2 job's full run.

**NEXT (Phase 3), traps to carry:** the chrome image is ~2 GB (Chromium) — the l2 job's first build adds a few minutes (within its 30-min budget). The chrome lane runs a single NAT profile (port-restricted); extend to more profiles/relay-only if desired (relay policy is already honored in `driver.mjs`). Only the x64 arm of the Chrome lane is runtime-validated here — the arm64 leg builds the same image on the arm64 runner (Playwright pulls arm64 Chromium) and is CI-validated. `wasmJsBrowserTest`/`jsBrowserTest` need a host Chrome for Karma (`CHROME_BIN=/usr/bin/google-chrome` locally; CI provides one). Phase 3 = fill `webrtc-testsuite` (`withWebRtcHarness { natType(); relayOnly(); impaired() }`) + consumer-smoke; decouple the first Central release from interop-green.

---


### Phase 2(a) landed (this session) — what exists, runtime-validated on this box:
- **`test-harness/pion/`** — a Pion (Go) echo-peer (answerer): `main.go` drives a `pion/webrtc/v3` (DTLS-1.2-only) PeerConnection; `signaling.go` is the Go mirror of the native peer's `UdpSignaling` — it speaks the SAME big-endian buffer-codec rendezvous wire schema (nonce-correlated PUT/GET), so Pion and the native peer meet in the same mailbox. It gathers from the same coturn, accepts the DCEP data channel, echoes ping→pong. `Dockerfile` (multi-arch, native per-arch Go build) + `entrypoint.sh` (NAT default-route rewrite, mirrors the native peer). `signaling_test.go` round-trips the wire codec against a live `rendezvous.py` (skips if none).
- **Native peer gained a `WEBRTC_DTLS13` toggle** (`HarnessConfig` + `Main.kt`): the Pion lane sets `WEBRTC_DTLS13=false` so our offerer pins its (W4-tested) DTLS 1.2 fallback — else it would negotiate up to 1.3, which Pion v3 lacks. Default stays 1.3-on (production).
- **Wiring:** `docker-compose.yml` adds a `pion` service (gated behind the `pion` compose profile; drop-in for `peer_b` on `nat_b`/`PEER_B_IP`) + `WEBRTC_DTLS13`/`PEER_DTLS13` on the native peers. `run-interop.sh` gained a 6th `b_impl` matrix column (native|pion) and the `pion-interop` scenario. `harness-l2.yaml` comment updated (the pion image builds inside the l2 job — pure Go, no cross-compile step). README documents the lane.
- **A real harness bug this found + fixed:** `compose up` (via `compose-up-retry.sh`) ran WITHOUT `--build`, so a **stale cached image silently shadowed current source** — a dev box with an old `rendezvous.py` (pre-nonce wire schema) mis-signaled and every scenario hung with no code fault. Cost real debug time (both peers reached the rendezvous, but a 5-byte malformed reply revealed the stale no-nonce `_response`). Fixed: `--build` on both bring-up paths. CI was immune (fresh checkout); locally it's cached-fast.

**NEXT (Phase 2b/3), traps to carry:** the native offerer's `textBuffer("ping")` sends a **binary-PPID** message (Pion logged `string=false`) — echo still worked, but if a lane asserts string-vs-binary PPID, note our text helper isn't WebRTC-string-typed. The pion lane runs a single NAT profile (port-restricted) — extend to more profiles/relay-only if desired. Chrome lane (2b): Chrome does DTLS 1.3, so it runs default (no `WEBRTC_DTLS13=false`); it needs a JS shim to speak the UDP rendezvous OR an HTTP face on the rendezvous for the browser only.

---

---

### START HERE — W7 Phase 2 (interop: Pion + Chrome). Phase 1 is done + reviewed; branch off `w7-harness-l2`.

**Phase 1 landed (this session) — what exists now, all runtime-validated on this box:**
- **`:webrtc-harness-endpoint`** — a NEW non-published Kotlin/Native executable module (`linuxX64` +
  `linuxArm64`, both link + run; x64 fully validated). It composes the PRODUCTION stack —
  `NativePeerConnection` + `BoringSslDtls` over **real UDP** (`socket-udp`) — and drives it as a container
  endpoint. Config from `WEBRTC_*` env; offer/answer/candidates over a **UDP rendezvous** (buffer-codec
  KSP-generated wire schema — `SignalingWire.kt`); proves the data path with a `ping`/`pong`. Applies a new
  `build-logic/webrtc.native-executable` convention (KGP+KSP from build-logic's classloader — a module
  `alias(...)` double-loads KGP). Root `build.gradle.kts` aggregates (`allTests`/`detektAll`/`prePublishCheck`)
  now filter to `libraryModules` (this module has no such tasks). Sources live in ONE `src/linuxSharedMain`
  dir added to both targets' *main* source sets — KSP 2.3.10 has no common-metadata task for a native-only
  module, so per-target KSP generates into `<target>Main`, invisible to a shared `linuxMain`; the shared-dir
  trick sidesteps it with zero duplication. (The `…Main` name keeps it under the standing-directive grep.)
- **`test-harness/`** — the L2 compose harness (mirrors socket's): **coturn** (real STUN/TURN), a Python
  **UDP rendezvous** relay, two **NAT gateways** (`nat/nat-setup.sh` — all 4 RFC 4787 profiles; fidelity
  table in `test-harness/README.md`), **netem** on demand, two **peer** containers (self-building
  `Dockerfile` for portability incl. Apple Silicon, + fast `Dockerfile.prebuilt`). `run-interop.sh` drives
  the scenario matrix, asserts BOTH peers exit 0 (established + echoed), and tears the stack down on exit.
  `.github/workflows/harness-l2.yaml` runs it arch-matched (x64 + arm64 runners, no QEMU).

**Bugs this session found + fixed (real-network surfaced them; the vnet never did) — carry into review:**
1. **webrtc-ice production fix:** the gathering drivers built STUN datagrams with the DEFAULT (heap)
   buffer factory, bypassing `IceConfig.bufferFactory`. On real io_uring UDP (`socket-udp`) a heap buffer is
   rejected (`send requires a native-memory buffer`) → srflx/relay gathering crashed. Fixed:
   `gatherServerReflexive` takes a `bufferFactory` (additive param, `.api` re-dumped); `IceAgentDriver` now
   threads `config.bufferFactory` into both `gatherServerReflexive` and `TurnAllocation`. The peer injects
   `BufferFactory.deterministic()` (Linux native) into `IceConfig`/`SctpConfig`/`DtlsConfig`. **Fixture
   (directive #5) DONE:** `webrtc-ice/commonTest/GatheringBufferFactoryTest` — a `TaggingBufferFactory` +
   a `NativeOnlyChannel` that rejects any datagram not built from the injected factory (models io_uring's
   "send requires a native-memory buffer"). Two tests (srflx Discovered with the injected factory; rejected
   with the default heap factory). **Proven non-vacuous** — the positive test fails against the pre-fix
   `.encode()`. Runs on all platforms under `runTest`.
2. **io_uring under Docker:** Docker's default seccomp denies `io_uring_setup` → peers need
   `security_opt: [seccomp=unconfined]` (in compose).
3. **container-router forwarding:** a container routing between two Docker bridge networks only forwards
   with host `net.bridge.bridge-nf-call-iptables=0` (else bridged frames hit the host Docker ISOLATION via
   physdev). `run-interop.sh` sets it via a privileged host-netns container; CI via `sudo sysctl`.
4. **answerer teardown race:** the answerer closed its SCTP association the instant after `send(pong)`,
   racing reliable delivery → offerer's `receive()` timed out. Fixed with a bounded flush linger.

**Gates green:** `:webrtc-harness-endpoint` compiles + links (x64 **and** arm64 via cross-compile);
`:webrtc-ice:apiCheck` passes (re-dumped); `./gradlew build allTests` green (Linux side); standing-directive
greps clean (the `Clock.System` line carries an inline `@Suppress("UnseamedEntropy")` — the grep is
line-based). **CI (PR #17):** standing-directives, build-apple, all fuzz, and **harness-l2 (x64)** PASS on
real runners — the full 7-scenario NAT matrix establishes on a stock `ubuntu-24.04`, not just WSL2.

**The arm64 gotcha (carry this forward):** Kotlin/Native **cannot host its compiler on a linux/arm64
host** (`Unknown host target: linux aarch64`) — every other lane builds on x64 (`build-linux` *cross*-builds
arm64). So the `harness-l2` arm64 leg does NOT gradle-build on the arm64 runner: `build-peer` (x64)
**cross-builds both arches** and uploads them as an artifact; the arm64 `l2` job **downloads and only runs**
its binary in native arm64 containers (no QEMU on the data path). `run-interop.sh` gained a "supplied
`PEER_KEXE` → use as-is, don't build" path for exactly this (validated locally via the x64 binary). The
arm64 runtime lane needs the `ubuntu-24.04-arm` runner enabled for the repo.

**A strategic thread opened this session (see `~/git/cinterop-issues/`):** the owner is leaning toward
**option (II) — pure-Kotlin DTLS 1.3 over buffer-crypto** (RFC §11.5 / W4b) instead of linking BoringSSL,
which would retire the peer-binary hacks (native-only, cinterop, native buffer factory) by letting the peer
be JVM. A dedicated agent verified it's viable (only 2 gaps: a raw-AES buffer-crypto PR + a ~150-line cert
wrapper) and wrote `W4B-DTLS-SPIKE-PLAN.md` (3 spikes, go/no-go = a browser handshake). W7 is the interop
harness that de-risks it, and today's BoringSSL native path is its differential oracle — so Phase 1 is
needed under either option. **Decision pending the spikes; do not start the DTLS rewrite inside W7.**

**Phase 2 scope (unchanged from the plan below):** (a) **Pion echo-peer** container (Go, DTLS 1.2 → run our
side with `DtlsConfig(enableDtls13=false)`), (b) **headless Chrome via Karma** ⇄ our linuxX64 peer, both over
a scripted signaling bridge (the UDP rendezvous already is one — Chrome will need a JS shim to speak it, or
add an HTTP face to the rendezvous for the browser lane only). Then Phase 3 (testsuite publish).

---

### START HERE — W7 (harness + interop + testsuite publish). Fresh session; branch off `main` @ `c057a57`.

**Read first:** `RFC_KMP_WEBRTC.md` (§5.2 vnet, §8 harness) → `EXECUTION_PLAN.md` (W7 row) → this section →
`TESTING.md` §L2/L3 (the operative deliverables) → sibling `socket`'s `test-harness/` + `socket-testsuite/`
(the pattern to MIRROR, not consume — verified: socket's harness is QUIC-coupled and unpublishable for us).

**The one correction that reshapes the plan (do not miss it):** EXECUTION_PLAN/TESTING say "our **JVM** stack
⇄ Pion/Chrome." **JVM has NO DTLS backend** (typed `BackendUnavailable` — W4 is native-Linux-only). So the
"our side" interop endpoint MUST be the **native `linuxX64` binary**, the only backend with a real DTLS 1.3
handshake. Plan text predates the W4-native-only reality; treat "JVM" as "linuxX64" for every interop lane.

**What already exists (don't rebuild):** `webrtc-testsuite` is a published, validate-wired module *skeleton*
(`src/commonMain/.../testsuite/WebRtcTestsuite.kt` placeholder; deps `:webrtc` + coroutines). There is **no**
container/harness/docker dir yet. `peerConnectionSupport()` browser delegation (JS) already works (Karma-tested);
**wasmJs delegation still throws `NotImplementedError`** (the one open W6 follow-up — fold into the Chrome lane).

**Scope, three phases:**
1. **L2 container harness** (Integration; no DTLS dep, can start first) — mirror socket's `test-harness/`
   docker-compose: **coturn** (real STUN/TURN → srflx+relay gathering), **NAT-profile containers** (iptables/
   netns per RFC 4787), **netem** impairment, **toxiproxy** on the signaling channel. Arch-matched CI matrix
   (no QEMU), Colima on macOS. Exit: two-peer establish over each NAT profile against real kernels.
2. **L3 interop** (needs the native stack) — (a) **Pion echo-peer container** (Go/pion-webrtc: accept offer,
   answer, echo a data channel). **Pion released v3 is DTLS 1.2-only** (§11.3) → run this lane with
   `DtlsConfig(enableDtls13=false)` (our 1.2 fallback is tested), or Pion's 1.3 branch. (b) **headless Chrome
   via Karma** driving real `RTCPeerConnection` ⇄ our linuxX64 binary (Chrome does 1.3). Both need a **scripted
   signaling bridge** (offer/answer over a file/HTTP/ws side channel — TESTING.md insists interop be
   reproducible, not flaky live exchange). Exit: our stack ⇄ Pion AND ⇄ Chrome establish + echo data-channel
   messages in CI.
3. **Consumer testsuite + publish** — fill `webrtc-testsuite` with the `withWebRtcHarness { natType();
   relayOnly(); impaired() }` DSL (mirror socket's `withNetworkHarness` + `HarnessController`); a clean-checkout
   consumer-smoke project; it's already wired into validate-artifacts. Decouple the "first Central release" from
   interop-green — get interop landing first.

**Traps to carry in:** (a) the memory-BIO sends a whole flight as ONE datagram — fine on the vnet, but a
**real-MTU path may need a datagram-preserving BIO** (documented W4 deferral; W7 real-network is where it could
bite). (b) Browser-reachability gymnastics on Linux CI (socket documented these). (c) `SocketException` bridge
is still blocked (socket↔buffer-crypto BoringSSL dup-symbol) — W7 does not need it. (d) `skip-release` label →
`flow=dry-run` in `merged.yaml` (builds+validates, does NOT publish); a real release is `minor`/no-label.

**Session hygiene:** this is a new wave → **fresh session, new branch off `main`** (`c057a57`). W4's 5 commits
+ CI fixes are on `main`. Standing traps unchanged: `skip-release` via `gh api …/labels` (not `gh pr edit`);
Apple runtime-validated on the macOS runner; `git fetch` before reasoning about `main`.

---

### (W4, now merged) Adversarial-review gate — DONE (4 parallel lanes; all confirmed defects fixed + regression fixtures)
CI-directive greps clean (no primitive arrays, no unseamed clock/random); driver/lifecycle lane found no
blockers (pump, handshakeTimeout, peer-fingerprint check, role-from-`a=setup` all correct). Five
MAJOR/BLOCKER findings fixed, each with a fixture (see CHANGELOG "Hardened"): **(1 BLOCKER)**
`CertificateFingerprint` primary ctor made **private** + validating `ofHex` (the RFC 8122 identity check was
casing-fragile; `.api` re-dumped — constructor removed); **(2)** fatal read-path error → `Failed(RecordLayerError)`
(was swallowed → wedged `Established`); **(3)** GC-heap FFI staging bounded (was an unbounded over-read);
**(4)** `handshakeTimeout` liveness fixture added (`DtlsHandshakeTimeoutTest`); **(5)** three real buffer-leak
sources closed (bd_new BIO partial-alloc, native ctor-throw, driver teardown-race) + the alloc invariant
scoped honestly to bounded-allocation (W3/W5 posture). Plus a malformed-record T0 fixture. **All green:**
`webrtc-dtls`+`webrtc` linuxX64 tests, apiCheck, ktlintCheck all pass. **One finding NOT covered by a
deterministic fixture:** the pure `BD_FATAL`-on-read branch — DTLS silently drops malformed records rather
than faulting, so a genuine post-handshake fatal alert isn't synthesizable at this seam; the fix is
defensive and the malformed-record test covers the read-path robustness.

---

### START HERE — W4 wiring session (what this session did)

**The headline: `PlaintextDtls` is no longer the only option — `BoringSslDtls` is real and the W4 exit
fixture passes.** `webrtc/src/linuxTest/.../PeerConnectionDtlsEndToEndTest.kt` is the gate W5 and W6
both deferred: two `NativePeerConnection`s negotiate offer/answer, nominate an ICE pair, complete a
**real BoringSSL DTLS handshake**, bring up SCTP, and exchange data-channel messages both ways — 7 ms of
virtual time, zero wall-clock.

**Four design decisions this session made (each deliberate — don't silently revert):**
1. **The DTLS role moved out of the `DtlsEngine` constructor into `start(role, now)`.** Forced by a real
   ordering constraint: the engine mints its self-signed cert at construction, but `a=fingerprint` must
   go into the *offer*, long before `a=setup` negotiates the role. So an endpoint has an identity from
   birth and learns its role from signaling later — which is exactly WebRTC's own model. In C, `bd_new`
   lost `is_client` and gained `bd_set_role` (SSL_set_connect/accept_state is legal any time before the
   first `SSL_do_handshake`). A `started` guard makes driving-before-start a `check()`, not a segfault.
2. **Certificate identity lives on the DTLS factory** (`DtlsTransportFactory.localFingerprint`), and
   `PeerConnectionConfig.localFingerprint` (the W6 all-zero placeholder) is **deleted**. `PeerConnection`
   now advertises `dtls.localFingerprint`, so advertising one digest while presenting another is
   unrepresentable rather than merely discouraged. `DtlsTransportFactory` is therefore no longer a
   `fun interface`, and `secure()` takes the peer's `Fingerprint`.
3. **One DTLS vocabulary.** The root's W6-era duplicate `DtlsFailureReason` is **deleted**;
   `PeerConnectionFailureReason.Dtls` composes webrtc-dtls's sealed reason unchanged, exactly as
   `Ice`/`Sctp` compose theirs (and it dodges an import clash between two same-named types). The
   webrtc-dtls vocabulary now spans the whole layer and marks each case *(engine)* or *(driver)*.
4. **`DtlsConfig.handshakeTimeout` (30 s default)** closes a liveness hole: DTLS retransmits a lost
   flight forever, so a peer that goes silent mid-handshake would otherwise hang the session. The
   sans-io engine has no clock, so the driver enforces it — hence the config field with no engine use.

**A latent CI break this session found and fixed:** `webrtc-dtls` had **no `appleMain` actual**, and the
convention plugin registers Apple targets **only on macOS hosts** — so it compiled clean on this Linux
box and would have failed `build-apple` on the runner. `appleMain` now carries typed
`BackendUnavailable` actuals. **Apple needs more than JVM/Android do**: buffer-crypto is CommonCrypto
there, so there is no already-linked libcrypto for a libssl.a to resolve against — Apple DTLS needs the
buffer-crypto BoringSSL migration first, not just a boringssl-kmp release.

**A hang I wrote and caught in self-review (the shape to watch for in this driver):** when the pump exits
on a record-layer failure it left `outbound` **open**, so a later `send()` would `trySend` successfully
and `await` an ack no pump would ever complete. Fix: close `outbound` *before* draining it in the pump's
`finally`, so `trySend` fails fast with a typed reason.

**Where the remaining W4 exit criteria landed:** the dropped-flight **retransmission** fixture and the
injected-factory/bounded-allocation invariant are both in
`webrtc-dtls/src/linuxTest/.../DtlsRetransmissionTest.kt`. The retransmission test is deliberately
non-vacuous: it asserts the timer arms, does **not** fire early, and that the retransmitted flight
actually completes the handshake.

**Status of the gates:** `./gradlew build` green (3 runs, incl. two `--rerun-tasks`); ktlint + apiDump +
detekt + both standing-directive greps green; linuxArm64 cinterop re-verified against the new `.def`.
**One unexplained transient `BUILD FAILED`** was seen once and never reproduced across three subsequent
full builds — re-run `./gradlew build` before pushing and, if it recurs, capture the log (the known
suspect is the documented `node:internal/timers` JS-node flake).

---

### (prior) START HERE — W4 (fresh session), branch `w4-webrtc-dtls` (3 commits off `main` @ `0e1a702`)

**Two decisions were resolved and recorded in the `EXECUTION_PLAN.md` decision log — read those two rows first:**
1. **§11.3 (DTLS version)** → **min 1.2 / max 1.3, 1.3 ON by default** (`DtlsConfig.enableDtls13 = true`).
   The field has moved to 1.3 (**verified by search, not assumed**): Firefox ships it in Release,
   Chrome/BoringSSL has it on by default (libwebrtc flipped in 2025), and BoringSSL itself now defaults
   to 1.3. Min stays 1.2 purely for breadth — **Pion's released v3 is still 1.2-only** — and negotiation
   falls back automatically. **Both paths are asserted by tests**, not assumed.
2. **W4 sequencing** → **native-Linux DTLS now, self-contained; JVM/Android/Apple deferred to
   `boringssl-kmp`.** This *inverted a plan premise* — see "the boringssl-kmp reality" below.

**A third thing to know: RFC §11.5 — pure-Kotlin DTLS 1.3 over buffer-crypto is now an open question
+ a candidate wave (W4b).** Audited this session: buffer-crypto already has ~every primitive TLS 1.3
needs (`Hkdf.extractInto`/`expandInto` **separately** = the key-schedule shape, AEAD, X25519/P-256,
ECDSA/Ed25519, streaming SHA, constant-time, CryptoRandom). The **only** gap is a raw AES block for
RFC 9147 §4.2.3 sequence-number encryption → an additive buffer-crypto PR (W1 precedent). What
BoringSSL uniquely gives us is *the protocol*, not the crypto — plus ASN.1 DER for the self-signed
cert. Because both browsers now do 1.3, a **1.3-only** core already talks to the whole browser field
(1.2 is a later breadth add for Pion), and 1.3 is the *simpler, more misuse-resistant* protocol — so
this is far more tractable than "reimplement TLS" sounds. It would delete the native dep, the
duplicate-symbol class, the boringssl-kmp dependency, **and** unblock the W6 SocketException bridge.
**Do not do it instead of finishing W4** — `DtlsEngine`'s caller-clocked sans-io `expect` already fits
it exactly, so a pure-Kotlin core later just *becomes* the commonMain implementation and inherits
W4's fixtures; and BoringSSL should stay permanently as the **differential-testing oracle**. Full
rationale in RFC §11.5 / EXECUTION_PLAN "W4b".

**The linkage (the crux — proven empirically, do not re-litigate):** `webrtc-dtls` links **only**
`libssl.a`, built from **buffer-crypto's exact pinned commit `63893acb`**, and lets libssl's undefined
`AES_*`/`SHA256_*` resolve against **buffer-crypto's single already-linked `libcrypto.a`** (embedded
once in its published cinterop klib, contributed transitively). **Never add `-staticLibrary
libcrypto.a`** to our cinterop — that is the duplicate-symbol trap that breaks the native link (the
socket/quiche hazard, same class as the W6 `libs.socket` blocker). `DtlsBackendLinkNativeTest` is the
tripwire: it links libssl + libcrypto in one K/N binary and would fail if a second libcrypto appeared.

**What landed (3 commits, all lanes compile, linuxX64 runtime-validated):**
- `webrtc-dtls/build.gradle.kts` — `buildBoringsslSsl{X64,Arm64}` provisioning (clone @ pinned commit →
  cmake → `make ssl` → harvest `libssl.a` + headers into gitignored `libs/boringssl-ssl/linux-$arch`,
  marker-file skip so a dev box can drop in a prebuilt). **Both x64 and arm64 verified end-to-end**
  (arm64 cross-built locally via `aarch64-linux-gnu-gcc`). cinterop wired on the Linux targets only.
- `src/nativeInterop/cinterop/boringsslssl.def` — the whole `bd_*` inline-C wrapper surface (cinterop
  returns EMPTY bindings for raw BoringSSL symbols, hence wrappers): SSL_CTX/SSL + memory-BIO pair,
  self-signed P-256 cert + `X509_digest` fingerprints, `DTLSv1_get/handle_timeout`,
  `SSL_export_keying_material` (DTLS-SRTP), `use_srtp` extension, negotiated-version readout.
- **The determinism seam:** BoringSSL's DTLS timers read `SSL_CTX_set_current_time_cb`. **Its `ssl` arg
  is always NULL** (documented) — so the injected virtual time rides a **thread-local** (`bd_now_us`)
  that every driving wrapper sets from the caller's `now` before entering libssl. That is what makes
  handshake retransmission replay deterministically; do not "simplify" it to `SSL_get_app_data(ssl)`.
- `commonMain` — sans-io caller-clocked `expect class DtlsEngine` (`start`/`onDatagram`/`onTimeout`/
  `send`/`beginClose` + `nextTimeoutMicros`, epoch-micros), sealed `DtlsState`
  (Handshaking/Established/Closed/Failed) + sealed `DtlsFailureReason`, `DtlsConfig` seams,
  `CertificateFingerprint` (+ RFC 8122 `sdp` rendering). `.api` dumped.
- `linuxMain` — the BoringSSL actual. **FFI buffer edge is a fast/slow split:** a native-backed buffer
  hands BoringSSL its own address (zero staging copy — pass a *pooled native* factory in production);
  a GC-heap buffer (`managed()`/`Default`, which on Linux are `ByteArrayBuffer` with **no** native
  address) stages through one reusable per-engine 64 KiB native `scratch`. No `ByteArray` anywhere.
- `jvm/android/js/wasmJs` — typed `DtlsUnavailable` actuals (`BackendUnavailable`), fail-fast.
- `linuxTest` — **the W4 exit fixture**: `two_stacks_complete_a_dtls_handshake_under_virtual_time`
  (both sides Established, each verifying the *other's* real cert fingerprint, negotiated **1.3**) +
  `two_stacks_fall_back_to_dtls_1_2_when_1_3_is_disabled` (the Pion/1.2 interop lane, negotiated
  **1.2**) + `application_data_flows_after_the_handshake` + the linkage tripwire. **7/7 in 2 ms.**

**A trap that cost real time — do not reintroduce:** a wrapper returning a **positive status sentinel**
from a **byte-count** function is catastrophic. `bd_read_app` returned `BD_WANT_READ = 1` for "no data",
which collides with a 1-byte read; the Kotlin drain loop checked `n > 0` first, so it allocated forever
— **`dmesg` shows `test.kexe` OOM-killed at 42 GB RSS**, which killed the whole Claude/node process.
Byte-count wrappers now report `BD_NO_DATA = 0` with **negative-only** errors, plus a
`MAX_RECORDS_PER_PUMP` bound. When running native tests locally, cap them:
`(ulimit -v 2000000; timeout 90 ./webrtc-dtls/build/bin/linuxX64/debugTest/test.kexe)` — do **not**
`ulimit` the Gradle daemon itself (it needs > 4 GB and will fail to start).

**Next steps, in order:** *(steps 1–3 are DONE — see the wiring-session section at the top of this file)*
1. ~~**Wire `webrtc` root (replace `PlaintextDtls`)**~~ — **DONE** (`BoringSslDtls`). Add
   `api(project(":webrtc-dtls"))` to `webrtc/build.gradle.kts`, then implement `BoringSslDtls :
   DtlsTransportFactory` in `webrtc` root `commonMain`: a **coroutine driver** that constructs
   `DtlsEngine` (the expect class, so root `commonMain` can reference it), pumps it over
   `IceDataTransport` (inbound records → `onDatagram`; outbound `DtlsStep.records` → `iceData.send`),
   arms timers from `nextTimeoutMicros` against the **injected clock**, and exposes the established
   engine as an `SctpDatagramTransport` (`send` → `engine.send`, `receive` → a channel fed by the pump).
   Map `DtlsFailureReason` → `PeerConnectionFailureReason.Dtls`. **Verify the peer fingerprint** from
   `DtlsState.Established.peerFingerprint` against the SDP `a=fingerprint` — the engine is deliberately
   signaling-agnostic and does NOT do this. Role comes from `a=setup` (W6 already negotiates it).
2. **The real ICE+DTLS+SCTP end-to-end TB fixture** (the W5/W6 exit gate this un-gates) — gate it to
   native (`linuxTest`), since JVM/JS have no backend. The existing `PlaintextDtls` tests stay on all
   platforms.
3. **Remaining W4 exit criteria:** the dropped-flight **retransmission fixture** (drop a flight, assert
   `nextTimeoutMicros` fires and the flight is retransmitted — the caller-clocked timer path is built
   but not yet covered by a test), and the **wrapper-free/no-leak invariant** (`bd_free` + `scratch.close`
   on every path; a `CountingBufferFactory` no-leak test).
4. **Then:** adversarial-review gate, CHANGELOG, PR with `skip-release` **via the REST API** (`gh pr
   edit` no-ops), state the V6_MAC_VALIDATION lane reality (Apple has **no** DTLS backend this wave).

**The boringssl-kmp reality (why W4 is native-only — investigated this session, 2 agents):**
`com.ditchoom.boringssl:boringssl-kmp` (sibling at `../git/boringssl-kmp`) is a **binary factory**
(native provision plugin + JVM FFM MRJAR + Android prefab AAR) that names `webrtc-dtls` as a consumer —
it is the **right long-term home** for JVM/Android/Apple DTLS. It cannot serve W4 today because:
(a) **unpublished** (`0.0.1-dev`; W0 discipline forbids depending on an unpublished sibling);
(b) its pin is **quiche-anchored `44b3df6f` (API 21) ≠ buffer-crypto's `63893acb` (API 42)**, so mixing
them in one K/N binary = **two unprefixed libcryptos → SIGSEGV** (webrtc already links buffer-crypto via
STUN's HMAC); (c) its **JVM FFM shim is crypto-only — no DTLS/SSL exported yet**; (d) its **Apple lane is
unbuilt**; (e) no js/wasm ever (browsers delegate — fine). Its own RFC sequences `webrtc-dtls` as
migration **step 9, last**, after buffer-crypto/socket/quiche migrate onto the one canonical copy.
**So:** JVM/Android/Apple DTLS unblocks when boringssl-kmp publishes *and* grows a DTLS surface (JVM/
Android need no native-link dedup — buffer-crypto is pure JCA there, so those are clash-free whenever it
lands; **Apple/native additionally require the buffer-crypto migration** or they re-create the clash).
**Worth raising upstream (their repo):** boringssl-kmp's quiche-anchored API-21 pin has **no
`DTLS1_3_VERSION`** — its own RFC locks in a "DTLS 1.2 baseline" — so that route would ship
JVM/Android/Apple a **1.2-only** DTLS stack just as both browser engines standardise on 1.3 (§11.3).
The quiche anchor is the cause. buffer-crypto's API-42 gives us 1.2 **and** 1.3 on native today. This
is also a point in favour of the §11.5 / W4b pure-Kotlin route, which sidesteps the pin entirely.

**Also deferred (documented in code):** real-network **MTU/datagram-boundary** preservation — the memory
BIO is a byte stream, so a flight is drained and sent as ONE datagram (valid: DTLS records self-delimit,
and correct on the vnet; a real-MTU path may need a datagram-preserving BIO — a W7 concern).

---

### (prior) START HERE — after W6 (fresh session)

**W6 built, unmerged** on `w6-webrtc-peerconnection` (4 commits on top of `02c6a4e`):
1. `IceAgentDriver` (webrtc-ice `commonMain`) — the W5 ICE→SCTP composition promoted to production
   (`DatagramBinder` net seam + `IceDataTransport` app-data seam + RFC 7983 demux) + `IceCandidateLine`
   (RFC 8839 candidate↔typed codec).
2. `NativePeerConnection` / `RtcPeerConnection` (webrtc root) composing JsepSession + IceAgentDriver +
   plaintext-DTLS seam + SctpDataChannelStack; sealed `PeerConnectionState`; DTLS/SCTP role **negotiated
   from `a=setup`** (RFC 8842). Typed error hierarchy (`PeerConnectionFailureReason` + `WebRtcException`
   + `JsepStateException`/`SdpFormatException`).
3. `peerConnectionSupport()` browser delegation — **js** actual maps our API onto the browser
   `RTCPeerConnection`, Karma-tested against a real in-browser loopback.
4. Adversarial-gate fixes (role-negotiation deadlock, 5 lifecycle/liveness defects, 6 API-surface, 4
   browser defects), each with a regression fixture.

**Deferred / open (documented in code + CHANGELOG):**
- **`SocketException` bridge (RFC §3.1) is BLOCKED, not done.** Depending on `com.ditchoom:socket` links
  socket's `LinuxSockets` cinterop, whose **vendored BoringSSL duplicate-symbols against buffer-crypto's
  BoringSSL** on every native target (`ld.lld: duplicate symbol AES_set_decrypt_key`, …) — and drags
  node `fs`/`tls` into the browser bundle. So webrtc keeps a **self-contained** typed error vocabulary;
  re-parenting `WebRtcException`/`SctpClosedException` onto `SocketClosedException` waits on an upstream
  socket↔buffer-crypto BoringSSL dedup. Same posture as DTLS-on-W4. **Do not re-add `libs.socket` until
  that upstream fix lands** (it will fail the native link).
- **wasmJs browser delegation** — the wasmJs actual reports `BrowserDelegated` but `createDelegated`
  throws `NotImplementedError`; the external-interface (`JsAny`) mapping of the js `dynamic` delegation is
  the one remaining W6 browser follow-up.
- **W4 (DTLS) parked** — the plaintext seam stands in; the real ICE+**DTLS**+SCTP end-to-end TB fixture is
  W4's exit gate. `PlaintextDtls` has **no default** (must be passed explicitly — greppable insecurity).
- **wpt webrtc/ smoke** — the Karma loopback delegation test is the browser smoke; a fuller wpt import is
  a W7 concern.
- Speculative review notes left as follow-ups (not defects): `gatheringRandom` is single-stream (safe for
  the default one-shot gather policy; a custom policy launching concurrent gathers on a multi-thread
  dispatcher would need synchronization); `IceAgentDriver._selectedPair` is a non-volatile cross-coroutine
  read (fine under single-thread `runTest`).

**Next:** merge W6 (below), then **W4 (`webrtc-dtls`, BoringSSL)** — resolve §11.3 (DTLS 1.2-vs-1.3) first;
it un-gates both the real end-to-end TB fixture and (with the upstream BoringSSL dedup) the SocketException
bridge. Then W7 (harness/interop: Pion + Chrome).

---

### (prior) START HERE — W6 (`webrtc` root: PeerConnection + JSEP + browser actuals) · original plan

**Read first, in order:** `RFC_KMP_WEBRTC.md` (§3.1 consumer API, §5 determinism) → `EXECUTION_PLAN.md`
(W6 row + exit criteria) → this file → `DESIGN_PRINCIPLES.md` (§4 no illegal states — W6 is the public API,
so this matters most here) → `TESTING.md` (§2 L3 interop, §7 W6 deliverables). Skim RFC 8829 (JSEP) and
the browser `RTCPeerConnection` API.

**What's already merged (W6-partial, PR #5):** `webrtc-sdp` — the hand-written SDP text codec (T0 + Jazzer)
— and the **sans-io `JsepSession` machine** (`handle(event,now)` + `nextDeadline`, RFC 8829 §3.5.1 signaling
transition table + rollback, entropy-seeded `o=` id). Both `commonMain`, green everywhere. Do **not** rebuild
these; W6 consumes them.

**What W6 must build (the remaining consumer API):**
1. **`PeerConnection` session API** in the `webrtc` root module — the state machine that composes the layers:
   drives `JsepSession` (offer/answer over the injected signaling seam), gathers via the W3 **`IceAgent`**,
   and once a pair is nominated runs DTLS + the W5 **`SctpDataChannelStack`** over it. `createDataChannel()`
   returns the buffer-flow `StreamMux`/`Connection` W5 already implements. Sealed `PeerConnectionState`
   (DESIGN §4 — no boolean/nullable soup), caller-clocked, seams injected. `use {}`/`SessionTransport`
   lifecycle convention.
2. **The ICE→SCTP composition, promoted to production.** W5 proved this in `webrtc-ice/commonTest`
   (`IceDriver.sctpTransport()` — an `SctpDatagramTransport` over the nominated pair + the **RFC 7983
   STUN/app demux**). W6 needs the **production** version: either `webrtc-ice` exposes a public
   "connected `DatagramChannel` / transport over the selected pair" (recommended — W6 and a future media
   layer both need it), or `webrtc` root owns the demux+adapter. The seam stays `SctpDatagramTransport`-shaped
   so **DTLS (W4) slots in at exactly that boundary** — the plaintext stub used through W5 is the placeholder.
3. **Browser / wasmJs `peerConnectionSupport()`** delegating to the native `RTCPeerConnection` (RFC §1.1: browsers
   are the sole target where we wrap, not reimplement). The `webrtc` module's browser actual maps our
   `PeerConnection` API onto the JS object; Karma unit-tests the delegation.
4. **The `SocketException` error sweep** — map every typed reason into socket's `SocketException` hierarchy with
   exhaustive sealed reasons: `IceFailureReason` (W3), `SctpFailureReason`/`SctpClosedException` (W5), and the
   coming DTLS reasons. This is the "typed errors, never stringly" directive realized at the session boundary
   (the ICE/SCTP handoffs explicitly left this mapping to W6).

**Prerequisites / gating (unchanged posture from W5):**
- **W4 (DTLS) is parked**, so the *real* full-stack **ICE+DTLS+SCTP → PeerConnection** end-to-end TB fixture
  (TESTING §7 W6/W5 exit) is gated on W4. Build the API + JSEP wiring + browser delegation + error sweep **now**
  against the **plaintext DTLS-shaped seam** (`SctpDatagramTransport`), exactly as W5 did — the real-DTLS
  end-to-end is the exit gate once W4 lands. Resolve §11.3 (DTLS 1.2-vs-1.3) before W4.
- **`.api` is THE public commitment** (EXECUTION_PLAN W6 exit: *"the wave where API mistakes become expensive —
  extra review pass"*). Treat `apiDump` output as the deliverable; run an adversarial API review before merge.
- **Browser target must compile + delegation Karma-tested**; a `wpt webrtc/` smoke on the browser target is the
  W6 testing deliverable (TESTING §7).

**Branch W6 off `main`** (W5 is now merged in). Standing traps unchanged (see below): `skip-release` via the REST
API + verify; Apple runtime-validate on the macOS runner; `git fetch` before reasoning about `main`.

---

### 2026-07-15 — W5 built (association + DataChannel), green all platforms; PR open, unmerged

**Branch `w5-webrtc-sctp`** (off `main` + the W3-merged docs commit). What landed (one commit `92ea6d1` +
the test/fuzz/api follow-ups):
- **`SctpAssociation`** (`webrtc-sctp/commonMain/.../association/`) — sans-io `handle(event,now)` +
  `nextDeadline`, no clock/RNG/IO inside. Four-way handshake (stateless State Cookie — plaintext magic,
  not HMAC, because DTLS authenticates the transport; documented), TSN/SACK, RTO (RFC 4960 §6.3.1),
  congestion control (`CongestionControl.kt`: slow-start/cong-avoid/T3+fast-rtx collapse), retransmission
  queue (`RetransmissionQueue.kt`), fragmentation + ordered/unordered reassembly (`ReassemblyQueue.kt`),
  **RFC 3758** FORWARD-TSN partial reliability, graceful+abort shutdown. Seeded `Random`, sealed
  events/outputs/state/reasons.
- **`SctpDataChannelStack`** (`.../datachannel/`) implements buffer-flow **`StreamMux<ReadBuffer>`** —
  DCEP (RFC 8832) OPEN/ACK wired to the association, even/odd stream split (§6), empty-message PPIDs
  (RFC 8831 §6.6). Drives the association over an injected **`SctpDatagramTransport`** (the clean
  DTLS-shaped seam), scope, and clock. `openBidirectional()` → `Connection<ReadBuffer>`.
- **Key seam decision (matches HANDOFF plan):** `SctpDatagramTransport` is the one small connected
  `DatagramChannel`-shaped interface where real **DTLS (W4) drops in as a swap**. Tests use a plaintext
  in-memory pair and an ICE-backed adapter.
- **§11.2 resolved:** dcSCTP-style subset (no multihoming, no interleaving) — recorded in the
  EXECUTION_PLAN decision log.
- **Tests, all platforms under `runTest`:** sans-io two-endpoint conductor (`SctpSim`); coroutine
  DataChannel end-to-end over an impaired transport; the **W5 composition** — SCTP DataChannels over the
  **real W3 `IceAgent` nominated pair** across the vnet (added `IceDriver.sctpTransport()` + RFC 7983
  demux to `webrtc-ice/commonTest`, with `webrtc-sctp` as a test-only, acyclic dep). A **260-seed
  loop-until-dry invariant campaign** (no reorder / no unacked-drop / no dup / liveness) and the Jazzer
  `sctpCodecFuzz` lane extended to fuzz `association.handle` (3 M runs clean). `CountingBufferFactory`
  no-per-tick-leak (directive #6). **`webrtc-sctp:allTests` + `webrtc-ice:allTests` green; ktlint +
  apiCheck + standing-directive greps green; apiDump committed.**

**Explicit W5 scope note (why this is complete without W4):** the full ICE+**DTLS**+SCTP TB fixture with
*real* BoringSSL DTLS is, per TESTING §7 and the W3 handoff, the exit gate **once W4 lands** — it is
W6's composition job. This wave delivers everything achievable with DTLS parked: the SCTP core, the
DataChannel mux, and the end-to-end proof over ICE with a plaintext DTLS stand-in at the seam.

**Adversarial-review gate — DONE (5 parallel reviewers; confirmed defects fixed with regression
fixtures).** Directives #1–#3 clean; #6 injection clean (pooling/release deferred, matches W3); the
DataChannel driver's `association.handle` re-entrancy was investigated and **refuted** (outputs are
materialized before `apply` runs). Confirmed defects fixed (directive #5 fixtures in
`ReassemblyQueueTest`/`SctpRegressionTest`/`DataChannelStackTest`): lone FORWARD-TSN→SACK (RFC 3758 §3.6);
T3 retransmit **paced by cwnd** (§6.3.3 E3, was a full-flight burst); `missingReports` reset on re-send
(was infinite fast-retransmit); PR abandonment on the SACK path (timed msg no longer retransmitted
forever); **reflected T-bit ABORT** accepted (§8.5.1); gap-block u16 overflow omitted (was malformed
`end<start`); **SSN wrap** (was ordered stall after 65535 msgs); I-bit + gap-fill immediate SACK;
cross-stream/SSN fragment splice guard; driver **teardown completes pending deferreds** (was: open/send
hang forever) + breaks on ABORT + OPEN-parity validation + early-data buffering + `SctpClosedException`.
Jazzer re-stamps a valid CRC so the association handlers are actually fuzzed (cov 1052→1472); the
invariant campaign is split into an all-platform smoke + a JVM deep-run (+ fragmentation-under-loss); the
sim conductor throws on non-convergence. All lanes green; committed as `5970af7`.

**Also landed: CI flake-diagnosis capture** (`ci: capture test reports + Jazzer crash repros on failure`)
— build-linux/build-apple upload `**/build/test-results/**` (JUnit XML: full stack + captured stdout;
seeded tests print the failing seed → reproducible) + `**/build/reports/tests/**` on failure; the fuzz
jobs upload `**/build/fuzz/**` (the exact crash/timeout repro input). This is what turns a flake like the
earlier `node:internal/timers` JS-node timeout into a diagnosable artifact instead of a guess.

**W5 status: MERGED to `main` (squash, PR #13, `skip-release`).** Full CI matrix green (build-linux +
build-apple/Apple K/N + all three fuzz lanes + standing-directives + validate); the adversarial-review
gate ran and every confirmed defect is fixed with a regression fixture. Nothing published to Central
(`skip-release`). W6 is next — see the **START HERE** section at the top.
- **Follow-ups documented in code / deferred (not blockers):** channel close via SCTP **stream reset**
  (RFC 6525 RE-CONFIG) is out of the subset — `Connection.close` tears down local halves only; TSN/SSN
  **serial-number wrap** is not modeled (session never nears 2³², noted in `ReassemblyQueue`); explicit
  pool `release`/`use{}` of packet/reassembly buffers is the same entangled refactor deferred in W3
  (managed buffers + `CountingBufferFactory` bounded-alloc used instead of strict `assertNoLeaks`);
  SACK bundles one chunk per packet (correct, not yet coalesced); no HEARTBEAT probing (WebRTC relies on
  ICE consent). detekt flags the state-machine complexity (`onSack`/`onDatagram`/`SctpAssociation` size)
  — non-blocking, inherent to the protocol.
- **W4 (DTLS) or W6 (PeerConnection) next.** W6 composes ICE+DTLS+SCTP into `PeerConnection` and is where
  the full TB fixture + the `SocketException`-hierarchy mapping of `SctpFailureReason`/`IceFailureReason`
  land. Resolve §11.3 (DTLS 1.2-vs-1.3) before W4.

### (prior) W3 state

### 2026-07-15 — W3 merged; W5 is next (W4 held); resume guide

**W3 landed on `main` as `1556c0d` (squash of PR #11):** the full sans-io ICE agent (RFC 8445 + trickle
8838 + consent 7675) — checklist FSM, connectivity checks over the W1 STUN client, regular nomination,
role-conflict, consent/keepalive, ICE restart; host/srflx/relay gathering (`TurnAllocation` as a
`DatagramChannel`); the deterministic NAT vnet (4 RFC 4787 profiles + virtual TURN/STUN + seeded
impairment); and a strong type model (sealed per-type `IceCandidate`, `ComponentId` enum, sealed
gathering results, no boolean/nullable soup — see `DESIGN_PRINCIPLES.md` §3–§5). An adversarial review
gate (5 reviewers) ran and every confirmed defect is fixed with a regression fixture. Full CI matrix
incl. Apple K/N is green.

**Next wave — W5: SCTP association state machine + `DataChannel` (pure Kotlin, sans-io).** The chunk
codec + DCEP are already merged (W5 floor). Remaining: the association FSM (4-way handshake, TSN/SACK,
RTO, congestion control, fragmentation/reassembly over `StreamProcessor`), RFC 3758 partial-reliability,
and `DataChannel` implementing buffer-flow's `StreamMux`. Resolve §11.2 as it starts.

**Key architectural decision for W5 (why it doesn't need W4 yet):** the sans-io split decouples the SCTP
core from DTLS exactly as it decoupled ICE from real UDP. The association FSM only needs a **datagram
transport** underneath, which the W3 ICE stack + the vnet already provide. So build and test W5
end-to-end over `ICE + vnet` under `runTest` virtual time with a **plaintext/stub transport at the
driver edge where DTLS will later slot in** — design that seam as a clean `DatagramChannel`-shaped
boundary so dropping real DTLS in (W4) is a swap, not a rewrite. Target milestone: **two peers exchange
ordered/unordered/lossy data-channel messages end-to-end under virtual time, all platforms.** The full
end-to-end TB fixture with *real* DTLS is the exit gate once W4 lands.

**W4 (`webrtc-dtls`, BoringSSL) is intentionally parked** (user request) — it's the one native dep and a
worse fit for local iteration (Apple/Android runtime-validated on runners). Pick it up in parallel/after
W5; resolve §11.3 (DTLS 1.2-vs-1.3) before it.

**Documented W3 follow-ups (not blockers, tracked in code):** TURN allocation `Refresh` /
permission re-install (RFC 8656 §8/§9 — fine within LIFETIME; a W7-interop concern); explicit
pool-`release`/`use{}` of datagram buffers (entangled with the core's per-retransmit slice ownership) +
webrtc-stun builder intermediates still on `BufferFactory.Default`; IPv6 host-string parsing in
`IceAddress` (fixtures are v4). Mapping `IceFailureReason` into the `SocketException` hierarchy is the
session layer's job (W6).

**Standing traps (unchanged):** `gh pr edit --add-label skip-release` fails silently — apply via
`gh api repos/DitchOoM/webrtc/issues/<n>/labels -f 'labels[]=skip-release'` and verify. Apple lanes are
compile-faithful locally; runtime-validate on the macOS runner (`V6_MAC_VALIDATION`). `git fetch` +
check `origin/main` before reasoning about what's merged.

---

### 2026-07-15 — W3 built end-to-end (steps 1–5), green throughout (landed as #11)

The ICE agent core is done. Branch `w3-webrtc-ice` now carries (on top of the Step-1 seam gate) five
commits building the whole wave. **PR #11 is open, `skip-release` verified, and the full CI matrix is
green** — `build-linux` (JVM/JS/WASM/Android/Linux K/N), **`build-apple` (Apple K/N — runtime-validated
on the macOS runner, `V6_MAC_VALIDATION`)**, all three fuzz lanes, standing-directives, and
validate-artifacts all pass. Nothing is on Central (`skip-release`). **Not merged** (awaiting the
adversarial-review gate / a go).

**What landed (commits after `1d81dfe`):**
1. **Vnet NAT layer** (`webrtc-ice/commonTest/.../vnet/`): the flat `Router` seam became a richer
   `Fabric` (0..n deliveries, rewritten observed source, deferral onto virtual time). `Nat`/`NatBox` =
   the 4 RFC 4787 profiles (mapping × filtering); a virtual `TurnServer` + `StunServer` bound as
   ordinary endpoints; a seeded `Impairment` pipe; `Vnets` topology builders (`flat`, `behindNats`,
   `meetup`, `flatImpaired`). NAT-model property tests prove each profile filters per its definition.
2. **Type model + sans-io core** (`commonMain`): `IceCandidate`/priority/`Foundation`,
   `CandidatePair`/pair-priority (ULong), `IceRole`/`TieBreaker`/`IceCredentials`, `IceAttributes`,
   and **`IceAgent`** — `handle(event,now)` + `nextDeadline(now)`, no clock/RNG/IO inside; checklist
   FSM, triggered checks, nomination, RFC 7675 consent, role conflict, restart. Seeded `Random`.
3. **Connectivity checks** reuse the W1 STUN client (`StunMessageBuilder` + `StunTransaction`); ICE
   attrs (PRIORITY/USE-CANDIDATE/ICE-CONTROLL*) built on the additive public
   `RawAttribute.ofRaw` / `ofXorAddress` I added to `webrtc-stun` (apiDump'd).
4. **Gathering drivers + trickle** (`commonMain`): `gatherServerReflexive` (srflx), `TurnAllocation`
   (a full RFC 8656 relay client presented **as a `DatagramChannel`** — Allocate/401/CreatePermission/
   Send/Data — so relay complexity stays out of the core), `NetworkMonitor`/`MdnsResolver` seams.
   The `IceDriver` test harness drives one `handle`-loop per agent over the vnet; all intake flows
   through one inbox so **trickle + restart just work**.
5. **Fixtures + fuzz** (`commonTest`): host-to-host, role-conflict, full-cone srflx hole-punch,
   **dual-symmetric-NAT → relay**, candidate-flap, `NetworkId`-restart, consent-expiry, `AllPairsFailed`;
   RFC priority/foundation conformance; pinned-seed fuzz (loss+jitter liveness, deterministic replay,
   every-profile-terminates).

**Core bug caught + fixed with its fixture (directive #5):** consent expiry used strict `>` while
`nextDeadline` armed exactly `lastResponse+consentTimeout` → the driver spun without advancing virtual
time. Now `>=`; `consent_expiry_fails_...` is the regression.

**Adversarial review gate — DONE (5 parallel reviewers), all confirmed defects fixed with regression
fixtures** (commits `48a5330` core-A, `333798e` drivers-B, `c97294b` buffer-C on the branch):
- **Role-conflict comparison was INVERTED** in the Controlled branch (RFC 8445 §7.3.1.1: larger
  tie-breaker → controlling in both directions) — controlled-vs-controlled glare thrashed. Fixed +
  one-shot resolution latch + pacing re-arm on a 487 retry (a pair re-entering Waiting on an idle
  checklist was never rescheduled — a second bug the glare fixture caught).
- **Three liveness hangs** closed by a global `establishmentTimeout` failsafe: nomination-check failure
  on the sole valid pair, controlled peer that never nominates, and zero-compatible-pairs (now emits the
  previously-dead `NoCandidatePairs`). `nominationInFlight` wedge fixed + on-timer nomination retry.
- **MI-splice** (RFC 8489 §14.5): checks read only `attributesCoveredByMessageIntegrity()`.
- `pruneRedundant` state-aware; `selectPair` no Completed-regression; consent expiry clears its tx.
- Driver/vnet: `select` drive loop (no lost trickled candidate); `close()` unbinds the vnet endpoint
  (flap frees it; no false delivery/leak); vnet TURN server validates REALM/NONCE like coturn (the relay
  fixtures now exercise TurnAllocation's full 401 challenge); srflx gather retransmits; `toTransportAddress`
  typed-rejects non-v4.
- **Directive #6 (BufferFactory):** injectable end-to-end (agent uses `config.bufferFactory` for all
  datagrams); `BufferLifecycleTest` proves pool-injectability + steady RSS (no per-tick leak).

Reviewer notes verified CLEAN (no change): priority/pair-priority arithmetic, pacing/consent spin
guards, MI keying direction, USERNAME handling, unsigned tie-breaker, MI/FINGERPRINT ordering, T0
throw-safety, the impairment RNG stream, and the NAT profiles' RFC 4787 fidelity.

**Next-session TODO to finish the wave:**
- PR #11 is open, `skip-release` **verified present**, CI green incl. Apple. Re-push the review-fix
  commits (done) and let CI re-run; keep unmerged until a maintainer says go.
- **Remaining directive-#6 follow-ups (documented in code):** explicit pool `release`/`use{}` of the
  datagram buffers is entangled with the core's per-retransmit slice ownership, and webrtc-stun's
  builder intermediates still use `BufferFactory.Default` — both are a scoped later refactor.
- **TURN Refresh / permission re-install** (RFC 8656 §8/§9) not yet implemented (fine within LIFETIME;
  the vnet models no expiry) — a W7-interop follow-up. TurnAllocation collections are single-dispatcher.

**Known simplifications to revisit (not blockers, noted in code):** the frozen algorithm is
"lite" (highest-priority-first pacing rather than per-foundation unfreezing); srflx/relay **gathering
has no STUN retransmit** yet (fine on the vnet; add before real-network W7); `IceFailureReason.NoCandidatePairs`
is defined but reserved for the trickle end-of-candidates signal (W6 signaling); IPv6 host-string
parsing in `IceAddress` is a follow-up (fixtures are v4); TURN auth is short-term-credential MI
(MD5-free) — real-coturn long-term keys are a W7 concern.

**Module structure (a question raised this session):** no client/server split is needed for the ICE
agent — it is symmetric peer code (controlling/controlled is a runtime role, not a module). The only
"server" components (the virtual STUN/TURN servers) are **`commonTest`-only** and never ship; if a real
TURN-server product ever appears it belongs in `webrtc-testsuite` (W7), depending only on `webrtc-stun`.
The module graph already keeps peers free of server code.

### 2026-07-15 update — Step 1 (wire socket + prove the seam) DONE; a premise correction

The seam gate the last session named ("prove a two-peer datagram echo over the vnet under `runTest`,
all platforms, before writing any ICE") is **green** — JVM, JS-Node, wasmJs-Node, Linux/native, Android
host. What landed (all on the W3 branch, unmerged):
- **buffer bumped 6.10.0 → 6.11.0** (on Central) — carries the buffer-flow **datagram trichotomy**
  (`DatagramChannel`/`DatagramSource`/`DatagramSink` + `SocketAddress`, `@ExperimentalDatagramApi`),
  which is **the UDP seam webrtc rides**. Merged codecs (stun/sdp/sctp) re-tested green on 6.11.0.
- **socket wired into the catalog** — `socket = "3.11.0"` + `socket-udp` lib, resolved from **Maven
  Central**. socket-udp 3.11.0 (PR #239) landed on Central mid-session (`20260715152514`) with all of
  jvm/android/js/linux/**apple**, pinning buffer 6.11.0 — so **the merge-gate is lifted**: the pin is a
  release (not a `publishToMavenLocal` snapshot) and `mavenLocal()` was removed from the convention.
  Validated with `--refresh-dependencies` + mavenLocal gone: resolves and the real-UDP jvmTest passes.
- **webrtc's own vnet** (`webrtc-ice/src/commonTest/.../vnet/Vnet.kt`) — an in-memory `DatagramChannel`
  (flat router now; `Router` seam for NAT/impairment later) + `CountingBufferFactory`. Tests:
  `VnetDatagramSeamTest` (virtual-time echo, boundaries, drop-to-void, all platforms) +
  `RealUdpSocketSeamTest` (jvmTest: real loopback `UdpSocket` echo — proves the snapshot pin resolves and
  the real actual honors the same seam the vnet implements).

**Premise correction (important, verified against socket `origin/main` + buffer `origin/main`):** the
last session's "socket ships the deterministic vnet/sim harness (#225), so webrtc consumes it" is **not
usable as stated**. Socket's #225 sim is **QUIC-specific, lives in unpublished test source sets**
(`socket-quic-quiche/src/{commonTest,jvmTest}`: `TimelineUdpChannel`/`ImpairedPipe`/`SimClock`/
`runQuicSim`), drives the **internal quiche `UdpChannel`** seam (not the public `DatagramChannel`), and
models **no NAT/TURN/topology**. `:socket-testsuite` can't be published without the whole
quiche/rust/BoringSSL stack. **So the vnet is webrtc's own** — which is exactly what RFC §5.2 already
says ("the vnet — the WebRTC-specific addition"). §11.1's "sim lives in socket" is only half-true: the
*virtual-time pattern* (`SimClock(testScheduler)` + `runTest`) is socket's reference; the *UDP vnet with
NAT models* is ours to build. socket-udp remains the **real-socket actual** consumed at the
platform-edge gathering driver only (it has **no wasm/browser** target — RFC §1.1 — so it never enters a
common/core/wasm source set; the core targets buffer-flow's interface).

**§11.4 (mDNS) resolved** in the EXECUTION_PLAN decision log: resolve-only in W3, responder deferred
behind a flag; resolution rides an injected `MdnsResolver` seam (deterministic stub in tests).

**Next (Step 2 = W3 proper):** the sans-io ICE agent core + gathering drivers + trickle + NAT vnet
fixtures + fuzz. Single session-chain, do **not** fan out the core. See the ORIGINAL recommendation
below (still accurate) for the ICE scope.

### START HERE — the ICE agent core (fresh session)

State: branch **`w3-webrtc-ice`** (2 commits, clean tree, green on all local lanes). socket-udp is a
plain Central dep now (`3.11.0`); nothing is merge-gated. Build order (each step green-throughout):

1. **Vnet NAT layer** — extend `webrtc-ice/src/commonTest/.../vnet/Vnet.kt`. The `Router` fun-interface
   seam is already there (`route(from, to): SocketAddress?`, `null` = drop). Add the four NAT profiles
   (full-cone / address-restricted / port-restricted / symmetric: each a small pure map of
   internal↔external mappings + a per-direction filter), a virtual TURN server (Allocate/Send/Data via
   the W1 TURN codec), and seeded impairment (loss/reorder/dup/delay — copy socket's `ImpairedPipe`
   shape: one `Random(seed)`, a fixed draw count per datagram; delay via `delay()` so `runTest` drives
   it). Topologies-as-data builders. Keep the flat `DirectRouter` for unit tests.
2. **ICE type model + sans-io core** — `Ice.kt` already has `Ufrag`/`IcePassword`/`IceFailureReason`.
   Add `Candidate`(host/srflx/relay/prflx, `TransportAddress`, foundation, component, priority),
   `CandidatePair` + RFC 8445 priority (§5.7.2) / foundation / pair-priority formulas, the checklist
   FSM (`handle(event, now): List<Output>` + `nextDeadline(now): Instant?`, NO clock/random/IO inside),
   triggered checks, nomination (regular), RFC 7675 keepalive/consent, restart. **Seeded `Random` from
   day one** (directive #2) for tie-breaker / ufrag / pwd / foundations.
3. **Connectivity checks reuse the W1 STUN client** (`webrtc-stun`, already a dep). Shape:
   `StunMessageBuilder.of(StunClass.Request, StunMethod.Binding, TransactionId.random(rng)).add(attr)
   .addMessageIntegrity(keyBuf).addFingerprint().encode(factory)`; decode via `StunMessage.decode(buf)`;
   retransmit via `StunTransaction(txId, requestBuf, policy).handle(event, now)/nextDeadline()`.
   **GOTCHA:** the ICE STUN attributes (PRIORITY `0x0024`, USE-CANDIDATE `0x0025`, ICE-CONTROLLED
   `0x8029`, ICE-CONTROLLING `0x802A`) are **not** in webrtc-stun's typed set, and
   `RawAttribute.Companion.ofValue(type, ReadBuffer)` is **`internal`**. So either (a) add a public
   `RawAttribute.Companion.ofRaw(type, ReadBuffer)` escape-hatch to webrtc-stun (additive → `apiDump`),
   or (b) define the ICE-attr builders inside webrtc-stun like the TURN ones. `StunAttributeType(short)`
   ctor is public, so `StunAttributeType(0x0024)` is fine. Recommend (a).
4. **Gathering drivers + trickle (RFC 8838)** over injected `DatagramChannel` (buffer-flow) +
   `NetworkMonitor` (lives in socket **core** `com.ditchoom:socket`, NOT socket-udp — add that dep at
   the driver edge, or define a thin `NetworkMonitor`-shaped seam webrtc owns) + `MdnsResolver` seam.
   Real `UdpSocket.bind()` is the production channel (jvm/native/apple/android only — no wasm).
5. **Canonical fixtures + fuzz + PR** — dual-symmetric-NAT→relay, candidate-flap mid-check,
   NetworkId-change→restart, all under `runTest`; ICE invariants in the fuzz set; typed `IceFailureReason`
   complete; `apiDump`; CHANGELOG; PR with `skip-release` (apply via REST API — `gh pr edit` fails
   silently here). Do not fan out the core.

Seam facts (verified, don't re-explore): the datagram API is `com.ditchoom.buffer.flow.*` under
`@ExperimentalDatagramApi` (`DatagramChannel`=Source+Sink, `receive()→DatagramReadResult.Received|Closed`,
`send(payload, to?, opts)`, `SocketAddress.ofLiteral(ip,port)` / `.resolve`). `runTest` + coroutines-test
is wired into `webrtc-ice` commonTest. Full detail in the `webrtc-socket-udp-vnet-reality` memory.

---

## Prior framing (still accurate for the ICE scope): **pure-codec track COMPLETE; transport track UNBLOCKED for dev**

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

### Transport prerequisites: they now EXIST in socket (W2 is NOT a webrtc wave)
The pure codecs (stun/sdp/sctp) were buildable and testable **without any I/O**. Everything remaining —
W3 (ice), W4 (dtls), the rest of W5 (SCTP association + `DataChannel`), the rest of W6
(`PeerConnection`), W7 (harness) — needs the **transport seam**: an unconnected, deterministic UDP
`DatagramChannel` in `commonMain` runnable under `runTest`. **That seam and the deterministic vnet are
now merged in the socket sibling** (`../git/socket`), so webrtc **consumes** them rather than building
its own — W2 (vnet) is a socket/simulation deliverable, not a webrtc wave:
- **`socket-udp` module** — `UdpSocket` in `commonMain` (the `DatagramChannel` seam). Merged to socket
  `main` in **PR #239** ("published UDP datagram module + QUIC datapath cutover"), 2026-07-15.
- **Deterministic network simulation / vnet + trace-replay + consumer harness** — merged earlier in
  socket **#225**; this is the W2 NAT-modeling vnet webrtc's TA/TB tiers run against.

**Publish status (confirmed 2026-07-15):** `socket-udp` is **NOT on Central yet** — the latest published
socket was **3.10.1** at the start of this session (`socket-udp` maven-metadata → HTTP 404, #239's first
deploy failed). **RESOLVED 2026-07-15:** socket-udp **3.11.0 is now on Central** (all targets incl.
Apple, pins buffer 6.11.0) — the catalog pins the release and the merge-gate is **lifted** (see the
top-of-doc W3 update). Historical consequences that no longer bind:
- ~~Dev unblocked against a local socket `publishToMavenLocal`~~ → now a plain Central dependency.
- ~~Merge gated on an unpublished socket~~ → lifted; `socket = "3.11.0"`, `mavenLocal()` removed.
- Open cross-repo decisions to settle as W3/W4 start: §11.3 (DTLS 1.2-vs-1.3, before W4). §11.4 (mDNS)
  is now **resolved** (resolve-only in W3 — EXECUTION_PLAN decision log). §11.1 (sim home): the
  virtual-time *pattern* lives in socket, but the UDP vnet + NAT models are **webrtc's own** (RFC §5.2)
  — see the premise correction above.

### Recommended next webrtc wave: **W3 (`webrtc-ice`)**
The first integration point (a single-session chain — do NOT fan out the core). Sans-io agent core
(candidate pairing, checklist scheduling, triggered checks, nomination, keepalive/consent RFC 7675,
restart) + gathering drivers (host + srflx via the W1 STUN client + relay/TURN + mDNS resolve-only)
over the socket `DatagramChannel`/`NetworkMonitor`; trickle (RFC 8838) via the signaling seam; seeded
`Random` for tie-breaker/ufrag/pwd/foundations. Exit: canonical vnet fixtures under virtual time
(dual-symmetric-NAT→relay, candidate-flap, `NetworkId`-change→restart) + typed `IceFailureReason` +
ICE state invariants in the fuzz set. **First step before the FSM:** wire socket into the catalog and
prove the seam from webrtc `commonTest` — a two-peer datagram echo over the vnet under `runTest`, all
platforms. W4 (`webrtc-dtls`, BoringSSL) is parallelizable but is the one native dep (Apple/Android
runtime-validated on runners) — a worse fit for local iteration.

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

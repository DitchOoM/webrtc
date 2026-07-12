# Testing strategy — `com.ditchoom:webrtc`

How this library is tested, end to end. The unit-level tiers are specified in `RFC_KMP_WEBRTC.md` §7;
this document is the operational companion — it makes the **integration, interop, and harness** layers
concrete and states what each wave must ship. It extends, and reuses wholesale, socket's
`TESTING_STRATEGY.md` (the container harness, `scenario = port`, the arch-matched CI matrix, Colima on
macOS) rather than reinventing them.

The organizing idea: **because every protocol core is sans-io and caller-clocked, the bulk of what
would normally be flaky, live-network integration testing collapses into deterministic, hermetic tests
that run under virtual time on every platform.** Foreign-peer interop still exists — but it *finds*
bugs, it does not *own the regression corpus*. Every bug it finds is demoted into a deterministic
fixture (§6). That inverts the usual WebRTC testing pyramid, where the integration tier is the flaky
part you can never fully trust.

---

## 1. Tier reference

| Tier | What | Where it runs | Deterministic? | Wave |
|---|---|---|---|---|
| **T0 — codec floor** | round-trip + property tests + committed malformed corpus for STUN/SDP/SCTP parsers; parse-fail is a typed reject, never a throw-through/crash | commonTest, all platforms | yes | W1/W5/W6 |
| **T0′ — coverage-guided fuzz** | Jazzer over the pure-Kotlin parsers (real JVM-bytecode coverage feedback) | jvmTest, time-boxed CI | seeded | W1+ |
| **TA — timeline replay** | fixtures + seeded fuzz + ddmin shrinker over vnet/stub seams, virtual time | commonTest, all platforms | yes | W3+ |
| **TB — real-stack vnet** | full native stack (real BoringSSL) through simulated NATs/impairment; strict trace-prefix invariants, RNG drift bounded | commonTest, native + JVM | yes (±1-datagram RNG drift bound) | W5 |
| **Integration** | container harness: coturn, NAT-profile containers (iptables), netem impairment, toxiproxy on signaling | harness CI job, arch-matched matrix | no (real OS net) | W7 |
| **Interop** | our stack ⇄ Pion echo peer; our stack ⇄ headless Chrome (`RTCPeerConnection`) via Karma | harness CI job | scripted signaling | W7 |
| **Consumer** | published `webrtc-testsuite`: `withWebRtcHarness { … }` from a clean checkout | consumers' commonTest | per-scenario | W7 |
| **Benchmarks** | kotlinx-benchmark in `src/commonBenchmark/kotlin`; parse / crypto ops-per-sec, tracked in `PERFORMANCE.md` | on demand + release | n/a | per module |

T0–TB are unit-to-integration on a single machine with no Docker. Integration/Interop/Consumer need the
harness. The split matters for CI gating (§7).

---

## 2. The four integration layers

### L1 — Real-stack over the vnet (the workhorse) · tier TB
The whole point of sans-io. The complete stack — real BoringSSL DTLS + pure-Kotlin SCTP + the ICE agent
— composes and runs **end to end through a simulated NAT topology under `runTest` virtual time, in
`commonTest`, on every platform**. Two of our own peers establish a PeerConnection and exchange
ordered/unordered/lossy data-channel messages; the run asserts golden state trajectories (ICE pair
states, DTLS state, SCTP cwnd/RTO, buffer accounting), not just "it didn't crash."

- Hermetic: no sockets, no Docker, no wall-clock. A 90-second field ICE saga replays in milliseconds.
- The vnet implements the **same `DatagramChannel` seam** production uses, so this is the real stack,
  not a mock of it — the only substitution is the packet/clock plumbing beneath ICE.
- The only real-time residue is BoringSSL's RNG shaping ClientHello bytes — bounded explicitly as the
  same ±1-datagram drift the QUIC work already characterizes (Tier-B discipline).

This is where the majority of cross-layer bugs are caught and kept. Lands in **W5**.

### L2 — Container harness over a real OS network · tier Integration
The vnet models NAT; real kernels have quirks a model can't. We extend socket's `test-harness/`
docker-compose stack (existing services: `echo`, `http`, `toxiproxy`, `controller`, `netem`,
`socketnet` bridge; design principle **scenario = port**) with WebRTC services:

| New service | Purpose |
|---|---|
| **coturn** | real STUN/TURN — srflx + relay candidate gathering, TURN allocations/refresh |
| **NAT-profile containers** | iptables/netfilter cones: full-cone / address-restricted / port-restricted / symmetric; hairpinning on/off |
| **netem profiles** | loss / delay / jitter / reorder on the data path (reuse the existing netem control shim) |
| **toxiproxy on signaling** | deterministic signaling-channel faults (drop/delay offer/answer/candidate) |

The controller's `/describe` gains WebRTC entries so every platform discovers endpoints uniformly.
Runs on the arch-matched matrix (no QEMU), Colima on macOS. **W7** (container work can start earlier).

### L3 — Interop with foreign peers · tier Interop
Borrow *other implementations* as the correctness oracle. Signaling is a seam, so the offer/answer
exchange is scripted — interop runs are reproducible, not flaky live-network tests.

- **our stack ⇄ Pion** (Go WebRTC) — an independent, widely-deployed stack, containerized as an echo
  peer. Interop with Pion ⇒ our wire format is correct.
- **our JVM/native stack ⇄ headless Chrome** via Karma driving real `RTCPeerConnection` — interop with
  the dominant browser stack, and simultaneously the test for our own browser delegation
  (`peerConnectionSupport()`).

Note the browser-reachability constraints socket already documented apply: a Karma browser can drive
`RTCPeerConnection` against our JVM peer on the same runner (`127.0.0.1`), no `host.docker.internal`
gymnastics on Linux CI. **W6/W7.**

### L4 — Consumer smoke · tier Consumer
The published `webrtc-testsuite`:

```kotlin
withWebRtcHarness {
    natType(Symmetric)
    relayOnly()
    impaired(loss = 5.percent) { /* plain commonTest, no docker CLI */ }
}
```

consumed from a clean checkout and wired into `validate-artifacts` from its first release (the socket
#188 lesson: every published artifact goes through the release loop). **W7.**

---

## 3. External suites & vectors we adopt

There is no turnkey "WebRTC conformance suite" for a non-browser native stack. We assemble one from
strong reusable pieces:

| Resource | Gives us | Plugs into | Wave |
|---|---|---|---|
| **RFC 5769** sample STUN vectors | canonical MESSAGE-INTEGRITY / FINGERPRINT test messages — an interop-grade codec corpus on day one | `webrtc-stun` T0 | W1 |
| **RFC 8445 / 8489 / 8656 / 8831 / 8832** scenarios | ICE / STUN / TURN / SCTP / DCEP behaviors, encoded as committed timeline fixtures | L1 vnet, TA/TB | W3/W5 |
| **Pion** (Go WebRTC) | independent interop oracle; echo-peer container | L3 | W7 |
| **Headless Chrome + Karma** | real `RTCPeerConnection` peer; also validates browser delegation | L3 | W6/W7 |
| **coturn** | real STUN/TURN server | L2 | W7 |
| **web-platform-tests `webrtc/`** | W3C conformance for the JS API surface | browser-delegated target only | W6 |
| **BoringSSL test runner** | DTLS handshake conformance (kept upstream) | `webrtc-dtls` | W4 |

Deliberately **not** used: **KITE** (Google's interop framework — browser-to-browser oriented, overkill
for a native stack); a formal **SDP conformance suite** (none exists — SDP gets a hand corpus + Jazzer
fuzz at the same rigor as the binary codecs).

---

## 4. Standing invariants (asserted across TA/TB/fuzz — RFC §5.3)

Every timeline replay and fuzz campaign asserts, not just crash-freedom:

1. **No buffer leaks** — `TrackingBufferFactory.assertNoLeaks()` in every harness.
2. **No illegal state transition** — ICE pair/checklist and `PeerConnectionState` never take an illegal edge.
3. **Every native handle freed** — every DTLS wrapper freed, every TURN allocation released.
4. **Errors are typed** — surface as sealed reasons, never strings.
5. **Liveness** — the session reaches Connected or a typed terminal failure; it never hangs.
6. **SCTP ordering** — no message reordered within a stream, no unacked data dropped, DCEP converges.

Assertion discipline (carried from socket): assert **observable state + a watchdog**, never wall-clock
budgets; `scenario = port`; skip-on-unreachable probes for off-CI harness runs; wrapper-transparency
(everything works when handed a `PooledBuffer`/`TrackedSlice`, not just a raw `PlatformBuffer`).

---

## 5. Determinism & the demote-to-fixture rule

The corpus is append-only, and it grows *from the flaky layers inward*:

> Every bug found at L2 (harness), L3 (interop), or in the field becomes a committed **L1 timeline
> fixture** in the same PR that fixes it (standing directive #5).

A field bundle from a debug app build — captured by `TraceRecorder` tapping the `DatagramChannel`
decorator, the state `StateFlow`s, and the signaling seam — *is* the bug report *is* the regression
test. So a symmetric-NAT-relay failure that first showed up against Chrome gets replayed forever under
virtual time on every platform, and never flakes again. **Interop finds bugs; the vnet owns the
regressions.**

---

## 6. CI gating

Mirror socket's split so the fast path stays fast:

- **`review.yaml` (every PR)** — deterministic tiers only (T0/T0′/TA/TB + the standing-directive greps
  + `apiCheck`). No Docker. This is the bulk of coverage and it is hermetic, so it gates every PR.
- **Harness job** — brings the compose stack up (coturn, NAT profiles, netem, toxiproxy) and runs the
  L2 integration + L4 consumer scenarios against `127.0.0.1`. Arch-matched matrix, `--wait` on
  healthchecks to kill readiness flakes.
- **Interop job** — L3: our stack ⇄ Pion, our stack ⇄ Chrome/Karma.

Because the harness no longer depends on flaky public hosts, the integration job can run on every PR,
not just labeled ones.

---

## 7. Per-wave testing deliverables (exit criteria)

Each wave lands green on all lanes before the next starts (green-throughout rule). The testing artifact
each wave must ship:

| Wave | Testing deliverable |
|---|---|
| **W1 `webrtc-stun`** | T0 round-trip + **RFC 5769 vectors** + malformed corpus; Jazzer lane wired with seed corpus; wrapper-transparency tests |
| **W2 vnet** | NAT-model property tests (each NAT type provably filters per its definition); two-peer echo over each topology under virtual time |
| **W3 `webrtc-ice`** | canonical TA fixtures (dual-symmetric-NAT→relay, candidate-flap, `NetworkId` change→restart); timeline fuzz smoke + JVM deep-run with shrinker; ICE invariants in the fuzz set |
| **W4 `webrtc-dtls`** | handshake between two of our stacks over the vnet under virtual time (RNG-drift bound asserted); dropped-flight retransmission fixture; wrapper-free invariant; Apple/Android runtime-validated on runners |
| **W5 `webrtc-sctp`+DC** | **end-to-end TB**: two full stacks (ICE+DTLS+SCTP) over dual-NAT vnet exchange ordered/unordered/lossy messages under virtual time, all platforms; SCTP invariants in fuzz set; one loop-until-dry fuzz campaign |
| **W6 `webrtc` root** | full API round-trip fixture (signaling scripted); browser target compiles + delegation unit-tested under Karma; wpt `webrtc/` smoke on the browser target |
| **W7 harness/interop** | interop green (our stack ⇄ Pion, ⇄ Chrome establish + exchange data-channel messages in CI); consumer-smoke from clean checkout; `webrtc-testsuite` published + in `validate-artifacts` |

---

## 8. Running it

```bash
# Deterministic tiers (what every PR runs) — no Docker
./gradlew allTests                    # T0/TA/TB across all modules + platforms
./gradlew :webrtc-stun:jvmTest        # one module
# Fuzz (time-boxed) — wired in W1
./gradlew :webrtc-stun:stunHeaderFuzz # example; Jazzer, jvmTest lane

# Harness (L2/L4) — Docker, added in W7
bash test-harness/compose-up-retry.sh coturn nat-symmetric controller
./gradlew jvmTest -PwebrtcHarness=1

# Benchmarks (on demand)
./gradlew :webrtc-stun:jvmBenchmarkBenchmark
```

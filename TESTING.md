# Testing strategy — `com.ditchoom:webrtc`

How this library is tested, end to end. The unit-level tiers are summarized in
[`ARCHITECTURE.md`](./ARCHITECTURE.md) §7; this document is the operational companion — it makes the
**integration, interop and harness** layers concrete. It extends, and reuses wholesale, socket's
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

| Tier | What | Where it runs | Deterministic? |
|---|---|---|---|
| **T0 — codec floor** | round-trip + property tests + committed malformed corpus for STUN/SDP/SCTP parsers; parse-fail is a typed reject, never a throw-through/crash | commonTest, all platforms | yes |
| **T0′ — coverage-guided fuzz** | Jazzer over the pure-Kotlin parsers (real JVM-bytecode coverage feedback) | jvmTest, time-boxed CI | seeded |
| **TA — timeline replay** | fixtures + seeded fuzz + ddmin shrinker over vnet/stub seams, virtual time | commonTest, all platforms | yes |
| **TB — real-stack vnet** | the full production stack (ICE + pure-Kotlin DTLS + SCTP) through simulated NATs/impairment; golden state trajectories, not just crash-freedom | commonTest, all platforms | yes |
| **TP — platform adapter** | the thin actuals the deterministic tiers stub out, against the **real** platform API on the host: `getifaddrs(3)` (`nativeTest`), `java.net.NetworkInterface` + the JDK-21 FFM routing socket (`jvmTest`), and `ConnectivityManager` under Robolectric (`androidHostTest`). Asserts the adapter, never the radio — that a callback reaches our seam, not that a real handoff fires one | jvmTest / nativeTest / androidHostTest | yes (no network I/O) |
| **Integration** | container harness: coturn, NAT-profile containers (iptables), netem impairment, toxiproxy on signaling | harness CI job, arch-matched matrix | no (real OS net) |
| **Interop** | our stack ⇄ Pion, werift, Chrome, Firefox and WebKit — establishment **and** the data-channel semantics sequence | harness CI job | scripted signaling |
| **Consumer** | `.ci/consumer-smoke` — a standalone build declaring `com.ditchoom:webrtc` + `webrtc-testsuite` by coordinate, compiled + K/N-linked + run (`withWebRtcHarness { natType(); relayOnly(); impaired() }`) against a **cold** resolve of the merged maven-local repo (pre-publish) and of **Maven Central** (post-release) | `consumer-smoke.yaml`, Linux + macOS hosts | yes (virtual time) |
| **Benchmarks** | kotlinx-benchmark in `src/commonBenchmark/kotlin`; parse / crypto ops-per-sec, tracked in `PERFORMANCE.md` | on demand + release | n/a |

T0–TB are unit-to-integration on a single machine with no Docker. Integration/Interop/Consumer need the
harness. The split matters for CI gating (§6).

---

## 2. The four integration layers

### L1 — Real-stack over the vnet (the workhorse) · tier TB
The whole point of sans-io. The complete stack — ICE agent + pure-Kotlin DTLS + pure-Kotlin SCTP —
composes and runs **end to end through a simulated NAT topology under `runTest` virtual time, in
`commonTest`, on every platform**. Two of our own peers establish a PeerConnection and exchange
ordered/unordered/lossy data-channel messages; the run asserts golden state trajectories (ICE pair
states, DTLS state, SCTP cwnd/RTO, buffer accounting), not just "it didn't crash."

- Hermetic: no sockets, no Docker, no wall-clock. A 90-second field ICE saga replays in milliseconds.
- The vnet implements the **same `AddressedDatagramChannel` seam** production uses, so this is the real
  stack, not a mock of it — the only substitution is the packet/clock plumbing beneath ICE.
- There is no real-time residue at all: every core is caller-clocked and every source of entropy is
  injected, DTLS included, so a run is byte-identical from its seed.

This is where the majority of cross-layer bugs are caught and kept.

### L2 — Container harness over a real OS network · tier Integration
The vnet models NAT; real kernels have quirks a model can't. We extend socket's `test-harness/`
docker-compose stack (existing services: `echo`, `http`, `toxiproxy`, `controller`, `netem`,
`socketnet` bridge; design principle **scenario = port**) with WebRTC services:

| New service | Purpose |
|---|---|
| **coturn** | a real STUN/TURN server, with `lt-cred-mech` enforced — the relay lanes authenticate for real, so a wrong long-term-key derivation fails them (§3) |
| **NAT-profile containers** | iptables/netfilter cones: full-cone / address-restricted / port-restricted / symmetric; hairpinning on/off |
| **netem profiles** | loss / delay / jitter / reorder on the data path (reuse the existing netem control shim) |
| **toxiproxy on signaling** | deterministic signaling-channel faults (drop/delay offer/answer/candidate) |

The controller's `/describe` gains WebRTC entries so every platform discovers endpoints uniformly.
Runs on the arch-matched matrix (no QEMU), Colima on macOS.

### L1 ↔ L2 parity matrix

L2 (Docker) is Linux-only by nature — it drives real coturn / Pion / browsers over a real kernel
network. Every L2 *network* scenario (NAT topology × IP family × policy — the peer-implementation axis
`native/jvm/pion/chrome/firefox/webkit` is an interop concern, not a network one) has a deterministic
L1 vnet fixture that reproduces the **same traversal outcome** under `runTest` virtual time, so
**macOS / iOS-sim / Node / wasm / Android inherit the full NAT-traversal + TURN(v4/v6) + dual-stack
story** that only Linux can prove on the real wire. The vnet is the source of truth; L2 is the oracle
that keeps it honest (§5).

| L2 scenario | family | L1 vnet fixture | Traversal proven |
|---|---|---|---|
| `full-cone` | v4 | `IceNatFixtureTest.full_cone_peers_connect_via_server_reflexive` | srflx hole-punch |
| `port-restricted` / `address-restricted` | v4 | `VnetNatTest` (`hole_punch…`, `port_restricted…`, `address_restricted…`) | filtered srflx |
| `symmetric-relay` | v4 | `IceNatFixtureTest.dual_symmetric_nats_connect_only_via_relay` | forced relay (mapping) |
| `mixed-sym-port` | v4 | `IceNatFixtureTest.mixed_symmetric_and_port_restricted_peers_fall_back_to_relay` | forced relay (mixed) |
| `relay-only` | v4 | `VnetTurnRelayTest.symmetric_peers_relay_a_round_trip_through_turn` | TURN relay round-trip |
| `impaired-loss-delay` | v4 | `IceRelayLossTest` · `IceConsent/Nomination/RestartLossTest` · `VnetImpairmentTest` | loss/delay/reorder (seeded) |
| `full-cone` / `port-restricted` | **v6** | `IceV6TraversalTest.port_restricted_v6_peers_connect_directly_by_hole_punching` | routed-v6 direct hole-punch |
| `firewall-relay6` | **v6** | `IceV6TraversalTest.firewall_forces_a_v6_relay_when_direct_is_blocked` + `VnetTurnRelayV6Test` (Allocate family) | v6 network-forced relay discovery |
| dual-stack preference | **dual** | `IceDualStackTest.dual_stack_agents_select_the_ipv6_pair` | RFC 6724 v6-preferred |
| dual-stack fallback | **dual** | `IceDualStackNatTest.a_broken_v6_path_falls_back_to_the_v4_server_reflexive_pair` | happy-eyeballs v6→v4 |
| RFC 6724 / 8445 priority | — | `IcePriorityTest` (family precedence + pair-priority arithmetic) | candidate/pair ordering |

The vnet models routed IPv6 exactly as the harness does — **no NAT66**, a pure RFC 4787 §5 filtering
router (`RoutedFilter`) or the `firewall-relay6` administrative firewall (`RoutedFirewall`), with
`FamilyFabric` carrying a broken-v6 + working-v4 stack in one vnet for the fallback case.
Harness-only failures (a peer's v6 signaling-bind, a browser CLAT shim, a log double-read) are **not**
stack bugs and correctly have no fixture. cgnat / hairpin (v4-only carrier-NAT / NAT444) are a
documented follow-up — they need NAT-*chaining* in the vnet fabric, tracked separately.

### L3 — Interop with foreign peers · tier Interop
Borrow *other implementations* as the correctness oracle. Signaling is a seam, so the offer/answer
exchange is scripted — interop runs are reproducible, not flaky live-network tests.

- **our stack ⇄ Pion** (Go WebRTC) — an independent, widely-deployed stack, containerized as an echo
  peer. Interop with Pion ⇒ our wire format is correct.
- **our stack ⇄ Chrome, Firefox and WebKit**, driven through Playwright against real
  `RTCPeerConnection`s — interop with every shipping browser engine, and simultaneously the check on our
  own browser delegation (`peerConnectionSupport()`).
- **our stack ⇄ werift** (TypeScript/Node WebRTC) — a fourth independent implementation.

Note the browser-reachability constraints socket already documented apply: a browser can drive
`RTCPeerConnection` against our peer on the same runner, with no `host.docker.internal` gymnastics on
Linux CI.

**Data-channel semantics, not just establishment.** A green interop lane proving one `ping`→`pong` proves
ICE + DTLS + SCTP INIT + one DCEP OPEN — and nothing about the semantics the library implements. So every
lane additionally runs an offerer-driven phase sequence over the same association: fragmentation +
reassembly of a message far past one MTU (byte-identity checked, sized against the peer's advertised
`a=max-message-size` **and** probed at exactly that ceiling), unordered delivery, PR-SCTP with its
FORWARD-TSN no-wedge property, three multiplexed channels with mixed profiles, a reverse-direction channel
(our lanes only), a **per-channel close** (RFC 8831 §6.7 stream reset: one channel closed mid-session while
its neighbour keeps echoing, the peer's own half reset — observed as the stream id coming back — and the
recycled id reopened and used), and finally a graceful association SHUTDOWN. Its L1 siblings are
`DataChannelCloseTest` (bare stack pair) and
`PeerConnectionRoundTripTest.closing_one_channel_keeps_its_neighbour_and_recycles_the_stream_id` (whole
stack over the vnet). The answerer stays a scenario-agnostic **reflector**
in every family — echo every message back on the channel it arrived on — because the binding constraint is
the browser, where nothing beyond the W3C API can be injected; every assertion therefore lives on our side.
Honest limits: a clean path rarely reorders and never abandons, so s2/s3 prove *negotiation* there and get
their real proofs on the impaired lane, with the deterministic vnet suites remaining the hard gate for both.
See `test-harness/README.md` and `docs/DC_SEMANTICS_INTEROP_DESIGN.md`.

### L4 — Consumer smoke · tier Consumer
The published `webrtc-testsuite`:

```kotlin
runTest {
    withWebRtcHarness(scope = backgroundScope, clock = virtualClock) {
        natType(NatType.Symmetric)     // both peers behind a symmetric NAT (RFC 4787)
        relayOnly()                    // force the TURN-relay path
        impaired(loss = 0.05)          // 5% packet loss — plain commonTest, no docker CLI
        assertEquals("ping", roundTrip("ping"))
    }
}
```

consumed from a clean checkout and wired into `validate-artifacts` from its first release (the socket
#188 lesson: every published artifact goes through the release loop).

---

## 3. External suites & vectors we adopt

There is no turnkey "WebRTC conformance suite" for a non-browser native stack. We assemble one from
strong reusable pieces:

| Resource | Gives us | Plugs into |
|---|---|---|
| **RFC 5769** sample STUN vectors | canonical MESSAGE-INTEGRITY / FINGERPRINT test messages — an interop-grade codec corpus on day one. §2.4 (long-term auth) additionally pins `MD5(user:realm:pass)` key derivation against a published vector | `webrtc-stun` T0 |
| **RFC 8445 / 8489 / 8656 / 8831 / 8832** scenarios | ICE / STUN / TURN / SCTP / DCEP behaviors, encoded as committed timeline fixtures | L1 vnet, TA/TB |
| **Pion** (Go WebRTC) | independent interop oracle; echo-peer container | L3 |
| **Chrome, Firefox, WebKit** (Playwright) | real `RTCPeerConnection` peers across all three engines; also validates our browser delegation | L3 |
| **coturn** | real STUN/TURN server, with `lt-cred-mech` enforced — the relay lanes authenticate with the RFC 8489 §9.2.2 long-term key, so a wrong derivation fails them | L2 |
| **web-platform-tests `webrtc/`** | W3C conformance for the JS API surface | browser-delegated target only |
| **BoringSSL** | the differential oracle our pure-Kotlin DTLS handshakes against, both directions, under `linuxTest` | `webrtc-dtls` |

Deliberately **not** used: **KITE** (Google's interop framework — browser-to-browser oriented, overkill
for a native stack); a formal **SDP conformance suite** (none exists — SDP gets a hand corpus + Jazzer
fuzz at the same rigor as the binary codecs).

---

## 4. Standing invariants (asserted across TA/TB/fuzz — ARCHITECTURE §5.3)

Every timeline replay and fuzz campaign asserts, not just crash-freedom:

1. **No buffer leaks** — `LeakTrackingFactory.assertNoLeaks()`, which tracks frees as well as
   allocations. Stated here as the standard, **not** as something asserted everywhere yet: it lives in
   `webrtc-ice`'s vnet (`vnet/PoolLeakTracking.kt`, used by `BufferLifecycleTest` and
   `MdnsEndpointTest`), while the `CountingBufferFactory` copies in `webrtc-sctp`, `webrtc-stun` and
   `webrtc-dtls` count allocations only, and the published `webrtc-testsuite` harness exposes just
   `WebRtcHarnessScope.allocationCount` — so a *consumer* cannot yet assert this invariant at all.
   Two things bound how far it can go, and both are named in `CLAUDE.md`: the receive side has no
   last-reader rule, so nothing releases an inbound datagram; and `LeakTrackingFactory` is blind to
   DitchOoM/socket#277, where socket's own JVM/NIO and Node send paths drop a `TrackedSlice` unreleased
   — only `pool.stats().currentPoolSize` discriminates that one.
2. **No illegal state transition** — ICE pair/checklist and `PeerConnectionState` never take an illegal edge.
3. **Every native handle freed** — every DTLS wrapper freed, every TURN allocation released.
4. **Errors are typed** — surface as sealed reasons, never strings.
5. **Liveness** — the session reaches Connected or a typed terminal failure; it never hangs.
6. **SCTP ordering** — no message reordered within a stream, no unacked data dropped, DCEP converges.
7. **An optional watcher never kills the session** — anything we `launch` to collect a flow the *app*
   supplied (today: `IceRestartPolicy.OnNetworkChange`'s `NetworkMonitor`) must survive that flow
   throwing. Uncaught, it escapes into the app's own `CoroutineScope` and cancels a healthy data
   channel — the concrete case being an Android app that stripped `ACCESS_NETWORK_STATE`.

Assertion discipline (carried from socket): assert **observable state + a watchdog**, never wall-clock
budgets; `scenario = port`; skip-on-unreachable probes for off-CI harness runs; wrapper-transparency
(everything works when handed a `PooledBuffer`/`TrackedSlice`, not just a raw `PlatformBuffer`).

---

## 5. Determinism & the demote-to-fixture rule

The corpus is append-only, and it grows *from the flaky layers inward*:

> Every bug found at L2 (harness), L3 (interop), or in the field becomes a committed **L1 timeline
> fixture** in the same PR that fixes it (standing directive #5).

A field bundle from a debug app build — captured by `TraceRecorder` tapping the
`AddressedDatagramChannel` decorator, the state `StateFlow`s, and the signaling seam — *is* the bug report *is* the regression
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
- **Interop job** — L3: our stack against Pion, werift, Chrome, Firefox and WebKit, over `{x64, arm64}
  × {v4, v6, dual}`.
- **Consumer-smoke job** (`consumer-smoke.yaml`) — the artifact-shape safety net, run twice per release:
  on every PR and merge against the merged maven-local repo `validate-artifacts` produced (so a broken
  artifact fails the merge instead of reaching Central), and again after the tag against **Maven Central
  only** — no `mavenLocal()` in the repository list, so a module that never actually published has
  nowhere to fall back to. Every run uses a throwaway `GRADLE_USER_HOME` and `--no-build-cache`: a warm
  cache would hide exactly the missing-variant bug the lane exists to find. `validate-artifacts` checks
  the *shape* of the published tree; this compiles, links, and runs against it.

Because the harness no longer depends on flaky public hosts, the integration job can run on every PR,
not just labeled ones.

---

## 7. Running it

```bash
# Deterministic tiers (what every PR runs) — no Docker
./gradlew allTests                    # T0/TA/TB across all modules + platforms
./gradlew :webrtc-stun:jvmTest        # one module
./gradlew :webrtc-ice:testAndroidHostTest   # TP: Robolectric — real ConnectivityManager, no emulator
# Fuzz (time-boxed)
./gradlew :webrtc-stun:stunHeaderFuzz # example; Jazzer, jvmTest lane

# Harness (L2/L4) — Docker
bash test-harness/compose-up-retry.sh coturn nat-symmetric controller
./gradlew jvmTest -PwebrtcHarness=1

# Benchmarks (on demand)
./gradlew :webrtc-stun:jvmBenchmarkBenchmark
```

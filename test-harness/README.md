# L2 interop harness (W7)

Two **native** WebRTC peers establish a full data channel — ICE → **real BoringSSL DTLS** → SCTP →
`ping`/`pong` — across **real Linux NAT kernels**, gathering `srflx`/`relay` candidates from real
**coturn** and signaling over a UDP **rendezvous**. This is the L2 (Integration) tier of `TESTING.md`:
the vnet models NAT, but real kernels have quirks a model can't, so we run against real ones.

> The "our side" endpoint is the native `linuxX64`/`linuxArm64` binary, not JVM — JVM has no DTLS backend
> (W4 is native-only), so the native peer is the only one that does a real DTLS handshake. Built from
> `:webrtc-harness-endpoint` (a non-published module that composes the production `NativePeerConnection` +
> `BoringSslDtls` over real UDP via `socket-udp`).

## Topology

```
peer_a ─lan_a─ nat_a ═══pub═══ coturn / rendezvous ═══pub═══ nat_b ─lan_b─ peer_b
 (offerer)                     (STUN/TURN)  (signaling)                    (answerer)
```

Each peer sits behind its own NAT gateway on a private LAN. It reaches coturn + the rendezvous on the
public net *through its NAT* (exactly like the real internet), but **cannot reach the other peer
directly** — that is what ICE establishes. All IPs/ports/creds are pinned in `harness.env`.

- **coturn** — real STUN + TURN (short-term creds). Gives genuine `srflx` + `relay` candidates.
- **rendezvous** — a stateless in-memory keyed mailbox that relays the offer/answer/candidate blobs,
  reachable two ways onto the *same* mailbox: a **UDP** face for the native/Pion peers (they can only
  link `socket-udp` — linking socket core / socket-quic would duplicate-symbol its BoringSSL against
  buffer-crypto's, see `~/git/cinterop-issues` — so they speak raw UDP; wire format = the peer's
  KSP-generated buffer-codec schema) and an **HTTP** face (`POST /put` + `GET /poll`) for the browser
  (Chrome) lane, which has no raw UDP. A browser and a native peer therefore still meet in the same slot.
- **nat_a / nat_b** — Alpine routers applying one RFC 4787 profile each (below).
- **peer_a / peer_b** — the native binary; `peer_a` offers, `peer_b` answers.
- **peer_a_jvm** — the SAME peer program on the **JVM** (the pure-Kotlin engine over socket-udp's NIO
  datapath), a drop-in offerer for `peer_a`. Used by the `jvm-*` lanes to prove the pure engine on the real
  wire from a managed runtime (see the JVM-offerer section below).

## NAT profiles (RFC 4787) and their fidelity

A profile is a *(mapping, filtering)* pair. What stock netfilter models (`nat/nat-setup.sh`):

| Profile | Mapping | Filtering | Fidelity |
|---|---|---|---|
| **port-restricted** | EIM (`MASQUERADE` preserves the port) | Address+Port (conntrack return) | faithful |
| **symmetric** | Endpoint-dependent (`MASQUERADE --random-fully`) | Address+Port | faithful — a peer's coturn-learned `srflx` is useless to the other peer, so it **forces the TURN relay** |
| **address-restricted** | EIM | Address-only (`recent` module: record egress dest IPs, allow return from them on any port) | faithful for the hole-punch; `recent` is coarser than per-flow state |
| **full-cone** | EIM | Endpoint-independent (static `DNAT` of the mapped ICE port from any source) | faithful for the fixed ICE port — the only one ICE hole-punches on |

**netem** (loss/delay/jitter/reorder) is applied to a NAT's public interface on demand (`nat/netem.sh`
via `docker exec`), so it composes with any profile.

### Carrier-grade NAT (NAT444) and hairpin — the `cgnat` / `hairpin` lanes

The four profiles above are a single NAT layer. Two lanes add a **second** layer — an extra carrier-grade
NAT between each CPE (`nat_a`/`nat_b`) and the public net, over a `car` network (RFC 6598 `100.64/24`
shared space). In *behind-carrier* mode `nat-setup.sh` masquerades the LAN onto the carrier link too and
pulls the whole public net through the carrier NAT (two `/25` routes beat the CPE's connected `/24`), so a
peer's reflexive candidate is the **carrier's** public IP — a faithful double translation. The carrier
NATs (`cgnat_a`/`cgnat_b`/`cgnat`) are the same `nat/` image, wired `car→pub` and profile-gated.

| Lane | Carrier NATs | Result |
|---|---|---|
| **cgnat** (NAT444) | per-side `cgnat_a` + `cgnat_b`, distinct public IPs, port-restricted cone | a genuine double NAT; the composed cone mapping stays consistent, so it traverses via `srflx` (relay is the `policy=all` safety net) |
| **hairpin** | ONE shared `cgnat` both CPEs route through, symmetric | both peers share a single external identity; stock netfilter won't hairpin `car→car`, so — like `symmetric-relay` — ICE falls back to the **coturn TURN relay**, which is what the lane asserts |

## Running

```bash
cd test-harness
./run-interop.sh                    # full scenario matrix, asserts a two-peer establish+echo in each
./run-interop.sh port-restricted    # a single scenario by name
```

Scenarios (in `run-interop.sh`): each NAT profile direct, `symmetric×symmetric` → relay, a mixed
sym×port lane, an explicit `relay-only` lane, an `impaired` (netem) lane, the two carrier-grade NAT
(NAT444) lanes — **`cgnat`** (double NAT) and **`hairpin`** (shared carrier NAT → relay; above) — the
native-offerer interop lanes — **`pion-interop`**, **`chrome-interop`**, **`firefox-interop`**,
**`webkit-interop`** — and the **JVM-offerer** lanes — **`jvm-native`**, **`jvm-pion`**, **`jvm-chrome`**,
**`jvm-firefox`**, **`jvm-webkit`** (below). Each row is
`name | nat_a | nat_b | policy | netem | a_impl | b_impl | topo`, where `a_impl` (offerer) ∈ `native|jvm`,
`b_impl` (answerer) ∈ `native|pion|chrome|firefox|webkit`, and `topo` (NAT layering) ∈
`single|cgnat|hairpin` (defaults to `single`). A scenario **passes** iff both peers exit `0` — and
each exits `0` only after it CONNECTED *and* the `ping`/`pong` crossed the encrypted data channel. Every
run tears the whole stack down (containers + networks + volumes) on exit.

Selecting scenarios: positional args are an **allowlist** (`./run-interop.sh chrome-interop firefox-interop`
runs just those); `HARNESS_SKIP="chrome-interop firefox-interop" ./run-interop.sh` is a **skiplist** (the CI
`l2` job runs the full matrix minus the browser lanes, which run as their own parallel per-browser jobs).

## Interop: the Pion lane (W7 Phase 2a)

The `pion-interop` scenario swaps the native answerer `peer_b` for a real **Pion (Go) echo-peer**
(`pion/`), so our native offerer establishes against an independent WebRTC implementation — the
differential oracle. It runs the same topology (Pion behind `nat_b`, gathering from the same coturn,
signaling over the same rendezvous — the Go client in `pion/signaling.go` speaks the identical
buffer-codec wire schema). Pion accepts the data channel and echoes `ping`→`pong`.

- **DTLS 1.2**: Pion's released v3 is DTLS-1.2-only, so this lane sets `PEER_DTLS13=false` (via
  `WEBRTC_DTLS13`) — our peer pins its tested 1.2 fallback and version negotiation meets at 1.2.
- The Pion service is gated behind the `pion` compose profile (activated by `run-interop.sh` for this
  scenario only); it and `peer_b` share `PEER_B_IP` but never run at once.
- Its image builds natively per-arch (pure Go, no cross-compile / QEMU), so CI needs no extra build step.

```bash
./run-interop.sh pion-interop       # our native offerer ⇄ Pion answerer, DTLS 1.2, over port-restricted NAT
```

## Interop: the browser lanes — Chrome + Firefox + WebKit (W7 Phase 2b)

The `chrome-interop`, `firefox-interop`, and `webkit-interop` scenarios swap the native answerer `peer_b`
for a real **headless browser** (`browser/`, driven by Playwright), so our native offerer establishes
against a real *browser* WebRTC engine and echoes `ping`→`pong`. One image, three engines (selected by the
`BROWSER` build-arg + env):

- **Chrome** — Chromium's **libwebrtc** (BoringSSL DTLS, libwebrtc ICE, dcSCTP).
- **Firefox** — a **fully independent** stack (**NSS** DTLS, **nICEr** ICE, **usrsctp**), sharing nothing
  with Chrome — the highest-value second oracle.
- **WebKit** — **Safari's engine** (Playwright's cross-platform WebKit build; Apple's libwebrtc fork + its
  own build) — a third oracle, and the only way to exercise the Safari family in Linux CI without a Mac.

Same topology as the Pion lane (the browser behind `nat_b`, same coturn), accepting the data channel and
echoing `ping`→`pong`.

- **DTLS 1.3**: all three browsers negotiate DTLS 1.3, so these lanes leave the native peer at its
  **default** (`WEBRTC_DTLS13=true`) — the opposite of the Pion 1.2 lane. This exercises our real DTLS 1.3
  handshake against three production browser stacks.
- **No raw UDP in a browser** → the browser signals over the rendezvous **HTTP face** (`rendezvous.py`
  serves a `POST /put` + `GET /poll` JSON API onto the *same* in-memory mailbox the UDP peers use, so a
  browser and a native peer meet in the same slot). ICE/DTLS/SRTP still run in the engine's native code
  over real UDP through the NAT — the raw-UDP limit is signaling-only.
- mDNS host-candidate obfuscation is disabled for **Chrome** (`--disable-features=WebRtcHideLocalIpsWithMdns`)
  and **Firefox** (`media.peerconnection.ice.obfuscate_host_addresses=false`) so our peer is fed real-IP
  host candidates. **WebKit exposes no such pref**, so it emits `.local` mDNS host candidates our peer
  can't resolve — its lane connects via the coturn **srflx/relay** candidates instead (our ICE agent skips
  the unresolvable hosts; srflx/relay carry connectivity across the NATs regardless).
- Each is gated behind its own compose profile (`chrome` / `firefox` / `webkit`); they, `peer_b`, and
  `pion` share `PEER_B_IP` but never run at once. The image builds natively per-arch (Node + Playwright
  fetches the per-arch engine — only the selected one), no QEMU. In CI these run as a parallel
  `{arch × browser × offerer}` job
  matrix (`l2-browser`), separate from the fast native `l2` job.

```bash
./run-interop.sh chrome-interop     # our native offerer ⇄ headless-Chrome answerer, DTLS 1.3, over port-restricted NAT
./run-interop.sh firefox-interop    # our native offerer ⇄ headless-Firefox answerer, DTLS 1.3, over port-restricted NAT
./run-interop.sh webkit-interop     # our native offerer ⇄ headless-WebKit (Safari engine) answerer, DTLS 1.3
```

## Interop: the JVM-offerer lanes (W7 test-matrix expansion)

The `jvm-*` scenarios swap the native offerer `peer_a` for **`peer_a_jvm`** — the SAME peer program
running on the **JVM**. Since the W4b flip, DTLS is pure-Kotlin `commonMain` on every target (BoringSSL
demoted to a test oracle), so the JVM has a real handshake too: `peer_a_jvm` composes the identical
production stack (`NativePeerConnection` + `PureKotlinDtls`) over **socket-udp's NIO datapath** and
establishes over real NAT kernels against any answerer — our native peer, Pion, Chrome, or Firefox. This
proves the pure engine on the real wire from a managed runtime (previously "we support JVM" rested on unit
tests + compile alone).

- **`jvm-native`** ⇄ our native answerer · **`jvm-pion`** ⇄ Pion (DTLS 1.2) · **`jvm-chrome`** /
  **`jvm-firefox`** / **`jvm-webkit`** ⇄ the real browser engines (DTLS 1.3).
- No io_uring (NIO, not socket-udp's native datapath), so — unlike `peer_a` — `peer_a_jvm` needs **no
  `seccomp=unconfined`**, only `NET_ADMIN` for the default-route rewrite.
- The jar is **arch-independent** (JVM bytecode): one build (`:webrtc-harness-endpoint:peerJar`) runs on
  both x64 and arm64 — no per-arch cross-compile (contrast the native `.kexe`). `peer-jvm/Dockerfile` is
  the portable self-building image; `Dockerfile.prebuilt` copies a host/CI-built jar.
- Gated behind the `jvm` compose profile (activated by `run-interop.sh` when `a_impl=jvm`); `peer_a` and
  `peer_a_jvm` share `PEER_A_IP` but never run at once. In CI the fast lanes (`jvm-native`, `jvm-pion`) run
  in the `l2` job; the browser lanes (`jvm-chrome`, `jvm-firefox`, `jvm-webkit`) join the `l2-browser` matrix (its
  offerer axis is `{native, jvm}`).

```bash
./run-interop.sh jvm-native         # our JVM offerer ⇄ native answerer, DTLS 1.3, over port-restricted NAT
./run-interop.sh jvm-pion           # our JVM offerer ⇄ Pion answerer, DTLS 1.2
./run-interop.sh jvm-chrome         # our JVM offerer ⇄ headless-Chrome answerer, DTLS 1.3
```

The deterministic sibling of these lanes is `:webrtc-harness-endpoint`'s `JvmRealUdpLoopbackTest` — two
JVM peers establish over real loopback UDP and echo, in the ordinary `./gradlew build` (no Docker).

### Portability (arch-matched, no QEMU)

- **linux/amd64 + linux/arm64** — the peer targets both; each arch builds and runs its own native peer
  (an x64 runner → `linuxX64`, an arm64 runner → `linuxArm64`). No emulation.
- **macOS / Apple Silicon** (Colima or Apple's `container` CLI) — set `HARNESS_SELF_BUILD=1` so the peer
  is compiled *inside* its image (`peer/Dockerfile`) for the target platform; on Apple Silicon that's a
  native linux/arm64 build in the VM. The default fast path (`peer/Dockerfile.prebuilt`) copies a
  host-built binary and is for Linux/CI, where the host can build the linux binary natively.

### Host requirement: bridge netfilter off

A container routing **between** two Docker bridge networks only forwards if the host has
`net.bridge.bridge-nf-call-iptables=0` — otherwise the bridged frames traverse the host's Docker
FORWARD/ISOLATION chain (via `physdev`) and are silently dropped (symptom: peers stuck in `New`/
`Connecting`). `run-interop.sh` sets this automatically via a privileged host-netns container (the Docker
daemon is root even where you aren't); CI sets it with `sudo sysctl`. It's harmless if already off.

## Files

| Path | Purpose |
|---|---|
| `harness.env` | single source of truth: subnets, IPs, ports, TURN creds, timeouts |
| `docker-compose.yml` | the topology (4 networks, coturn, rendezvous, 2 CPE NATs, 3 profile-gated carrier NATs, 2 peers) |
| `run-interop.sh` | orchestrator: scenario matrix, per-scenario stack, pass/fail, teardown |
| `compose-up-retry.sh` | `up --wait` with transient-pull retries |
| `coturn/` | `turnserver.conf` + entrypoint (subst from `harness.env`) |
| `rendezvous/` | keyed-mailbox relay (`rendezvous.py`) with UDP (native/Pion) + HTTP (browser) faces onto one mailbox, + image |
| `nat/` | NAT gateway image + `nat-setup.sh` (the 4 profiles + behind-carrier NAT444 mode) + `netem.sh` |
| `peer/` | native peer image: `Dockerfile` (self-building, portable) + `Dockerfile.prebuilt` (fast) + entrypoint |
| `peer-jvm/` | JVM peer image: `Dockerfile` (self-building) + `Dockerfile.prebuilt` (fast, arch-independent jar) + entrypoint |
| `pion/` | the Pion (Go) interop echo-peer: `main.go` + `signaling.go` (rendezvous client) + image |
| `browser/` | the headless-browser interop echo-peer (Chrome + Firefox): `driver.mjs` (Playwright answerer, `BROWSER`-parameterized) + entrypoint + image |

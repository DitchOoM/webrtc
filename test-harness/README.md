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
- **rendezvous** — a stateless in-memory UDP keyed mailbox that relays the offer/answer/candidate blobs.
  Signaling rides UDP (not TCP/HTTP) because the native peer can only link `socket-udp`; linking socket
  core / socket-quic would duplicate-symbol its BoringSSL against buffer-crypto's (see
  `~/git/cinterop-issues`). Its wire format is the peer's KSP-generated buffer-codec schema.
- **nat_a / nat_b** — Alpine routers applying one RFC 4787 profile each (below).
- **peer_a / peer_b** — the native binary; `peer_a` offers, `peer_b` answers.

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

## Running

```bash
cd test-harness
./run-interop.sh                    # full scenario matrix, asserts a two-peer establish+echo in each
./run-interop.sh port-restricted    # a single scenario by name
```

Scenarios (in `run-interop.sh`): each NAT profile direct, `symmetric×symmetric` → relay, a mixed
sym×port lane, an explicit `relay-only` lane, and an `impaired` (netem) lane. A scenario **passes** iff
both peers exit `0` — and each exits `0` only after it CONNECTED *and* the `ping`/`pong` crossed the
encrypted data channel. Every run tears the whole stack down (containers + networks + volumes) on exit.

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
| `docker-compose.yml` | the topology (3 networks, coturn, rendezvous, 2 NATs, 2 peers) |
| `run-interop.sh` | orchestrator: scenario matrix, per-scenario stack, pass/fail, teardown |
| `compose-up-retry.sh` | `up --wait` with transient-pull retries |
| `coturn/` | `turnserver.conf` + entrypoint (subst from `harness.env`) |
| `rendezvous/` | UDP keyed-mailbox relay (`rendezvous.py`) + image |
| `nat/` | NAT gateway image + `nat-setup.sh` (the 4 profiles) + `netem.sh` |
| `peer/` | `Dockerfile` (self-building, portable) + `Dockerfile.prebuilt` (fast) + entrypoint |

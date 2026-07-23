# Interop harness: v4/v6/dual matrix + deterministic-root-cause diagnostics — design note

**Status:** design complete (3-lens judge panel, convergent), grounded against the real harness.
**Branch:** `harness-ipv6-matrix`. **Scope:** one harness-only PR (compose/scripts/workflow + one small
`webrtc-harness-endpoint` peer change — seed logging + DTLS seeding + SDP/candidate dump). **No protocol
core change** (webrtc-ice already does v6, PR #37).

Two deliverables, deliberately together — the new v6/dual lanes are exactly where diagnostics matter most:
**(A)** a full `{v4, v6-only, dual}` IP-family cross-product across every lane; **(B)** a capture-on-failure
forensic bundle that makes a CI flake **deterministically root-causable** — the bridge from a real-UDP
harness failure to a seeded `commonTest` vnet fixture (standing directive #5).

## A. IP-family matrix

### Topology: routed v6 + stateful firewall — **not NAT66** (unanimous across all 3 lenses)
Real dual-stack WebRTC over v6 uses globally/ULA-addressed hosts behind a *filtering* firewall, never
NAT66 — so the "NAT" containers become v6 **routers** (`ip6tables -P FORWARD DROP`; `LAN→WAN ACCEPT`;
`WAN→LAN -m conntrack --ctstate ESTABLISHED,RELATED ACCEPT`; **no MASQUERADE**). This is both faithful
*and* strictly less code than porting the four RFC 4787 mapping profiles. Consequence: the RFC 4787
**mapping** dimension is IPv4-only; only the **filtering** half carries to v6 (full-cone ≡ also ACCEPT
inbound on `ICE_PORT`; address/port-restricted ≡ conntrack/`recent` return only). `symmetric`, `cgnat`,
`hairpin`, `mixed-sym-port` are v4 address-exhaustion artifacts with **no v6 analog** — excluded from v6.

**One v6-native forced-relay lane (`firewall-relay6`)** — decision 2026-07-23: `relay-only` proves the TURN
path works when *policy*-forced (`ice_policy=relay`), but not that ICE *discovers* it must relay when the
*network* blocks direct/srflx. Since the v6 router firewall is already being written, add ~3 `ip6tables`
lines (`WAN→LAN DROP` except from coturn) + one SCENARIOS row that **reuses the existing hairpin
relay-pair assertion** (`selectedPair=CandidatePair(local=Relayed…)`). Cheap coverage relay-only can't give:
real-network forced-relay *fallback* over v6. Runs on v6/dual only.

### Addressing (octet-mirrored, all bridge-local — the runner needs no upstream v6)
| net | v4 | v6 |
|---|---|---|
| pub ("the internet") | `172.30.0.0/24` | `2001:db8:30::/64` (RFC 3849 doc prefix) |
| lan_a | `172.31.0.0/24` | `fd00:31::/64` (ULA) |
| lan_b | `172.32.0.0/24` | `fd00:32::/64` |
| car | `100.64.0.0/24` | `fd00:64::/64` |

Per-service reuses the v4 host octet: `COTURN_IP6=2001:db8:30::10`, `PEER_A_IP6=fd00:31::100`, etc.
`harness.env` gains a parallel `*_IP6` for every `*_IP` (inert on v4 lanes).

### Compose: two `-f` overlays over the untouched v4 base
`enable_ipv6`/`enable_ipv4` are booleans and `ipam.config` is a list — not env-interpolatable — so family
is carried by overlays, not variables:
- **`compose.ipv6.yml`** (dual-stack) — per-network `enable_ipv6: true` + a 2nd `ipam.config` subnet;
  deep-merges `ipv6_address: ${*_IP6}` into each service's networks block (base `ipv4_address` preserved);
  adds `net.ipv6.conf.all.forwarding: 1` to the 5 router sysctls; broadens the 5 NAT healthchecks to also
  assert `ip6tables -S FORWARD | grep -q ACCEPT` (so a v6-firewall bring-up failure is caught pre-flight);
  injects `GATEWAY_IP6`/`COTURN_IP6`/… into the peer + coturn env.
- **`compose.v6only.yml`** — additionally `enable_ipv4: false` per network (Docker Engine 27+, on ubuntu-24.04).

`run-interop.sh` sets `COMPOSE_FILE` from `IP_FAMILY` (`v4`→base; `dual`→base:ipv6; `v6`→base:ipv6:v6only),
which **every** `docker compose` call (compose-up-retry.sh, stack_down, exec, logs) inherits for free — no
call-site edits. coturn gains a 2nd listening/relay/external IP; `rendezvous.py` rebinds `::` with
`IPV6_V6ONLY=0` so one mailbox serves both families. The peer gathers a host+relay candidate **per family**.

### dockerd IPv6 on the runners (the crux risk)
Stock ubuntu-24.04 dockerd has IPv6 **off**. New workflow step, **conditional on `matrix.ipfamily != 'v4'`**,
before compose up: write `/etc/docker/daemon.json = {"ipv6": true, "fixed-cidr-v6": "fd00:d0c::/48",
"ip6tables": true}`, `systemctl restart docker`, `sysctl -w net.ipv6.conf.all.forwarding=1`.
- `ip6tables: true` installs the v6 chains for user-defined networks; `fixed-cidr-v6` governs only the
  default bridge and is **disjoint** from the compose v6 subnets.
- **Validate bring-up deterministically** (goal B): `docker network create --ipv6 --subnet fd00:cafe::/64
  v6probe && docker run --rm --network v6probe alpine ip -6 addr | grep -q 'inet6 .*scope global'` — fail
  the job with a clear message if absent, turning a silent v6-disabled daemon into an early, unambiguous
  failure instead of a 40-min ICE timeout. The v4 matrix is byte-unchanged (step gated off).

### Matrix expansion (family is a per-run env, never a 4th SCENARIOS column)
`IP_FAMILY` is read once near the `harness.env` sourcing; the 18-row SCENARIOS table, allowlist, and
skiplist stay orthogonal (a 4th column would explode 18→54 rows). A family-derived skip drops the
mapping-artifact lanes on v6. In `harness-l2.yaml`, add an orthogonal `ipfamily: [v4, v6, dual]` axis:
- **l2**: arch(2) → arch×family = **6 jobs**
- **l2-browser**: arch(2)×browser(3)×peer(2) = 12 → ×family = **36 jobs**  (total 14→42)
- **Do NOT** add family to the browser buildx cache scope — the image is family-independent; keep the #29
  bounded+retry logic unchanged.

### Gate vs informational — **v6/dual land NON-GATING first**
Working assumption: *every new v6/dual lane will flake at least once.* A `FAMILY_GATING` flag routes every
`v6`/`dual` failure to `::warning::` (informational, mirroring the existing impaired-lane precedent) — so a
new-lane flake is **captured and diagnosed but never reddens the required check**. v4 stays gating,
byte-unchanged. Each v6/dual lane is flipped to gating in a one-line follow-up once proven green.

## B. Deterministic-root-cause diagnostics

### The capture-on-failure bundle (`collect_diagnostics <name>`)
Today only the tee'd offerer+answerer stdout survives, and `stack_down` at the next scenario destroys the
capture window. One bash helper, called at **every** `record_fail; return` site inside `run_scenario`
*while containers are still up*, writes `test-harness/diag/${IP_FAMILY}/${name}/`:
- **All infra logs** (not just the 2 peers): coturn, rendezvous, nat_a, nat_b, active cgnat_* → per-file.
- **pcaps** (the gold-standard replay input): `tcpdump -i any -w …` (ring-buffered `-C 20 -W 3` to bound
  disk) backgrounded on nat_a/nat_b/coturn at scenario **start**, `docker compose cp`'d on failure, killed +
  discarded on pass. Needs `tcpdump` + `NET_RAW` in the nat image (coturn via a capture sidecar).
- **Firewall + conntrack, both families**: `iptables -S; iptables -t nat -S; ip6tables -S; conntrack -L;
  conntrack -L -f ipv6; ip -o addr; ip -6 route` per nat → `nat_*.state.txt` (needs conntrack-tools in the
  nat image).
- **Rendezvous mailbox**: curl the HTTP face (`:9998`) → `rendezvous-mailbox.json` — the exact offer/answer/
  candidate set (host/srflx/relay, v4 vs v6) both sides exchanged.
- **Resolved-env snapshot**: filtered `env` + `docker compose config` → pins the active family/addresses/overlays.
- **MANIFEST.txt**: scenario, family, profiles, policy, topo, rc_a/rc_b, `SEED_A`/`SEED_B`, selected-pair grep.

Failure-only, ring-bounded pcaps → the green path pays only an idle tcpdump. Upload: change the workflow
`path:` to the whole `test-harness/diag/` dir + the tee'd log; fold `ipfamily` into the artifact `name:` so
v4/v6/dual bundles never collide. Keep `if: failure()` + `if-no-files-found: ignore`.

### The bridge to a deterministic fixture (standing directive #5)
Our peer's ICE/JSEP/SCTP entropy is **already** seeded from `Random(cfg.seed)` (`Main.kt:90`, threading
ufrag/tie-breaker/STUN-txn-id/SCTP-init-tag; `cfg.seed` is a real injected field, `WEBRTC_SEED`-overridable).
Two gaps close the bridge — **verified against the source**:
1. **Seed is never logged** (highest-leverage). `Main.kt:48` prints role/session/policy/local/dtls13 but
   **omits `cfg.seed`** → a flake can't be replayed because no artifact records the seed that drove it.
   Fix: append `seed=${cfg.seed}` (+ the resolved per-family binds) to that line.
2. **DTLS entropy is unseeded.** `Main.kt:73` builds `DtlsConfig(bufferFactory = net, enableDtls13 = …)`
   with **no `random` arg** → defaults to `Random.Default`/CryptoRandom, so DTLS randoms + ephemeral X25519
   keys aren't byte-reproducible even given the seed (relevant to the post-Established storm class). Fix:
   pass `random = Random(cfg.seed xor 0xD715L)` so one logged seed reproduces the whole crypto flight.

Plus: **distinct per-lane seeds** (`run-interop.sh` exports `SEED_A`/`SEED_B` derived from scenario+family,
so no two lanes share entropy) and **dump on exit** the offer/answer SDP (held at `:161`) + `localCandidates`
+ the remote candidates currently discarded at `:187`. **Replay recipe:** logged seeds (our RNG) + the
mailbox SDP/candidate set (the environment's inputs) + the NAT-WAN pcap (the real-wire packet/loss schedule)
→ feed into `Random()` and drive the pair over the in-memory `DatagramChannel` vnet seam →
`DtlsSctpLossReproductionTest` is the working template. A `test-harness/replay/scaffold-fixture.sh` that
ingests a diag bundle and emits a pre-populated `commonTest` skeleton makes "fix it, ship the fixture, push
with confidence" a mechanical step.

## Risks
- **dockerd v6 on GHA** is the highest risk (env-specific, iterative). Mitigated by the gated enable + the
  `v6probe` deterministic validation + non-gating v6 lanes on first cut.
- **v6-only + `enable_ipv4:false`** needs Docker Engine 27+ (present on ubuntu-24.04) — validate.
- **Lane count 14→42** — bounded by keeping v6/dual informational + the family-skip of v6-degenerate lanes +
  not touching the browser cache scope.
- **pcap disk** — bounded by ring buffers + failure-only copy.

## Implementation order (CI-incrementally-validatable, one PR)
1. **Peer determinism** (Kotlin, tiny): `Main.kt` — log `cfg.seed`, seed `DtlsConfig`, dump SDP+candidates on
   exit. Ship a `commonTest` that asserts two seeded runs are byte-identical. (Independently valuable; lands first.)
2. **`collect_diagnostics` + pcaps + nat-image tools** on the existing **v4** lanes — prove the forensic
   bundle on the current green matrix before any v6.
3. **harness.env `*_IP6`** + **`compose.ipv6.yml`** + `nat-setup.sh` v6 router block + coturn/rendezvous v6.
4. **`IP_FAMILY` + `COMPOSE_FILE`** wiring + family-skip in `run-interop.sh`; per-lane seeds.
5. **dockerd v6 enable + v6probe** workflow step (gated) + the `ipfamily` matrix axis + `FAMILY_GATING`
   (v6/dual informational) + artifact `name:`/`path:` changes.
6. **`compose.v6only.yml`** (`enable_ipv4:false`) for the v6-only lanes.
7. Push, read the diag bundles from the first v6/dual runs, root-cause, promote lanes to gating as they prove green.

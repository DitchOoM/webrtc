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
| **hairpin** | ONE shared `cgnat` both CPEs route through, symmetric | both peers share a single external identity; stock netfilter won't hairpin `car→car`, so — like `symmetric-relay` — traversal must ride the **coturn TURN relay**. To *prove* that (not just hope for it), this lane pins **`ice_policy=relay`** (like `relay-only`), so only relay candidates are gathered and a green run cannot have used a direct/srflx path; `run_scenario` additionally asserts the offerer's selected pair is a relay pair from its `Connected` trace |

### The carrier switch — the `carrier-switch` topology (ICE restart)

The lanes above all give `peer_a` exactly one way off its LAN. This one gives it **two**: `nat_a2` is a
second, fully independent NAT gateway on `lan_a` with its own public IP (`172.30.0.33`). The peer
establishes through `nat_a` as usual, and mid-run the orchestrator flips its default route to `nat_a2` —
so the public address every remote candidate is aimed at stops working under a live session, exactly as it
does when a phone walks off Wi-Fi onto cellular. Note this is not a NAT *layer* like `cgnat`: nothing
routes through `nat_a2` on the way somewhere else, it is a sibling of `nat_a`.

The switch is **observed, never timed**. The offerer prints a cue when it reaches `s8` and then parks;
`run-interop.sh` watches for that cue, does the `ip route replace` with the same `docker compose exec` the
NAT/netem plumbing already uses, and publishes one record into the shared rendezvous mailbox — the only
channel there is into a running peer, and one it is already polling. Neither side ever sleeps.

Six lanes run it: **`restart-native`** (native ⇄ native), **`jvm-restart`** (JVM offerer ⇄ native), and —
since issue #71 — one per foreign answerer family that can complete one: **`restart-pion`**,
**`restart-chrome`**, **`restart-firefox`**, **`restart-webkit`**. Foreign peers used to be out of scope by
construction, because a dumb reflector never re-answered and would leave the re-offer unanswered; each
family now re-answers a later round, which is a mailbox read and not scenario logic (§4 of the semantics
design doc). All six are v4-only (a v6 analog needs a second v6 router, and "our public address changed"
is a v4 mapping statement), and all six **gate**.

What the foreign lanes add over ours is the one thing our own answerer cannot testify to: whether a
*production* stack, handed a restart offer, replaces **both** ICE credentials and **keeps** its DTLS
fingerprint (RFC 8842 §5.5) — i.e. restarts the session rather than rebuilding it. `s8` reads that off the
peer's own re-answer, and `run-interop.sh` separately greps the answerer's log for its own
`re-answered round 1` report, the same way `s7` greps a browser's `dc close:`.

#### Interop finding: werift does not complete a peer-initiated ICE restart

There is no `restart-node` lane, and that is a result rather than an omission. **werift** gets most of the
way: `RTCIceTransport.setRemoteParams` sees our changed credentials and calls `restart()`, which tears the
transport down, re-gathers (a fresh TURN allocation) and produces a **correct** re-answer — new
`ice-ufrag` *and* `ice-pwd`, unchanged `a=fingerprint`. It then never runs a connectivity check on the new
generation. `restart()` returns the transport to state `new` and fires `onNegotiationNeeded`, but the only
call site that starts a transport again is `PeerConnection.connect()`, which its `setRemoteDescription`
invokes for an **answer** — i.e. when werift is the *offerer*. Nothing on the answerer path restarts the
checks, and `connect()` is `private` in its public typings, so there is nothing the reflector may legally
call to finish the job.

Measured from the lane's own captures (STUN `USERNAME` counts, old generation `6353` → new `b11b`):

| | our checks → coturn | our checks → werift | werift's checks → us |
|---|---|---|---|
| generation 0 | 29 | 28 | 55 |
| generation 1 (the restart) | 21 | **0** | **0** |

werift installs no TURN permission for our new address because it never checks, so coturn drops what we
send. The session is therefore *gone* after the restart, not merely unconverged: the following `s6` DONE
handshake does not round-trip either. A lane could not pass — every lane's exit contract requires both
peers to exit `0`, and that requires the `DONE` handshake over a live association — so it would have had
to assert only "werift emitted a well-formed re-answer", which is a statement about its SDP writer and not
about its stack. The werift reflector re-answers anyway, exactly like the other families, so adding the
lane is a one-line change the day this is fixed upstream.

**IPv6 / dual-stack: the *stack* now supports it; the *real-network harness lanes* are still IPv4-only.**
As of Phase 1.5-A (PR #37), webrtc-ice does full IPv6 / dual-stack gathering, un-fenced address conversion,
and RFC 8445 §5.1.2 → RFC 6724 v6 candidate priority — **exercised in CI** by the deterministic
`commonTest` fixtures (`allTests` on every platform: the RFC 5952 parser corpus, `IceDualStackTest`, the
production-driver dual-stack test, the v6 vnet echo + NAT). What is **not yet** in CI is a **real-network**
(Docker) v6 / dual-stack interop topology: every lane above is IPv4-only, and the `harness-l2` matrix has
no IP-family dimension. Adding v6-only + dual-stack lanes (and enabling IPv6 in dockerd on the runners) is
the remaining follow-up (note: real carrier NAT ships NAT444 *with* native IPv6 as the escape hatch, so the
v6 topology rides with the CGNAT lanes there).

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
**`jvm-firefox`**, **`jvm-webkit`** (below) — and the six ICE-restart lanes, **`restart-native`**,
**`jvm-restart`** and **`restart-{pion,chrome,firefox,webkit}`** (above). Each row is
`name | nat_a | nat_b | policy | netem | a_impl | b_impl | topo`, where `a_impl` (offerer) ∈ `native|jvm`,
`b_impl` (answerer) ∈ `native|pion|chrome|firefox|webkit`, and `topo` (the extra network dimension) ∈
`single|cgnat|hairpin|carrier-switch` (defaults to `single`). A scenario **passes** iff both peers exit `0` — and
each exits `0` only after it CONNECTED *and* the `ping`/`pong` crossed the encrypted data channel. Every
run tears the whole stack down (containers + networks + volumes) on exit.

Selecting scenarios: positional args are an **allowlist** (`./run-interop.sh chrome-interop firefox-interop`
runs just those); `HARNESS_SKIP="chrome-interop firefox-interop" ./run-interop.sh` is a **skiplist** (the CI
`l2` job runs the full matrix minus the browser lanes, which run as their own parallel per-browser jobs).

## Data-channel semantics — what each lane now proves beyond `ping`/`pong`

A green lane used to prove **establishment**: ICE + DTLS + SCTP INIT + one DCEP OPEN + one 4-byte message.
It proved nothing about the data-channel *semantics* the library implements. Every lane now also runs an
**offerer-driven phase sequence** over the same association it already establishes, so the whole matrix
comes for free on every existing lane and CI grows no jobs. Design note: `docs/DC_SEMANTICS_INTEROP_DESIGN.md`.

| Phase | Channel(s) | What it proves against an independent stack |
|---|---|---|
| 0 | `harness` | establishment — the historical `ping`→`pong`, unchanged, still first |
| `s1` | `s1/large` | SCTP **fragmentation + reassembly** both ways: ~200 KB echoed **byte-identical** (~167 DATA chunks), clamped to `min(ours, peer's a=max-message-size)` — plus a probe **at** that ceiling, which is what proves we read and honour RFC 8841 §6 |
| `s2` | `s2/unordered` | the **unordered** channel type is honored end-to-end and still delivers (asserted as set equality, never order) |
| `s3` | `s3/rexmit`, `s3/timed` | **PR-SCTP** (`MaxRetransmits(0)` / `MaxLifetime`) is accepted, and an abandoned message does **not wedge** the stream — the peer advanced past it, i.e. processed our **FORWARD-TSN** |
| `s4` | `s4/a`,`s4/b`,`s4/c` | **multiplexing**: three concurrent channels with mixed profiles, each echo returning on its own stream (RFC 8832 §6 demux) |
| `s5` | `s5/reverse` | the **answerer** originates a channel and we reflect it — our DCEP responder path (odd stream-id parity). Our lanes only; foreign peers never originate |
| `s7` | `s7/victim`, `s7/keep`, `s7/reopen` | **per-channel close** (RFC 8831 §6.7 = an RFC 6525 stream reset, *not* a shutdown): one channel is closed mid-session and (a) its **neighbour keeps echoing**, (b) the **peer's channel closed** — proven by the victim's stream id becoming reusable, which our stack only does once **both** directions have been reset, the second being the peer's own reset, and (c) the **recycled id works**: a new channel on it echoes, so the peer's per-stream SSN state really was cleared |
| `s9` | `harness` | **RFC 7675 consent freshness**: the session is held **silent** for longer than a whole revocation window, then still round-trips. Nothing but the consent exchange keeps the pair (and its NAT mapping) alive across the hold — the dcSCTP subset has no HEARTBEAT on purpose, because ICE consent owns path liveness — so a peer that does not answer our §4.1 checks revokes and the phase reports it. Consent timing is a `PeerConnectionConfig.iceConfig` seam, so `run-interop.sh` compresses the window (2 s / 8 s) and a 10 s hold outlasts it; the phase **fails itself** if the hold does not, rather than passing vacuously. It asks nothing of the answerer but silence, so it runs on every lane |
| `s8` | `harness`, `s8/witness` | **ICE restart across a carrier switch** (RFC 8445 §9): the harness moves the offerer onto a second NAT mid-session, and the session (a) **reconverges on a new pair**, (b) is **reachable at the new carrier** — proven by the restarted generation gathering a candidate at that public address, which no earlier generation could have learned, (c) **keeps its association**: the control channel and a channel opened just before the switch both still round-trip, **on the same stream ids**, so nothing was closed and nothing was renumbered — and since a peer that had torn its own association down could not echo, that holds on both sides; and (d) **the peer really restarted**, read off its own re-answer: both ICE credentials replaced and the DTLS fingerprint unchanged (RFC 8842 §5.5). (d) is what separates a restart from a peer that reconnected, or that answered without restarting at all — outcomes (a)–(c) can all be satisfied on a forgiving path by a peer doing the wrong thing, which is precisely the risk when the peer is somebody else's stack. Carrier-switch lanes only |
| `s6` | `harness` | the `DONE` handshake, then a **graceful association SHUTDOWN** (RFC 4960 §9.2) — the peer sees a clean close, not a vanished association |

The ids are stable log labels, not a chronology: `s6` ends the association, so it necessarily runs **last**
and every phase added after it sorts before it — `s9` is the newest phase, not the final one, and it runs
before `s8`, which is the one that deliberately breaks the path it is standing on.

**The answerer stays dumb in every family.** Its whole contract is: *for every incoming channel, echo every
message back on that channel, verbatim; exit on `DONE`* (with `ping`→`pong` kept as the one historical
exception). That is what makes a **browser** — where nothing beyond the W3C `RTCDataChannel` API can be
injected — a first-class answerer for all of it: every scenario decision and every assertion lives on the
offerer side, in our Kotlin. Channel labels are self-describing for logs, `getStats` and pcaps, but drive no
behaviour. Each reflector also prints a `dc-negotiated:` line (`ordered=`, `maxRetransmits=`,
`maxPacketLifeTime=`) — the half of the proof only the peer can report, which is what the browser lanes are
asserted against.

Grading is one greppable line from the offerer:

```
[harness] phase s1: PASS (+412ms) 204800B echoed byte-identical, and so did a boundary probe at exactly the negotiated 262144B
[harness] phase s7: PASS (+3ms) closed "s7/victim" mid-session: its neighbour kept echoing, the peer reset its own half (stream 17 came back after 1 probe(s)), and a new channel on the recycled id echoed
[harness] phase s8: PASS (+1680ms) ICE restarted onto relay 172.30.0.10:64986 → srflx 172.30.0.32:40002 (was relay 172.30.0.10:60677 → srflx 172.30.0.32:40000), reachable at the new carrier 172.30.0.33; both channels kept their streams (1, 21) and still round-trip
[harness] semantics-summary: total=8 passed=8 failed=0 failed-phases=[]
```

A failed phase is **recorded and the sequence continues**, so one run reports everything that is broken.

| Env | Default | Effect |
|---|---|---|
| `HARNESS_SEMANTICS` | `1` | `0` restores the pure establish-and-echo harness (phase 0 only) |
| `HARNESS_SCENARIOS` | *(all)* | subset by short id, e.g. `s1,s3` — a debugging knob, never a lane matrix |
| `HARNESS_SEMANTICS_GATING` | `1` | **promoted**: a failed phase fails its lane. `0` de-gates everywhere for a debugging run |
| `HARNESS_SEMANTICS_NON_GATING` | *(empty)* | named lanes whose semantics stay informational. Empty — every lane gates. `node-interop`/`jvm-node` were the last holdouts (werift never reached `Connected`, so there was nothing to grade); the SCTP INIT deadlock behind that (#43) is fixed and both are promoted |
| `HARNESS_SEMANTICS_TIMEOUT_MS` | `120000` | watchdog for the whole sequence, on top of the establishment watchdog |

**Per-channel close** was the one gap here for as long as `webrtc-sctp` had no RFC 6525 RE-CONFIG (so `s6`
proved only the association-level shutdown). The library now implements the whole stream-reset exchange
(request/response, deferred processing, stream-id recycling), and `s7` is its interop proof against the
foreign stacks. Its deterministic siblings are `DataChannelCloseTest` (the SCTP stack pair) and
`PeerConnectionRoundTripTest.closing_one_channel_keeps_its_neighbour_and_recycles_the_stream_id` (the whole
stack over the vnet) — the L1↔L2 parity `TESTING.md` asks for.

## Interop: the Pion lane (W7 Phase 2a)

The `pion-interop` scenario swaps the native answerer `peer_b` for a real **Pion (Go) echo-peer**
(`pion/`), so our native offerer establishes against an independent WebRTC implementation — the
differential oracle. It runs the same topology (Pion behind `nat_b`, gathering from the same coturn,
signaling over the same rendezvous — the Go client in `pion/signaling.go` speaks the identical
buffer-codec wire schema). Pion accepts the data channel and echoes `ping`→`pong`.

- **DTLS 1.2**: Pion's released v3 is DTLS-1.2-only, so this lane sets `PEER_DTLS13=false` (via
  `WEBRTC_DTLS13`) — our peer pins its tested 1.2 fallback and version negotiation meets at 1.2.
  - **Why this is not a downgrade (the 1.3→1.2 non-fallback is deliberate + secure).** Meeting at 1.2 here
    is *version negotiation*, not a *downgrade*: Pion never offers 1.3, so there is nothing to downgrade —
    both sides simply agree on the highest common version. Our stack refuses a **silent** 1.3→1.2 downshift,
    because that silent fallback *is* the downgrade attack (an on-path attacker strips a 1.3-capable peer's
    offer to force the weaker version). A client that offered 1.3 treats any lower selected version as fatal:
    it detects the RFC 8446 §4.1.3 `DOWNGRD\x01` sentinel a 1.3-capable server stamps when it negotiates down
    (⇒ the offer was stripped) and fails `DtlsFailureReason.DowngradeDetected`. So interop with a 1.2-only
    peer works *because that peer never offers 1.3*, whereas a 1.3-capable peer downshifted mid-flight is
    correctly rejected. Proven end-to-end in `webrtc-dtls` by `DtlsDowngradeE2ETest`.
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
  - **mDNS end-to-end (obfuscation ON) has its own dedicated lane** (`mdns-chrome` / `mdns-firefox`,
    `compose.mdns.yml`). Once `socket-udp` gained multicast (3.15.0), the `MdnsResolver` seam was wired to a
    real `MulticastMdnsResolver` actual (`224.0.0.251:5353` / `[ff02::fb]:5353`, JVM **and** Kotlin/Native),
    so this lane puts our native peer (offerer) and a browser (answerer, obfuscation **ON**) on **one shared
    L2 bridge** (`lan0`, no NAT) where multicast floods, and our resolver resolves the browser's
    `<uuid>.local` host candidates for real. The lane **gates on proven resolution**: `peer_mdns` runs with
    `WEBRTC_REQUIRE_MDNS=true`, so it only exits 0 if `MulticastMdnsResolver` actually fired on a `.local`
    (it keeps the candidate-poll + resolve loops alive past the sub-second peer-reflexive connect). Note we
    do **not** assert the resolved pair is *selected*: mDNS is link-local, so a resolved `.local` is the same
    directly-reachable IP that prflx already won on — no topology makes the mDNS pair win a same-LAN race.
    The NAT lanes keep obfuscation OFF (real-IP host candidates); WebKit still proves the srflx/relay path
    with `.local` present. Tracked as issue #48 (closed by PR #51).
- **Browser-side diagnostics (`driver.mjs`)**: on every run — pass *or* fail — the driver logs the engine's
  own `getStats()` as a 2s-cadence + per-lifecycle-edge timeline (grep `getStats-timeline:`) plus a readable
  digest (`stats-summary:` — selected pair + RTT, DTLS state, per-channel message/byte counters), and rich
  per-message accounting (negotiated `ordered`/`maxRetransmits`/`maxPacketLifeTime`, size, running count,
  `bufferedAmount`). All of it flows page-console → node-stdout → the container log, which
  `collect_diagnostics` captures into the failure bundle as `<browser>.log`. So a red lane — especially a
  data-channel *semantics* lane (large/fragmented, unordered, partial-reliable) — is root-caused from the
  browser's OWN counters, not inferred from a pcap.
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
| `docker-compose.yml` | the topology (4 networks, coturn, rendezvous, 2 CPE NATs, 3 profile-gated carrier NATs, peer A's profile-gated second gateway `nat_a2`, 2 peers) |
| `run-interop.sh` | orchestrator: scenario matrix, per-scenario stack, pass/fail, teardown |
| `compose-up-retry.sh` | `up --wait` with transient-pull retries |
| `coturn/` | `turnserver.conf` + entrypoint (subst from `harness.env`) |
| `rendezvous/` | keyed-mailbox relay (`rendezvous.py`) with UDP (native/Pion) + HTTP (browser) faces onto one mailbox, + image |
| `nat/` | NAT gateway image + `nat-setup.sh` (the 4 profiles + behind-carrier NAT444 mode) + `netem.sh` |
| `peer/` | native peer image: `Dockerfile` (self-building, portable) + `Dockerfile.prebuilt` (fast) + entrypoint |
| `peer-jvm/` | JVM peer image: `Dockerfile` (self-building) + `Dockerfile.prebuilt` (fast, arch-independent jar) + entrypoint |
| `pion/` | the Pion (Go) interop echo-peer: `main.go` + `signaling.go` (rendezvous client) + image |
| `browser/` | the headless-browser interop echo-peer (Chrome + Firefox): `driver.mjs` (Playwright answerer, `BROWSER`-parameterized) + entrypoint + image |

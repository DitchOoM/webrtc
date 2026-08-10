# L2 interop harness

WebRTC peers establish a full data channel — ICE → **real DTLS** → SCTP → `ping`/`pong` — across **real
Linux NAT kernels**, gathering `srflx`/`relay` candidates from real **coturn** and signaling over a UDP
**rendezvous**. This is the L2 (Integration) tier of `TESTING.md`: the vnet models NAT, but real kernels
have quirks a model can't, so we run against real ones.

> The "our side" endpoint is built from `:webrtc-harness-endpoint`, a non-published module composing the
> production `NativePeerConnection` + `PureKotlinDtls` over real UDP via `socket-udp`. It ships as both a
> native `linuxX64`/`linuxArm64` binary **and** a JVM fat jar, and both do a real DTLS handshake — the
> engine is pure Kotlin in `commonMain`. (This note used to say the JVM had no DTLS backend and only the
> native peer could handshake. That has not been true since the engine moved to `commonMain`.)

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
  reachable two ways onto the *same* mailbox: a **UDP** face for the native/Pion peers (wire format =
  the peer's KSP-generated buffer-codec schema) and an **HTTP** face (`POST /put` + `GET /poll`) for the
  browser lanes, which have no raw UDP. A browser and a native peer therefore still meet in the same
  slot. (The UDP face was originally forced — linking socket core was believed to duplicate-symbol its
  BoringSSL against buffer-crypto's. That premise is obsolete; the UDP face stays because it works and
  keeps the peer's dependency surface to `socket-udp`, not because it must.)
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

### The carrier switch — the `carrier-switch` / `foreign-restart` topologies (ICE restart)

The lanes above all give `peer_a` exactly one way off its LAN. This one gives it **two**: `nat_a2` is a
second, fully independent NAT gateway on `lan_a` with its own public IP (`172.30.0.33`). The peer
establishes through `nat_a` as usual, and mid-run the orchestrator flips its default route to `nat_a2` —
so the public address every remote candidate is aimed at stops working under a live session, exactly as it
does when a phone walks off Wi-Fi onto cellular. Note this is not a NAT *layer* like `cgnat`: nothing
routes through `nat_a2` on the way somewhere else, it is a sibling of `nat_a`.

The switch is **observed, never timed**. The offerer prints a cue when it reaches its restart phase and
then parks; `run-interop.sh` watches for that cue, does the `ip route replace` with the same
`docker compose exec` the NAT/netem plumbing already uses, and publishes one record into the shared
rendezvous mailbox — the only channel there is into a running peer, and one it is already polling. Neither
side ever sleeps.

**Two topologies, one network event, opposite directions of the renegotiation.** The compose model is
identical (`nat_a2` and the same route flip); what differs is who asks for the new ICE generation:

| topo | phase | who restarts | what it proves |
|---|---|---|---|
| `carrier-switch` | `s8` | **we** do (`restartIce()` → re-offer) | a production stack correctly **answers** a restart we initiate |
| `foreign-restart` | `s10` | **the peer** does | **we** correctly **detect and answer** a restart a production stack initiates |
| `interface-swap` | `s11` | **nobody** — the network does | `IceRestartPolicy.OnNetworkChange` on the **production** monitor notices a real interface going away and restarts by itself |

Six lanes run `carrier-switch`: **`restart-native`** (native ⇄ native), **`jvm-restart`** (JVM offerer ⇄
native), and — since issue #71 — one per foreign answerer family that can complete one: **`restart-pion`**,
**`restart-chrome`**, **`restart-firefox`**, **`restart-webkit`**. Foreign peers used to be out of scope by
construction, because a dumb reflector never re-answered and would leave the re-offer unanswered; each
family now re-answers a later round, which is a mailbox read and not scenario logic (§4 of the semantics
design doc).

Five lanes run `foreign-restart` (issue #87): **`foreign-restart-native`**, **`foreign-restart-pion`**,
**`foreign-restart-chrome`**, **`foreign-restart-firefox`**, **`foreign-restart-webkit`**. Two run
`interface-swap` (issue #102): **`auto-restart-native`** and **`auto-restart-pion`**. All thirteen are
v4-only (a v6 analog needs a second v6 router, and "our public address changed" is a v4 mapping statement),
and all thirteen **gate**.

#### `interface-swap` — the automatic direction (issue #102)

`carrier-switch` moves the default **route**, which changes peer A's public identity while every local
address stays exactly where it was. That is why it needs an explicit `restartIce()`:
`IceRestartPolicy.OnNetworkChange` asks a different question — *"is the selected pair's local base still on
a live interface"* — and after a route flip the honest answer is yes, so the automatic policy correctly
does nothing. Proving the automatic path needs the **local address itself** to go away.

So `interface-swap` runs `ip addr del` + `ip addr add` + `ip route replace` on `peer_a` in one step: the
address the session is riding disappears, `172.31.0.101` takes its place, and the default route moves to
`nat_a2`. The kernel emits real `RTM_DELADDR`/`RTM_NEWADDR`, socket's **AF_NETLINK** monitor sees them
(the peer logs `detection=PlatformSignalled`, so this is not a poll), our `getifaddrs(3)` enumeration
confirms the address set moved, and `pathRidesOneOf` finds the selected pair's base gone. **Nothing in the
peer calls `restartIce()`** — that is the whole property.

Two ordering details, both learned the hard way and both load-bearing:

- **Delete before add.** The obvious order — add the new address, then remove the old — silently destroys
  the container's networking: Linux flushes every *secondary* address in a subnet when that subnet's
  *primary* is removed unless `promote_secondaries` is set, and it is `0` by default and the sysctl is
  read-only inside the container. Measured: the peer was left holding no `lan_a` address at all, could not
  reach the rendezvous mailbox, and `s11` failed as *"the harness never reported a carrier switch"* — a
  message blaming the orchestrator for a fault entirely in the peer's netns.
- **Re-add the address, then replace the default route.** Deleting the only address in a subnet withdraws
  that subnet's connected route, and the default route through it goes with it.

The lane's own anti-vacuity guard is in `run-interop.sh`: it greps the offerer's log for the `s11` verdict's
`NOTHING called restartIce()` token, because everything else `s11` asserts is equally true of a manual
restart. And the check issue #102 asked for was run directly — with `IceRestartPolicy.Manual` forced in the
peer, the lane fails with *"the network change alone (nothing called restartIce()) never signaled that a
renegotiation round is owed within 5s"*, which is what makes the green run mean something.

What the foreign `carrier-switch` lanes add over ours is the one thing our own answerer cannot testify to:
whether a *production* stack, handed a restart offer, replaces **both** ICE credentials and **keeps** its
DTLS fingerprint (RFC 8842 §5.5) — i.e. restarts the session rather than rebuilding it. `s8` reads that off
the peer's own re-answer, and `run-interop.sh` separately greps the answerer's log for its own
`re-answered round 1` report, the same way `s7` greps a browser's `dc close:`.

#### The reverse direction — `foreign-restart` and the second lifecycle word

Our detection rule is "a remote **offer** whose `a=ice-ufrag` *and* `a=ice-pwd` both changed" (RFC 8445 §9,
via `NativePeerConnection.peerRestarted`). Until issue #87 it had only ever been tripped by SDP we
generated ourselves — `PeerConnectionRestartTest` and the `restart-native` lane — so what a production
stack's re-offer does differently was untested by construction.

Three pieces this needed that `carrier-switch` did not:

* **A trigger.** No third-party stack restarts ICE because *somebody else's* carrier moved: a browser
  restarts when the app calls `restartIce()`, Pion and werift when their app does, and none of them has an
  app here beyond the reflector. So the reflector contract gains a **second lifecycle word**, `RESTART`,
  alongside `DONE` — read off the rendezvous mailbox the reflector is already polling, acted on by asking
  its own stack for a fresh generation and re-offering. It never learns *why*, never branches on what a
  restart means, and on a lane that never writes the slot the code is not reached. **The word, not a second
  carrier**: a `nat_b2` would have been more faithful about *why* a peer restarts, but it would still have
  needed the word (nothing in Pion or a browser page watches its own routing table), so it buys a second NAT
  and no additional proof — while the word on the existing topology keeps the network event real, the
  carrier assertion intact, and the reflector dumb. It rides the **mailbox** rather than the control
  channel for a load-bearing reason: by the time it is sent, the carrier under the data path has already
  been switched away, so a word on that channel would arrive — if at all — after the thing it asks for.
* **Mailbox slots.** `offer`/`answer` are the rounds *we* originate; a peer-originated round would collide
  on record ids, so it gets its own `peer-offer` / `peer-answer` pair (plus `peer-restart` for the word).
  Our offerer's single-consumer poll loop reads them, in the same loop and ahead of the peer's candidates —
  a trickled candidate carries no `ufrag` (RFC 8838 §3.1), so the round that renames the peer's generation
  must be applied before the candidates belonging to it.
* **Our offerer answering an incoming offer**, a role it has never played here. It could not, and finding
  that is worth more than the lane: `createAnswer()` re-ran the *initial*-offer rule (`actpass` ⇒ we are
  active) on a re-offer, claiming the DTLS client role the association had already given to the peer, and
  `resolveRole` correctly refused it with `RoleChangeOnRenegotiation`. Fixed in the same PR, with its
  deterministic fixture — see `PeerConnectionRestartTest.we_answer_the_peers_restart_offer_without_re_deciding_our_dtls_role`.

`s10` asserts four things, and the two in the middle are the point: the peer's own offer really carried a
restart (both credentials replaced, fingerprint kept), **our** answer opened a fresh local generation (both
of *our* credentials replaced, our fingerprint kept — the direct statement that the detection rule fired,
observable in nothing else we publish), the association survived on both sides on the same stream ids, and
the re-gather reached the new carrier's public address. `run-interop.sh` separately greps the answerer's own
`peer-initiated restart: re-offered round 0`, which is the half only the restarting peer can report.

#### Interop finding: werift does not complete an ICE restart in *either* direction

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

**And it cannot originate one either — which corrects the diagnosis above** (measured while building the
`foreign-restart` lanes, issue #87). The `connect()` asymmetry predicted that werift *as the offerer*
would be fine, since `setRemoteDescription` for an **answer** is exactly the call site that starts a
transport. It is not. Cued with `RESTART`, werift does everything visible right: `createOffer({ iceRestart:
true })` reaches `secureManager.restartIce()`, it publishes a well-formed restart offer (new `ice-ufrag`
`7fc1`, new `ice-pwd`, unchanged fingerprint), it takes a **fresh TURN allocation** on the new generation
and trickles it (`… typ relay … generation 1 ufrag 7fc1`), and it applies our answer. Then it sends
**nothing**:

| STUN `USERNAME`, generation 0 (`C9f0`/`6772`) → generation 1 (`7fc1`/`pqrs`) | at coturn | at `nat_a2` (ours) | at `nat_b` (werift's) |
|---|---|---|---|
| werift's checks → us, generation 0 | 55 | — | 75 |
| our checks → werift, generation 1 | 21 | 28 | 0 |
| **werift's checks → us, generation 1** | **0** | **0** | **0** |

So the defect is not the answerer-path call-site asymmetry; it is that werift does not run connectivity
checks on a restarted generation *at all*. `s10` fails there exactly as `s8` did — the phase reports "we
answered the peer's restart offer with a fresh generation, but the session never reconverged" — so there is
no `foreign-restart-node` lane either, and for the same honest reason. Both directions are one upstream fix
away from a one-line lane addition.

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
sym×port lane, an explicit `relay-only` lane, the two TURN-lifecycle lanes — **`turn-lifecycle`** (438
Stale Nonce + allocation Refresh) and **`turn-quota`** (486; below) — an `impaired` (netem) lane, the two carrier-grade NAT
(NAT444) lanes — **`cgnat`** (double NAT) and **`hairpin`** (shared carrier NAT → relay; above) — the
native-offerer interop lanes — **`pion-interop`**, **`chrome-interop`**, **`firefox-interop`**,
**`webkit-interop`** — and the **JVM-offerer** lanes — **`jvm-native`**, **`jvm-pion`**, **`jvm-chrome`**,
**`jvm-firefox`**, **`jvm-webkit`** (below) — the six ICE-restart lanes, **`restart-native`**,
**`jvm-restart`** and **`restart-{pion,chrome,firefox,webkit}`**, and the five **foreign-initiated**
restart lanes, **`foreign-restart-{native,pion,chrome,firefox,webkit}`** (both above). Each row is
`name | nat_a | nat_b | policy | netem | a_impl | b_impl | topo`, where `a_impl` (offerer) ∈ `native|jvm`,
`b_impl` (answerer) ∈ `native|pion|node|chrome|firefox|webkit`, and `topo` (the extra network dimension) ∈
`single|cgnat|hairpin|carrier-switch|foreign-restart` (defaults to `single`). A scenario **passes** iff both peers exit `0` — and
each exits `0` only after it CONNECTED *and* the `ping`/`pong` crossed the encrypted data channel. Every
run tears the whole stack down (containers + networks + volumes) on exit.

Selecting scenarios: positional args are an **allowlist** (`./run-interop.sh chrome-interop firefox-interop`
runs just those); `HARNESS_SKIP="chrome-interop firefox-interop" ./run-interop.sh` is a **skiplist** (the CI
`l2` job runs the full matrix minus the browser lanes, which run as their own parallel per-browser jobs).

## TURN lifecycle — the `turn-lifecycle` / `turn-quota` lanes

coturn's defaults put three of its own behaviours permanently out of a lane's reach: a NONCE lives 600 s,
an allocation 3600 s, and there is no quota at all — every one of those outlives the longest session this
harness runs. So 438 Stale Nonce, an allocation Refresh and 486 Allocation Quota Reached were implemented
in `TurnAllocation`, covered by deterministic vnet fixtures, and **never once seen from a real server**.
Two lanes close that, by compressing the *server's* clock the same way `PEER_CONSENT_INTERVAL_MS`
compresses consent — a directive, not a provider feature:

| lane | coturn directives | hold | what a green rc proves |
|---|---|---|---|
| `turn-lifecycle` | `stale-nonce=10`, `max-allocate-lifetime=20` | `PEER_IDLE_MS=35000` | the client answered a **438**, re-read REALM/NONCE, retried, and **renewed** an allocation that would otherwise have expired under it |
| `turn-quota` | `user-quota=1` | default | one peer's relay was refused **486** and the session established anyway, over host/srflx |

The knobs live in `harness.env` (empty = coturn's default, so every other lane is byte-unchanged),
are exported per lane by `run-interop.sh`, and are appended to the config by `coturn/entrypoint.sh` —
which also **echoes what it appended**:

```
[coturn] lifecycle: stale-nonce=10 max-allocate-lifetime=20
```

That echo is the first thing each lane asserts, and it is not ceremony: this file's own history has two
separate episodes of a configured value the server never applied (the `-n` open relay, the duplicated
`external-ip`), so a lane that assumed its directives took effect would pass green while proving nothing.
The rest is read out of `docker compose logs coturn` — `error 438: Stale nonce`, and a `refreshed, realm=…
lifetime=[1-9]` that excludes the `lifetime=0` deallocation `close()` sends, since otherwise a lane whose
keep-alive never ran would be satisfied by its own teardown. `turn-lifecycle` pins `ice_policy=relay` and
reuses the relay-pair assertion, so the session it holds really is riding the allocation under test.

Timings are measured against coturn 4.6.3, not guessed: `TurnMaintenance` refreshes at 0.75 of the
**granted** LIFETIME = 15 s, by which point the 10 s nonce has aged out, and the 35 s hold carries the
session well past the 20 s allocation. One caveat for anyone reading the server log: coturn prints
`new, …, lifetime=600` for our allocations, because it clamps a *requested* LIFETIME and our Allocate
sends none — the response it returns still carries 20, which is what the client's 15 s cadence confirms.

`turn-quota` is **v4-only**. A dual-stack lane gathers a relay per family, so one peer would exhaust a
quota of 1 by itself and the property under test — *the other peer was refused* — would stop being what
the lane measures.

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
| `s10` | `harness`, `s10/witness` | **the same carrier switch with the restart coming the other way** (issue #87): the peer is cued with the `RESTART` lifecycle word, restarts ICE and re-offers, and **we** have to detect that from its offer alone and answer it. It asserts (a) **the peer really restarted** — its own offer replaced both ICE credentials and kept its fingerprint, so the lane is not passing against a repeated offer; (b) **we detected it** — *our* answer replaced *our* credentials and kept *our* fingerprint, which is the direct statement that RFC 8445 §9's both-changed rule fired and is observable in nothing else we publish; (c) **the association survived on both sides**, same stream ids, both channels still round-tripping; and (d) **traffic moved to the new generation** — a different pair, reachable at the new carrier's public address, which no earlier generation could have learned. `s8` and `s10` are exclusive: a lane restarts in one direction. Foreign-restart lanes only |
| `s6` | `harness` | the `DONE` handshake, then a **graceful association SHUTDOWN** (RFC 4960 §9.2) — the peer sees a clean close, not a vanished association |

The ids are stable log labels, not a chronology: `s6` ends the association, so it necessarily runs **last**
and every phase added after it sorts before it — `s9` is the newest phase, not the final one, and it runs
before `s8`/`s10`, whichever of the two the lane has, since those are the phases that deliberately break the
path they are standing on.

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

## Interop: the Pion lane

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

## Interop: the browser lanes — Chrome + Firefox + WebKit

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
  - **…and, since #88, the MIRROR direction on the same lane**: `peer_mdns` also runs with
    `WEBRTC_MDNS_ADVERTISE=true`, so *our* host candidates are published as `<uuid>.local` names minted by a
    `MulticastMdnsEndpoint` — the two-way actual that serves the resolver and the responder over **one**
    socket per family (a second socket on 5353 would take a hash-chosen share of the unicast replies to our
    own queries). `WEBRTC_REQUIRE_MDNS_ANSWERED=true` makes rc=0 mean our responder actually **answered** a
    foreign engine's query for a name we minted, and the log carries every decision — `mdns answered <name>
    (Multicast)`, and the typed silences (`mdns silent: NotOurs(...)`, `NotAQuery`) that show the responder
    refusing everything that is not ours. Measured against Chrome: it queries the name out of our candidate
    line within ~200 ms of `setRemoteDescription` and we answer on the group.
    **What this lane cannot assert, and why** — the mirror of the note above. A `remote-candidate:
    type=host` at our IP never appears in the browser's `getStats()`, correctly: `lan0` has no NAT, so
    coturn reflects our own LAN address and our *srflx* candidate is the **same transport address**
    (`172.33.0.100:40000`) as the host candidate behind the name; libwebrtc prunes the redundant pair, so the
    resolved host candidate is real but unobservable. The load-bearing proof is therefore `mdns answered`:
    the browser can only have queried a name it read out of our own candidate line. The browser's log
    corroborates from its side (`remote candidate: candidate:…<uuid>.local…`, and no `addIceCandidate
    error`). **Mutation-checked**: with the responder made mute, Chrome still establishes and still exits 0
    — the lane goes red only because of these assertions. Tracked as issue #88.
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

## Interop: the JVM-offerer lanes

The `jvm-*` scenarios swap the native offerer `peer_a` for **`peer_a_jvm`** — the SAME peer program
running on the **JVM**. DTLS is pure-Kotlin `commonMain` on every target (BoringSSL survives only as a
test oracle), so the JVM has a real handshake too: `peer_a_jvm` composes the identical production stack
(`NativePeerConnection` + `PureKotlinDtls`) over **socket-udp's NIO datapath** and establishes over real
NAT kernels against any answerer — our native peer, Pion, Chrome, or Firefox. This proves the pure engine
on the real wire from a managed runtime, where "we support JVM" once rested on unit tests and compilation
alone.

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

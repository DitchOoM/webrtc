# Data-channel *semantics* interop — harness protocol design note

**Status:** **implemented** (Phase-1 close-out item #2). Decisions D1–D7 answered below in §7; the
sections above are the design as built. Prereq PR #52 (browser `getStats()` + rich DC logging) is merged
(`d276c8e`) and this builds on the counters it added.

**Phase numbering as built** (§5's S5 split in two once the reverse-direction phase was accepted):
`s1` large · `s2` unordered · `s3` partial-reliable · `s4` multiplex · **`s5` reverse** · **`s6` close**.

**Two things the design note got wrong about the code**, found while building it — both fixed in the same
PR rather than papered over:

1. **`close()` was not a graceful shutdown.** §5 assumed association-level SHUTDOWN was reachable from the
   public API. It was not: `NativePeerConnection.close()` *posted* the SHUTDOWN to the SCTP drive loop and
   then closed the ICE driver in the same breath, so the socket disappeared before the chunk could be
   written and the peer saw the association simply vanish. `close()` now waits (bounded by the new
   `PeerConnectionConfig.gracefulShutdownTimeout`, default 2 s, skipped when nothing is established) for
   the association to report `Closed` before tearing the transport down. Without this, s6 would have been
   a fiction.
2. **The PR-SCTP assertion in §5/S3 was unfalsifiable as written.** "A subsequent *reliable* message on the
   same channel still arrives" is not expressible — DCEP fixes reliability per channel at OPEN, so a
   `MaxRetransmits(0)` channel has no reliable messages to send. As built, both PR channels are **ordered**,
   which makes the same property observable: if the peer had not processed our FORWARD-TSN its cumulative
   TSN would never advance and every later message on that stream would stall behind the hole. So s3
   asserts (a) ≥1 message round-trips on a PR channel and (b) the reliable control channel still
   round-trips afterwards (no wedge), and *reports* an observed index gap as the FORWARD-TSN evidence
   rather than gating on it — on a clean path nothing is abandoned, so there is legitimately no gap.

## 1. The problem, precisely

Today every interop lane runs the **same fixed ritual** (`Main.kt` / `pion/main.go` /
`node/peer.mjs` / `browser/driver.mjs`): the offerer opens **one** reliable-ordered channel labelled
`"harness"`, sends `"ping"`; the answerer echoes `"pong"`. Green proves *establishment* (ICE + DTLS +
SCTP INIT + one DCEP OPEN + one small ordered reliable message round-trips). It proves **nothing**
about the data-channel semantics the library actually implements:

- SCTP **fragmentation + reassembly** of a message larger than one chunk / one MTU,
- **unordered** delivery (`ordered=false`),
- **partial reliability** (`MaxRetransmits` / `MaxLifetime` → PR-SCTP + FORWARD-TSN),
- **multiple concurrent channels** multiplexed over one association (stream-id demux),
- graceful **close / teardown**.

The library's own vnet + `runTest` suites cover these deterministically. What's missing is proof that
each behaves correctly **against an independent stack** (Pion, werift, Chrome, Firefox, WebKit) — the
whole reason the L2 harness exists.

## 2. The one asymmetry that shapes everything: offerer drives, answerer reflects

"Our side" is **always the offerer** (native or JVM). The three foreign families answer:

- **Pion** (Go) and **werift** (Node/TS) — arbitrary code, but a *different language each*.
- **Browsers** — standard **W3C `RTCDataChannel`** only; we cannot inject behaviour beyond what the
  API exposes.

So the design principle is: **keep the answerer a dumb, scenario-agnostic *reflector*; put every
scenario decision and every assertion on the offerer side (our Kotlin).** Concretely the reflector's
entire contract becomes:

> For every incoming data channel, echo every message back **on the same channel**, verbatim (same
> bytes, same string/binary type). If that channel is closed by the remote, mirror-close our end. Exit
> 0 once the offerer signals completion (see §4), having echoed everything without error.

That is a ~15-line generalisation of what each answerer already does (they echo *one* message on *one*
channel today). It means:

- **No cross-language assertion logic.** Only our offerer knows what "correct" is.
- **No scenario branching in the browsers.** The W3C reflector is identical for all engines.
- Every scenario below is expressible as "offerer opens channels + sends payloads; reflector echoes;
  offerer asserts the echo." The one exception (per-channel close) is discussed in §5 — and it turns
  out to be a *library* gap, not a harness one.

## 3. How the offerer selects the scenario — recommendation

The prompt framed three options — **channel-label convention**, **control message**, **per-container
env**. The key insight from §2 dissolves most of the question: **the reflector never needs to know the
scenario**, so "signalling the scenario to the answerer" is a non-goal. That leaves only *how the
offerer decides what to run*, and *how the two sides agree the run is over*.

**Recommendation — one long-lived PeerConnection runs the full scenario sequence, offerer-selected in
code:**

1. **Scenario selection = an ordered list compiled into the offerer**, run back-to-back over a single
   association. Default = all scenarios. `WEBRTC_SCENARIOS="large,unordered"` may *subset* it for
   debugging. **Not** per-lane env-matrix explosion, **not** a label-switch on the answerer, **not** a
   control message that reconfigures the answerer.
   - *Why one PC, all scenarios:* it multiplies coverage without multiplying CI lanes (every existing
     interop lane gains the whole semantics matrix for free), and a long-lived association with
     channels opening/closing across phases is *itself* a more realistic exercise of stream-id
     assignment and lifecycle than five short single-channel runs.
   - *Isolation cost* is mitigated by per-scenario labels + per-phase pass/fail logging (below); a
     phase failure is recorded and (decision **D2**) either aborts or continues.

2. **Channel labels encode `sN/<scenario>` as a self-describing convention** (e.g. `s1/large`,
   `s4/a`), purely for **observability** — they make the browser `data-channel` getStats entries, the
   peer logs, and the pcap self-explaining. Labels drive **no behaviour**. (This is option (a), demoted
   from a control mechanism to a naming convention.)

3. **A single control channel `ctl`, opened first, carries only lifecycle** — not scenario selection:
   - phase 0 is the **existing ping→pong on `ctl`** (backward-compatible liveness gate: establishment
     is still proven exactly as today, before any semantics phase);
   - after the last phase the offerer sends **`DONE`** on `ctl`; the reflector echoes it; both linger
     briefly and exit 0. This makes completion an **explicit, greppable handshake** instead of the
     current teardown-timing race (`FLUSH_LINGER` vs `ECHO_TIMEOUT`). (This is a *minimal* slice of
     option (b) — a control message, but for sequencing only, never to configure the reflector.)
   - *(optional, decision **D3**)* per-phase `BEGIN sN` markers on `ctl` for cleaner log correlation.

Net: **env is not used to tell the answerer anything**; the answerer is universal. Env only optionally
subsets the offerer's built-in list.

## 4. The reflector contract, per family (the only answerer change)

All three already echo; the change is "one channel" → "every channel", plus mirror-close and the
`DONE` completion:

| Family | Change |
|---|---|
| **Browser** (`driver.mjs`) | Already has `pc.ondatachannel` + per-message echo. Generalise: keep a handler per channel, echo `m.data` back on *that* `dc`, preserving `binaryType`. Mirror `dc.onclose`. Treat `DONE` on `ctl` as resolve. All the getStats/per-message logging added in #52 already keys by channel — nothing to add there. |
| **Pion** (`main.go`) | `OnDataChannel` per channel; `dc.OnMessage` → send back the same bytes with the same `IsString`. Mirror close. `DONE` → linger + exit. |
| **werift** (`peer.mjs`) | Same shape as Pion; echo string-vs-Buffer by input type (it already distinguishes). |
| **native/JVM** (`Main.kt` answerer path) | The `runAnswerer` echo becomes "collect `incomingDataChannels`, launch an echo pump per channel." Our own reflector can additionally assert nothing (it's still just a reflector) — but it's the one place we *could* later add reverse-direction origination (decision **D4**). |

## 5. Concrete scenario set

Ordered as the offerer runs them. For each: **what the offerer does**, **what it asserts**, and **what
it genuinely proves vs. what stays in the vnet tests** (honesty about clean-path limits).

### S1 — large / fragmented message (>64 KB) — *the flagship, run first*
- **Config:** `s1/large`, default (ordered, reliable).
- **Offerer:** send **one** message of ~**200 KB** of a deterministic pattern (seeded, so byte-identity
  is checkable). This is far past one MTU → forces SCTP fragmentation into many DATA chunks (B/E bits)
  and reassembly on the far side.
- **Assert:** the echoed message is **byte-identical** and the same length. Browser getStats:
  `messagesSent/Received == 1`, `bytesSent/Received ≈ 200 K` on the channel.
- **Proves:** our SCTP fragmentation/reassembly + receive-window flow control interoperates with the
  foreign stack's, **both directions**. This is the single highest-value true-semantics proof.
- **Interop hazard to respect:** `a=max-message-size` (RFC 8841 §6). Our SDP defaults to
  **262144** (`DataChannelDescription.DEFAULT_MAX_MESSAGE_SIZE`); browsers advertise their own. The
  offerer **must** size the payload `< min(local, remote-advertised)` — so it must **read the peer's
  answer `a=max-message-size`** and clamp. 200 KB is under every default; a follow-on "at the limit"
  probe is decision **D5**.

### S2 — unordered
- **Config:** `s2/unordered`, `ordered=false`, reliable.
- **Offerer:** send a burst of **N=50** small index-tagged messages (payload = its sequence number).
- **Assert:** all N echoes return with intact content (**set** equality, never sequence — see below).
  Browser reports `dc.ordered === false` (proof the DCEP OPEN channel-type negotiated end-to-end).
- **Proves (clean path):** the unordered channel-type is honoured by the foreign stack and still
  delivers reliably. **Honest limit:** a clean local path rarely *reorders*, so this does **not** prove
  reordering is tolerated — that proof stays in the deterministic netem/vnet tests. **Recommendation
  (D6):** also run S2 on the **impaired lane** (`impaired-loss-delay`), where real reordering occurs,
  asserting only set-equality.

### S3 — partial reliability
- **Config:** two channels — `s3/rexmit` (`MaxRetransmits(0)`) and `s3/timed` (`MaxLifetime(short)`).
- **Offerer:** send on each.
- **Assert (clean path):** the PR profile is **negotiated + visible on the foreign side** — browser
  reports finite `dc.maxRetransmits === 0` / `dc.maxPacketLifeTime`; the un-dropped messages round-trip.
- **Proves:** the foreign stack accepts our DCEP PR parameters. **Honest limit:** abandonment +
  **FORWARD-TSN** only happen under loss. **Recommendation (D6):** run S3 on the impaired lane too, and
  assert the stronger property — a dropped PR message does **not wedge** the stream: a subsequent
  reliable message on the same channel still arrives (i.e. the foreign stack processed our FORWARD-TSN
  and advanced its cumulative TSN). That is the real PR-SCTP interop proof.

### S4 — multiple concurrent channels
- **Config:** open **K=3** channels at once with mixed profiles — `s4/a` (ordered-reliable), `s4/b`
  (unordered), `s4/c` (partial-reliable) — and send a distinct tagged message on each near-concurrently.
- **Assert:** each channel's echo returns **on the same channel** (correct label/stream-id demux) with
  correct content, and the three profiles are each reflected in getStats.
- **Proves:** SCTP stream multiplexing + DCEP even/odd stream-id assignment (RFC 8832 §6) interoperate
  — the foreign stack routes each stream independently over the one association. Fully covered by the
  dumb reflector.

### S5 — clean close — ⚠️ **library gap, needs a decision**
- **What the prompt assumed:** "library already supports every semantic." For close, **it does not.**
  `SctpDataChannelStack` (line 55–56) states plainly: *per-channel close via SCTP stream reset
  (**RFC 6525 RE-CONFIG**) is **not in this subset** — `Connection.close()` tears down only the local
  halves, noted as a W7 follow-up.* Grep confirms **no RE-CONFIG chunk type / codec exists anywhere**
  in `webrtc-sctp`.
- **Consequence:** we **cannot** prove "clean per-channel stream-reset close" interop today — the very
  thing a browser's `dc.close()` → `onclose` exercises (RFC 8831 §6.7). The foreign side would never
  see an `OUTGOING_SSN_RESET`, so its channel would not transition to `closed`; asserting `dc.onclose`
  fired would *fail*.
- **What we *can* prove today:** whole-**association** graceful shutdown **is** implemented (SHUTDOWN /
  SHUTDOWN-ACK / SHUTDOWN-COMPLETE chunks + `SctpEvent.Shutdown` + `ShutdownPending` state). So S5 can
  be scoped to: after all phases, the offerer initiates a **graceful association SHUTDOWN**; assert the
  foreign stack observes a **clean** close (not an ABORT, not a watchdog timeout) — browser
  `transport`/`sctp-transport` state goes to `closed`, connectionState `closed` not `failed`.
- **Decision D1 (the important one):**
  - **(a)** Scope S5 to **association-level graceful SHUTDOWN** now (harness-only wiring, honest name:
    "clean association teardown"); defer per-channel close to a library follow-up. *Recommended* — it
    keeps this item "harness wiring only" as intended, and clean teardown is itself untested at interop.
  - **(b)** Treat per-channel **RFC 6525 RE-CONFIG** as a Phase-1 blocker and **implement it first** (a
    `webrtc-sctp` feature PR: chunk codec + outgoing/incoming SSN-reset state machine + `Connection.close`
    wiring + deterministic vnet fixtures), *then* add the real per-channel close scenario. Larger, and
    strictly a library change, not this note's harness work.

## 6. Surface of change (once a shape is agreed)

- **`test-harness/browser/driver.mjs`, `pion/main.go`, `node/peer.mjs`** — generalise the single-echo
  handler to the universal reflector (§4). ~15 lines each.
- **`webrtc-harness-endpoint/.../Main.kt`** — `runOfferer` gains the scenario sequence + per-phase
  assertions + `ctl`/`DONE`; `runAnswerer` becomes the multi-channel reflector. This is the bulk of
  the work and it is **all our Kotlin**.
- **`run-interop.sh`** — no matrix change required (semantics run inside existing lanes). Optional: a
  `WEBRTC_SCENARIOS` subset knob for targeted CI debugging; land semantics **NON_GATING-first** per the
  established convention (`$HARNESS_NON_GATING`), flip to gating once green across families/engines.
- **No new signaling wire** — `ctl` is just another data channel; labels ride existing DCEP OPEN.
- Diagnostics: the #52 getStats timeline + per-message counters already capture everything a red
  semantics phase needs (bytes/messages/retransmits per channel, DTLS/SCTP state) — no new capture.

## 7. Decisions — answered, and how each landed

| # | Decision | Answer | As built |
|---|---|---|---|
| **D1** | close scope | **(a)** association-SHUTDOWN now, defer RFC 6525 RE-CONFIG | `s6` = `DONE` handshake + graceful association SHUTDOWN. Required the `close()` fix above. Per-channel close remains a `webrtc-sctp` follow-up, named as such in the code and the README rather than implied |
| **D2** | phase failure | **record + continue** | `SemanticsReport` collects every verdict (a throwing phase included) and prints one `semantics-summary:` line; the sequence never short-circuits, so one CI run names everything broken |
| **D3** | per-phase markers | **yes** | `BEGIN <id>` on the control channel before each phase, echoed back — so it doubles as a liveness barrier: a marker that does not round-trip fails the phase before it starts |
| **D4** | reverse direction | **yes, our lanes only** | `s5`; `run-interop.sh` sets `PEER_REVERSE=1` only when the answerer is `native`. The offerer reflects it with the *same* universal reflector the far side runs, so neither role has bespoke echo logic |
| **D5** | max-message-size boundary | **yes** | `s1` sends `min(200 KB, ceiling)` **and** a probe at exactly `ceiling = min(ours, peer's advertised)`, read from the answer SDP. Absent advertisement ⇒ the conservative RFC 8841 64 KiB floor. This is also what keeps s1 honest against Pion, which advertises 65536 |
| **D6** | impaired lane | **yes** | The sequence runs on *every* lane, `impaired-loss-delay` included — that is where s2 sees real reordering and s3 real abandonment. Assertions are written so a clean path cannot pass vacuously *and* a lossy path cannot flake (set equality, not order; no-wedge, not delivery counts) |
| **D7** | gating | **non-gating first** | `HARNESS_SEMANTICS_GATING=0` by default: phases always run and always report, failures are `::warning::`. Promotion is one flag — it flips `WEBRTC_SEMANTICS_REQUIRED` on the peer, so a failed phase then fails the process and the lane |

## 8. Surface actually changed

- `webrtc-harness-endpoint/.../Semantics.kt` *(new)* — phase sequence, universal reflector, control
  channel, array-free pattern payload + verifier.
- `webrtc-harness-endpoint/.../Main.kt`, `HarnessConfig.kt` — role wiring, the new `WEBRTC_SEMANTICS*` /
  `WEBRTC_SCENARIOS` / `WEBRTC_REVERSE` env, the answerer's DONE-driven exit and clean-close observation.
- `webrtc/.../PeerConnection.kt` — the graceful-shutdown fix + `gracefulShutdownTimeout` (see above).
- `test-harness/{browser/driver.mjs, pion/main.go, node/peer.mjs}` — the universal reflector, the
  `dc-negotiated:` report line, DONE-driven exit.
- `test-harness/{docker-compose.yml, compose.mdns.yml, run-interop.sh}` — env plumbing, per-lane
  `PEER_REVERSE`, `semantics_report` grading (summary line + the browsers' negotiated-property assertion).
- `test-harness/README.md`, `TESTING.md` — what each lane now proves, and the honest limits.

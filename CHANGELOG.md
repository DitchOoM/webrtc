# Changelog

All notable changes to `com.ditchoom:webrtc` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are auto-derived from Maven Central
metadata + PR-label bumps (`major` / `minor`, else patch).

## [Unreleased]

### Changed — the ICE send path reads socket's typed failure, closing #143

Completes what #146 started, and **pins socket 4.0.2** to do it — 4.0.1 (what main pinned) does not carry
the type at all, so the same source fails to compile there with `Unresolved reference 'DatagramSendError'`.
Verified as a differential against both, not assumed from the release notes.

socket-udp now reports a refused send as a sealed `DatagramSendError`
(DitchOoM/socket#278) — `TooLarge`, `Unreachable`, `NotPermitted`, `WouldBlock`, `OsError`,
`PlatformError`, `Transport` — and its own KDoc names this consumer: *"consumers that want to branch
(ICE marking a candidate pair unusable)"*.

**It could not simply be caught.** That type lives in `com.ditchoom.socket.udp`, and the sans-io half of
`webrtc-ice` must not depend on socket at all (ARCHITECTURE §11.6) — but `sendOrFailure` and both
retransmit loops are `commonMain`. So the classification crosses the boundary as **ours**:

- `IceTransmitFailureReason` (`commonMain`, no socket dependency) — `PayloadTooLarge`,
  `DestinationUnreachable`, `Transient`, `Unknown`. Cut by *what ICE can do differently* rather than by
  what the OS distinguishes: `EHOSTUNREACH`, `ENETUNREACH`, `EAFNOSUPPORT` and `EACCES` are four kernel
  decisions and one ICE response, so they are one case.
- `TypedSendChannel` (`socketMain`, where socket-udp is already a dependency) translates and rethrows as
  `IceTransmitException`. `udpDatagramBinder()` wraps every channel it hands out.

A caller supplying their own binder — the demuxed socket shared with QUIC-P2P that §11.6 exists to
protect, or the vnet — gets no translation and therefore `Unknown`, which behaves exactly as this module
did before any of it existed.

**One reason changes control flow, deliberately.** `PayloadTooLarge` means the socket has already
measured these bytes against its limit, so re-sending them unchanged every retransmit interval until the
budget expires cannot succeed. Both loops now give up on the first such refusal. Everything else stays
retryable, including `Unknown` — the case a *new* socket error lands in, where defaulting to permanent
would let one unrecognized errno cost a candidate.

`DestinationUnreachable` is reported but **not acted on**: failing the pair in the checklist is a sans-io
core change and wants its own fixture, so it is left as a follow-up rather than smuggled in here.

`IceTransmitReasonTest` pins all three directions in `commonTest` — the short-circuit fires on exactly
one attempt, every other reason retransmits across the budget, and an untyped failure stays retryable.

**API:** adds `IceTransmitFailureReason`, `IceTransmitException`, and a `reason` field on
`IceTransmitFailure`. `minor`.

### Changed — socket core is no longer a dependency of this repo (`minor`)

Pins socket **4.0.1** and moves `webrtc-ice`'s native leaf from `com.ditchoom:socket` core to
`com.ditchoom:network-monitor`, the same artifact its jvm and android leaves already use.

The old arrangement was written down as an interim and is now retired. socket's netlink and NWPathMonitor
monitors reused socket core's cinterop, while `:network-monitor` deliberately stayed cinterop-free — so
on native that artifact shipped the contract with no implementation behind it, and we took socket core
"the ONLY place we depend on it" to get the monitor. DitchOoM/socket#275 closed DitchOoM/socket#269 by
giving `:network-monitor` its own netlink and Apple cinterops, so the interim is over.

**Verified as a differential rather than assumed.** Against socket 4.0.0 the identical swap does not
compile — `InterfaceChangeTrigger.nativeMain.kt` fails with `Unresolved reference 'default'` / `'state'` /
`'close'`, which is exactly "the contract with no implementation behind it". Against 4.0.1 it compiles
and all 9 `SystemNetworkMonitorTest` cases pass on linuxX64.

With this, **`socket-udp` in `socketMain` is the only socket artifact this repo depends on** — which is
what ARCHITECTURE §11.6 has always described. Two build comments that asserted the old arrangement are
corrected in place rather than left to rot; one of them had already been corrected once, for a different
reason, and would have been wrong a second time.

Also inherited from 4.0.1, and untested here because it only manifests on Apple: an
`nw_path_status_satisfiable` path now maps to `Routable` rather than `LinkLocal`. `linkTopology()`
forwards rung changes as "the network moved", so an on-demand VPN transition previously presented as
`Routable → LinkLocal → Routable` — two spurious ICE restarts under `IceRestartPolicy.OnNetworkChange`, on
a machine that was online throughout. `LinkTopologyTest` pins the current behaviour, so any change
surfaces on `build-apple` rather than silently.

**API:** no source change. Dependency-only, but a native consumer's transitive classpath loses socket
core — `minor`.
### Fixed — a raised `send` cost an ICE agent its buffer and the rest of its output batch (#143) (`minor`)

`IceAgentDriver.apply()` pumps a `List<IceOutput>` from the sans-io core, and its transmit arm was
written as though `send` could not raise:

```kotlin
channels[output.fromBase]?.send(output.data, to = output.to.toSocketAddress())
output.data.releaseAfterSend()
```

It can, and it is about to do so far more often: DitchOoM/socket#278 makes every socket-udp backend
report a refused send instead of returning normally having sent nothing. Two harms followed, and the
second is the one worth the fix.

- **The buffer leaked.** A raise between the two lines skipped the release outright — against the
  ownership invariant #142 established and proved.
- **The rest of the batch was abandoned.** The raise escaped the `for` loop, dropping every remaining
  output including `ConnectionStateChanged` and `PathChanged`. The driver's observable state then
  silently stopped matching the core state machine — strictly worse than the lost datagram that caused
  it, and invisible from the outside.

New internal `sendOrFailure()` — the exact mirror of the existing `receiveOrClosed()`, rethrowing
`CancellationException` and answering a sealed `IceTransmitResult` for anything else. The release now
rides a `finally`, and a refused transmit is reported on the new `IceAgentDriver.transmitFailed` flow
(bounded, `DROP_OLDEST`) rather than raised, surfacing to an application as
`SessionDiagnostic.TransmitFailed`.

The two **retransmit loops** — server-reflexive gathering and every TURN request — get the same
treatment, and there the argument is even simpler: their entire purpose is surviving transient loss ("a
single lost request must not cost the whole srflx"), and a raise bypassed that tolerance completely.

**Tolerating a failure is not the same as hiding it**, which is what the rest of this change is about. A
swallowed permanent failure — a closed socket, a `bufferFactory` this platform cannot send from (#125) —
would burn the whole budget and then report `NoResponse`, blaming a STUN or TURN server that was never
contacted. So both loops now track whether *anything* ever left the socket and answer accordingly:

- `ServerReflexiveResult.Unavailable.SendFailed(cause)`
- `TurnAllocationResult.Unavailable.SendFailed(cause)` — which reaches an application through the
  existing `IceGatheringNotice.RelayUnavailable`. This one matters most: behind a symmetric NAT the relay
  is the only path, so "the TURN server is unreachable" is the conclusion an operator acts on, and it is
  the wrong machine to go and look at.

`GatheringBufferFactoryTest` changes shape as a result — it used to assert the raise itself
(`assertFailsWith<IllegalStateException>`), which is precisely the behaviour being removed. It now
asserts the typed `SendFailed` and its carried cause, and gains the anti-vacuity direction: a socket that
*accepts* the datagram against a silent server must still report `NoResponse`, or the distinction would
be worthless. New `IceSendThrowTest` pins the driver half; both of its cases were confirmed to **fail**
against the pre-fix code, with the batch-abandonment one failing on exactly the assertion it exists for.

Two call sites are deliberately left raising, and say so in place: `IceDataTransport.send` and TURN's
Send indication are the **application** data path, where the buffer is the caller's (nothing of ours to
leak) and there is no batch of ours to abandon. Telling DTLS its record went out when it did not would be
worse than the throw.

**Still open on #143:** the typed `catch` on `DatagramSendException` cannot be written until socket#278
releases. This is the half that does not need it — and it is a real defect today, since a closed channel
already raises on the JVM.

**API:** adds `IceAgentDriver.transmitFailed`, `IceTransmitFailure`, `SessionDiagnostic.TransmitFailed`,
and a `SendFailed` case to two sealed `Unavailable` hierarchies. Additive, but new cases in sealed types
are source-breaking for an exhaustive `when` — `minor`.

### Fixed — a default-configured session could not send on Kotlin/Native Linux (#125) (`minor`)

`BufferFactory.Default` is a GC-heap `ByteArrayBuffer` on Kotlin/Native Linux, and socket-udp's io_uring
`sendmsg` path rejects a buffer with no native address outright. A session built from a hand-configured
`IceConfig()` / `DtlsConfig()` on linuxX64 or linuxArm64 therefore died on its **first connectivity
check** — after gathering had succeeded and the application believed it had a working session.

New `networkBuffer()` (public in `webrtc-ice`, with an internal twin in `webrtc-dtls`) is now the default
for every factory whose buffers reach a socket: `IceConfig`, `IceAgent`, `TurnAllocation`, `MdnsEndpoint`,
`MdnsResponder`, `MulticastMdnsEndpoint`, `MulticastMdnsResolver` and `DtlsConfig`.

**It resolves by asking, not by a platform table.** One throwaway 1-byte probe, cached for the process:
keep `BufferFactory.Default` where it is native-backed, fall back to `deterministic()` only where it is
not. Two things follow, and both were the point:

- **No target gets a worse factory than it has today.** On 15 of 16 targets `Default` is *already*
  native-backed **and** automatically reclaimed — `MutableDataBuffer` (ARC) on Apple, an auto-arena
  `FfmAutoBuffer` on JVM 21+, a `Cleaner`-backed direct buffer on Android/JVM 8-20, linear memory on
  wasm — so it is returned unchanged. A flat alias to `deterministic()` (which is what `socket-quic`'s
  `BufferFactory.network()` is) would have traded JVM 21's `Arena.ofAuto` for a manually-freed shared
  arena: a regression on a target that works.
- **It self-corrects.** When `buffer` gives Kotlin/Native Linux a GC-managed native buffer — the
  equivalent of Apple's ARC and the JVM's auto-arena — `networkBuffer()` picks `Default` back up there
  with no change at any call site.

`nativePeerConnection`'s own `bufferFactory` default moves from `deterministic()` to `networkBuffer()`,
so the documented path stops paying manual-free semantics on the platforms that never needed them.

**Two corrections to #125's diagnosis**, both found by checking rather than by trusting the issue:

- **`SctpConfig` is not affected**, and is deliberately left on `BufferFactory.Default`. An SCTP chunk is
  *input* to `sealApplicationData`, which copies it into a record freshly allocated from the **DTLS**
  factory (`Dtls12Handshake.encode`); an SCTP buffer never reaches a socket. This is the second wrong
  entry in that issue's table, after the Apple/`DtlsConfig` one corrected in #130.
- **It is 2 targets, not 7.** The issue counted every target whose socket demands native memory; what
  matters is where `Default` fails to supply it, and that is linuxX64 and linuxArm64 alone.

**The Linux trade is real and is not hidden.** The fallback is `malloc`-backed and freed by hand, and
this stack's receive side still has no last-reader rule, so inbound datagrams can accumulate there. It
replaces a hard crash, which is why it ships — but the end of #125 is the upstream buffer change, not
this.

`DtlsConfigBufferFactoryTest` changes shape accordingly: it used to pin the default's *identity*
(`assertSame(BufferFactory.Default, …)`) and recorded Linux as the target it "cannot fix and does not
pretend to". It now pins the stronger invariant that identity was standing in for — whatever the default
resolves to, this platform's socket can send from it — plus the anti-vacuity direction (a heap factory
must fail that check) and the no-downgrade direction (`Default` survives wherever it is already native).
`NetworkBufferTest` covers the same three properties in `webrtc-ice`. Both run in `commonTest` on every
platform; the anti-vacuity case skips only on js, where `managed()` **is** `Default` and no factory can
be distinguished from any other — a browser delegates to `RTCPeerConnection` and never hands one of these
buffers to a socket.

**API:** adds `networkBuffer()`. Purely additive — no signature changed, only default *values* — so it is
binary-compatible, but new public API, hence `minor`.
### Fixed — nothing had verified a publish since v0.14.0, and the docs said otherwise

`released.yaml` carries the post-release consumer lane: resolve the just-published version from Maven
Central and nothing else, cold, then compile, K/N-link and run the harness against it. It triggers on
`push: tags: v*`. Since #128 the release tag is created through the REST API with
`secrets.GITHUB_TOKEN`, and **GitHub does not dispatch workflow events for refs created with that
token** — so the lane stopped firing, silently, and `v0.15.0` … `v0.20.0` all shipped without it. The
tell was available the whole time: six tags, six releases, and `gh run list --workflow released.yaml`
still reporting v0.14.0 as its most recent run.

The pre-publish half was never affected — `merged.yaml`'s `consumer-smoke` job runs against the merged
maven-local repo and `publish` needs it, so a consumer-breaking artifact still could not reach Central.
What was missing was the check on the publish *itself*.

`merged.yaml` now runs `consumer-smoke-central` off `publish` rather than off the tag, so it no longer
depends on an event that does not arrive. It is gated to the `release` flow (a `draft` publish is
USER_MANAGED and has nothing on Central to resolve yet) and runs alongside `finalize` rather than
gating it. `released.yaml` stays as the fallback for a hand-pushed tag.

This is the second instance of the `CLAUDE.md` "a config the process never applied" trap, after
coturn's `-n`, and it failed the same way: a lane that should log on every release logging nothing.

### Fixed — documentation that no longer described the code

No API change; corrections only.

- **`README.md` pinned `0.14.0`** in both dependency snippets while Central was at `0.20.0` — six
  releases, several of them binary-breaking `minor` bumps. Now `0.20.0`, with a Maven Central badge so
  the next drift is visible without reading the file.
- **`ARCHITECTURE.md` §11.4 still described mDNS advertising as opt-in**, and argued structurally that a
  default of "advertise" was impossible. `nativePeerConnection` has defaulted `mdns = true` since #135,
  and the README has said so since #129. The section now states both defaults and why they differ: the
  factory is in `socketMain` and can construct the responder that makes the promise good, while a
  `commonMain` `PeerConnectionConfig` cannot, so opt-in remains correct *there*.
- **`TESTING.md` §4's no-leak invariant was stated as though enforced everywhere.** `assertNoLeaks()` is
  real (#142) but lives only in `webrtc-ice`'s vnet; the other `CountingBufferFactory` copies count
  allocations only, and the published `webrtc-testsuite` harness exposes just `allocationCount`, so a
  consumer cannot assert it at all. Restated as the standard with its actual reach, including the two
  things that bound it (the unowned receive side, and socket#277's invisibility to any factory-level
  tracker).
- **`TESTING.md`'s L4 example did not compile** — `natType(Symmetric)` unqualified and
  `impaired(loss = 5.percent)`, where the real signature is `impaired(loss: Double = 0.0, …)` and
  `percent` exists nowhere in the repo. Replaced with the form the README uses, which does compile.
- **`TESTING.md` §2's coturn table row had no second cell**, rendering as an empty column.
- **`PERFORMANCE.md`'s coverage table listed `webrtc-rtp` / `webrtc-srtp`** — modules that do not exist,
  against a stated non-goal. Replaced with the SCTP association round trip, which is measured and
  documented directly below it.

### Fixed — every TURN request was sent exactly once, over UDP

`TurnAllocation.request()` transmitted each request a single time and waited out its budget. TURN is the
only STUN client in this stack that had no retransmission: `gatherServerReflexive` has retransmitted its
Binding every 500 ms since it was written, and connectivity checks run the full RFC 8489 §6.2.1 chain
through `StunTransaction`. The relay was the exception, and each of its three requests failed differently:

- a lost **Allocate** cost the relay candidate outright, which behind a symmetric NAT is the only path;
- a lost **CreatePermission** lapsed the permission silently, in both directions (RFC 8656 §11.2);
- a lost **Refresh** ended the keep-alive loop *permanently* — `refreshAllocation` answered `null` for
  both "the server refused" and "nobody answered", and the loop treated `null` as terminal. So one
  dropped datagram on a healthy path reintroduced the exact expiry the section below exists to prevent.

Each request now retransmits every `retransmitInterval` (500 ms, the gathering RTO) until its response
arrives or the caller's budget elapses, re-slicing the same encoded request so every copy is
byte-identical. `TurnAllocationRefreshTest` drops transmission #1 of *every* TURN request and the session
is indistinguishable from a lossless one; it separately blackholes an entire Refresh transaction and the
keep-alive loop retries and recovers. Both have their anti-vacuity direction: with `retransmitInterval`
raised past the request budget, the same single dropped datagram loses the allocation outright.

### Changed — the TURN and ICE-driver seams answer with sealed types, not nulls (`minor`)

The retransmission bug above was a *typing* bug first: `null` meant both "refused" and "unanswered", and
no caller could tell them apart. The nullable returns on these seams are now sealed results, so the
distinction is one the compiler enforces rather than one a comment asks for.

- **`TurnAllocation.allocate()`** answers `TurnAllocationResult` — `Allocated(relayed)`, or
  `Unavailable.Rejected(error)` / `.NoResponse` / `.MalformedResponse`. A server that turns our
  credentials down is now distinguishable from one that never answered; both used to surface as "no relay
  candidate", which the class KDoc had flagged as the least diagnosable of the available failures.
- **`IceAgentDriver.gatherRelay()`** answers `RelayGatheringResult`, wrapping that cause rather than
  discarding it, and **`systemIceGathering()` emits it** as the new `IceGatheringNotice.RelayUnavailable`.
  A wrong TURN password reaches the application as a 401 instead of as silence.
- **`IceDataTransport.receive()`** answers `IceDataReadResult.Received`/`Closed`, mirroring
  `DatagramReadResult` one layer down — "closed" is a state of the seam, not an absent packet.

Internally `TurnMaintenance.Renewing` gains `retryAt`: an unanswered round re-arms at a twentieth of the
lifetime rather than a refusal's full cadence, spending the margin `refreshAt` always claimed to leave.

**API:** source-breaking at these three call sites, binary-breaking — `minor`.

### Fixed — a long relayed session lost its relay at the server's LIFETIME (#137)

`TurnAllocation` allocated once and then let the server's clock run out from under it. A TURN allocation
and its permissions expire independently — coturn defaults to 600 s and 300 s, both shorter than an
ordinary call — and they fail differently: the permission goes first, so the path dies while ICE is still
reporting the pair as live and only RFC 7675 consent notices, 30 s late and under the wrong name. For a
peer behind a symmetric NAT the relay is the only path, so this was "any long relayed call drops".

It now maintains itself, under a new `TurnMaintenance` policy on the constructor:

- **Refresh (RFC 8656 §8)** at a fraction of the *granted* LIFETIME — read from the Allocate/Refresh
  response rather than assumed, so a server that grants less than we asked for shortens our own cadence.
- **CreatePermission (§9) re-installation** for **every** permitted address, batched into one request.
  Every address, not just the one traffic is currently headed for: the address that lapses is precisely
  the one nothing is asking about.
- **438 Stale Nonce** handling on both — a long-lived allocation outlives the nonce it was created under,
  so the challenge is re-read and the request retried once. The key derivation is untouched.
- **Deallocation on `close()`** (Refresh with LIFETIME=0), so a closed session stops holding a relay port
  for the rest of its lifetime. It rides an atomically-started coroutine, so the socket is released even
  when the scope is being torn down in the same breath.

Both timers ride the injected scope and are exact under `runTest` virtual time (directive #2). The vnet
`TurnServer` learned configurable allocation/permission lifetimes and nonce rotation, and
`TurnAllocationRefreshTest` holds a relayed round trip across five allocation lifetimes and fifteen
permission lifetimes — with the anti-vacuity direction (`TurnMaintenance.None`) proving the same relay
dies at the first probe past the permission lifetime.

**API:** `TurnAllocation`'s constructor takes one more parameter (defaulted). Source-compatible,
binary-breaking — `minor`.

### Fixed — a default-configured session could not send DTLS records on Apple, or receive mDNS on Linux

Two instances of one defect class, both found while investigating #125: a **GC-heap** buffer factory
reaching a socket that requires a **native address**. socket-udp's Linux (`io_uring sendmsg`/`recvmsg`)
and Apple (`NWConnection`) paths reject such a buffer outright — `send requires a native-memory buffer` —
and the JVM, where every default happens to be correct, is where all our real-socket coverage lived.

- **`DtlsConfig.bufferFactory` defaulted to `managed()`**, which is a GC-heap `ByteArrayBuffer` on *every*
  target. Every record `DtlsEngine` seals is handed to the ICE transport and sent **unmodified**
  (`IceAgentDriver.send(packet)` passes it straight to the bound channel), so on Apple a session built the
  way the README documents could not put a single DTLS record on the wire. It now defaults to
  `BufferFactory.Default`, which is native-backed *and* reclaimed without an explicit free on every
  platform that needs it — `MutableDataBuffer` (ARC) on Apple, an auto-arena `FfmAutoBuffer` on JVM 21+, a
  `Cleaner`-backed direct buffer on Android. **Fixes the five Apple targets** (macosX64, macosArm64,
  iosArm64, iosSimulatorArm64, iosX64).

  The rationale the KDoc recorded for `managed()` — that a native buffer "hands BoringSSL its own address"
  — described the W4 backend and has been obsolete since the W4b flip made the engine pure Kotlin. That is
  the fifth stale premise found in this repo family; verify before propagating.

- **The mDNS sockets overrode socket-udp's per-platform receive factory**, exactly as the unicast binder
  did before #123. `MulticastMdnsResolver` and `SocketUdpMdnsBinder` both passed
  `bufferFactory = BufferFactory.Default` to `UdpSocket.bindMulticast`, replacing a validated per-platform
  allocation strategy with one that is wrong on Linux — so every *inbound* mDNS packet was unreadable
  there and queries simply went unanswered. They no longer pass one. The constructor parameter stays for
  what these types **encode**, which they do own; `SocketUdpMdnsBinder`'s now-dead `bufferFactory`
  parameter is removed (binary-breaking, hence `minor`).

### Known gap — Kotlin/Native **Linux** still cannot send with the shipped defaults (#125)

Stated plainly rather than left to be rediscovered. On linuxX64/linuxArm64 buffer's `Default` is a GC-heap
`ByteArrayBuffer` (unsendable), and its only native-backed factory, `deterministic()`, is `malloc`-backed
and must be freed by hand — which **nothing in this stack does**, because every default has always been
GC-managed and the free-tracking invariant `CountingBufferFactory` promises was never wired up. Flipping
Linux to it would trade "cannot send" for an unbounded native leak at the consent-check and per-record
rate, and it cannot be fixed by freeing after send either: `StunTransaction` emits `request.slice()` on
both the initial send *and* every retransmit, so the buffer is transaction-owned, not driver-owned.

A Kotlin/Native consumer on Linux must inject a native factory today (`BufferFactory.deterministic()`),
which is what `webrtc-harness-endpoint` has always done and why the interop matrix never saw this. The
real fix wants a GC-managed native-memory buffer from buffer itself — what Apple gets from ARC and the JVM
from `Arena.ofAuto`. Tracked on #125.
### Changed — `peerConnectionSupport()` stops claiming a capability it cannot honour (#126)

`PeerConnectionSupport` gains a third case, `Unavailable(reason)`, and js/wasmJs outside a browser now
return it instead of `Native`. **Breaking for an exhaustive `when`** over the sealed type, which is the
point — the compiler now makes every call site acknowledge the branch.

Before this, `js` under **Node** reported `Native`. The app built a `NativePeerConnection`, ICE gathered
and ran connectivity checks perfectly well, and the session then died at the **DTLS handshake** with
`DtlsFailureReason.BackendUnavailable`. A capability advertised at config time and dishonoured at connect
time, discovered at the worst possible moment. It is now a config-time fact, the same courtesy
`NetworkMonitorSupport.Unavailable(NoPlatformApi)` already extends for interface enumeration.

The two reasons are genuinely different, so they are two types rather than one string:

- **`NoBlockingKeyAgreement`** (js/Node) — UDP is *not* the obstacle: `socket-udp` publishes a full js
  actual. The one missing primitive is a **blocking raw-ECDH** premaster, because buffer-crypto's shared
  js/wasmJs `KeyAgreement` is WebCrypto and WebCrypto is async-only. Node's own `crypto.createECDH()` *is*
  synchronous, so this is fixable — tracked separately.
- **`NoDatagramTransport`** (wasmJs outside a browser) — strictly more missing: no wasm `socket-udp`
  actual at all, so there is no channel to bind. This case already contradicted its own file's KDoc, which
  said in as many words that a `NativePeerConnection` cannot run on wasm while the code returned `Native`.

Both `jsNodeTest` and `wasmJsNodeTest` now **assert** the reported value instead of silently no-opping
past it.

Also corrected while here: `systemInterfaceEnumerator`'s KDoc justified js and wasmJs together with
"there is no raw-UDP `AddressedDatagramChannel` actual on those targets". True of wasmJs, **false of js**.
The conclusion held; the reason did not.

### Added — `udpDatagramBinder()`: the production UDP seam now ships

Every consumer had to hand-write the one line that turns a virtual-time session into a real one.
`DatagramBinder` is the **only** substitution between a vnet run and a real-kernel run — the ICE agent,
the gathering drivers, DTLS and SCTP above it are byte-for-byte identical on either — and the only
implementation we shipped lived in the non-published interop peer.

- **`udpDatagramBinder(bufferFactory)`** in `webrtc-ice`, on every target where `socket-udp` publishes an
  actual (jvm, android, linux, macOS, iOS). Pass it straight to `NativePeerConnection`:
  ```kotlin
  NativePeerConnection(scope, clock, random, binder = udpDatagramBinder(), gathering, dtls)
  ```
  It is **absent**, not throwing, on the remaining targets — a browser has no raw UDP, so a call site
  that reaches for a binder there does not compile.
- It is a helper, **not** a factory: it binds when asked, owns no lifecycle and holds no state, because a
  WebRTC session and a QUIC-P2P connection are meant to share one demuxed socket and a binder that owned
  its sockets could not be composed into that (ARCHITECTURE §11.6). An app in that position keeps
  supplying its own binder, unchanged.
- **Two overloads, no defaulted buffer factory.** `udpDatagramBinder()` allocates received datagrams from
  socket-udp's own per-platform factory and offers no way to say otherwise;
  `udpDatagramBinder(bufferFactory)` overrides it with your pool (directive 6). There is no value the
  no-argument form could have defaulted to: the right factory differs per platform — NIO on the
  JVM/Android, native memory for io_uring on Linux and `NWConnection` on Apple — and only socket-udp knows
  which. The first draft defaulted to `BufferFactory.Default`, which is correct on the JVM and breaks
  **every received datagram** on Linux and Apple. Host candidates still gathered, because they are
  synthesized from the bind address and never received, so the only symptom was server-reflexive and relay
  gathering silently producing nothing.

### Fixed — ephemeral gathering advertised port 0

`IceAgentDriver.gatherHost`/`gatherRelay` built the candidate from the address they *asked* for, so
`gatherHost(ip, 0)` — bind me an ephemeral port — published `ip:0`. The candidate is well-formed on the
wire and names a place nothing lives: the peer has nowhere to send, and the only way through was
peer-reflexive discovery from whichever side punched first.

This was not a corner case. A **pinned port cannot survive an ICE restart** — the outgoing generation
keeps its sockets until the new one nominates, and no OS re-binds an address still in use — so ephemeral
binding is what a production gathering policy has to do. The port now comes from the bound channel's
`localAddress`, and so does the relay's `raddr`, which *is* that local base. The host literal deliberately
does not: a platform renders a bound v6 link-local with a `%scope` suffix our parser rejects.

Fixtures ship with it (directive #5), which meant teaching the vnet what an OS already knew:
`bind(host, 0)` now assigns from a deterministic counter over IANA's dynamic range instead of binding port
zero literally — a seam that binds `:0` quietly is a seam where this bug passes every test.
`IceEphemeralPortTest` asserts the nominated pair rides the *signalled* host candidate rather than a
peer-reflexive rediscovery, which is the only way an `ip:0` advertisement could ever have converged.

Real-socket coverage now runs on **more than one platform**, which is the lesson the buffer-factory defect
taught: `UdpDatagramBinderTest` moves into a shared `socketTest` source set (jvmTest + linuxTest, plus
macOS/iOS on a mac host) and proves the seam itself — a datagram out through a binder-bound socket, the
same datagram back, at the port the kernel actually assigned. A JVM-only version of it was green
throughout, because the JVM is precisely the platform where the wrong default is right. The fuller ICE
establishment stays on the JVM as `UdpDatagramBinderIceTest`.

### Changed — documentation is for consumers now

The README is rewritten for someone who wants to use the library: a quickstart with real wiring, the
honest platform matrix (including where the stack **cannot** establish — Node, tvOS/watchOS), and no
internal vocabulary. Its wiring block is compiled, run against real loopback UDP, and diff-checked
against the test that runs it, so it cannot rot silently.

`RFC_KMP_WEBRTC.md` becomes `ARCHITECTURE.md` — a description rather than a proposal, with `RFC §n`
citations throughout the source renamed to `ARCHITECTURE §n` (they were easy to confuse with the IETF
documents cited on nearly every adjacent line). `EXECUTION_PLAN.md` is deleted. `TESTING.md`, `CLAUDE.md`,
`MODULE.md` and `PERFORMANCE.md` lose their wave scaffolding and keep what is current.

Four stale claims were corrected in passing, three of them in published KDoc: that unifying into socket's
`SocketException` hierarchy is *blocked* by a BoringSSL symbol collision (it has not been for many
releases), that `DtlsFailureReason.BackendUnavailable` means "JVM/Android/Apple DTLS is deferred" (it
means js/wasmJs, one async-only primitive — and it is exactly why a Node session cannot establish), that
the end-to-end session fixture runs BoringSSL (it runs `PureKotlinDtls`), and that the harness's JVM peer
cannot do a real handshake (it does, in the lanes right below the claim).

### Added — we advertise our own `<uuid>.local` candidates, and answer for them (RFC 8828 / RFC 6762) (#88)

We have **resolved** a peer's `.local` candidates since #48; we never published our own. That is a privacy
asymmetry, not a functional gap: a browser hides its LAN address behind a `<uuid>.local` precisely so the
signaling server — and anyone else who sees the SDP — learns nothing about the private network, and we
handed ours over in the clear. A page using this library was strictly less private on the wire than the
same page using `RTCPeerConnection`.

- **`PeerConnectionConfig.mdnsAdvertising`** — `MdnsAdvertisePolicy.Disabled` (default) |
  `.Advertise(advertiser)`. One knob carrying the responder, because a name nothing answers costs the peer
  the candidate outright, so "advertise with nobody listening" is unrepresentable rather than discouraged.
  It is opt-in for exactly that reason: `PeerConnectionConfig` is `commonMain`, which cannot construct a
  multicast responder. On a target that has one it is a single argument:
  `mdnsAdvertising = MdnsAdvertisePolicy.Advertise(MulticastMdnsEndpoint(scope))`.
- **`MdnsEndpoint`** (`commonMain`) serves the resolver **and** the responder over **one** socket per
  family, and `MulticastMdnsEndpoint` is its socket-udp actual. Not a convenience: a responder must hold
  port 5353, and a second socket on it would take a hash-chosen share of the unicast replies to our *own*
  resolutions' queries — a 50/50 defect that reads as a flaky lane for a year. `MulticastMdnsResolver`
  remains for a session that never advertises.
- **`MdnsResponder`** (`commonMain`, sans-io) answers A/AAAA for **our own names only**, including RFC 6762
  §6.7 one-shot legacy queries (source port ≠ 5353 ⇒ unicast reply, question echoed, TTL 10) because that
  is what a resolve-only peer sends. Everything else on the group is an exhaustively typed
  `MdnsSilenceReason` (`NotOurs`, `NotAQuery`, `Malformed`, `UnsupportedType`, `NoQuestions`) — never an
  answer. It is not a general-purpose responder, and deliberately so: one that spoke for names it does not
  own would be an attack surface reachable by anything on the link.
- **Names are minted from the injected entropy seam** (`MdnsHostName.random(random)`, an RFC 4122 v4 uuid
  carrying nothing of the machine) and are **stable per address for the session**, so a re-gather after an
  ICE restart republishes the same name — two names for one interface would identify the host as loudly as
  the address.
- **Three leaks are closed, not one.** `CandidatePrivacy` (`Disclosed` | `Obfuscated(name, foundation)` |
  `Redacted(foundation)`) on `IceCandidateLine.format` also redacts the `raddr` of every reflexive/relayed
  candidate — which *is* the host base — and replaces the **foundation**, which this stack derives from the
  base IP (`host:192.168.7.31:-:udp`) and which would otherwise spell the private address out in field 1 of
  the very same line. The published foundation is a per-session random token per distinct foundation, not a
  hash: private IPv4 space is small enough that a hash would be invertible by dictionary.
- Both extra parameters of `IceCandidateLine.format` default to the previous behaviour, so a line a session
  that does not obfuscate emits is byte-for-byte what it always was.

Proven both ways, not asserted: `MdnsEndpointTest` runs two real endpoints over the vnet — one advertises,
the other knows only the name and resolves it — with only the 5353 bind/join substituted, and the
`mdns-{chrome,firefox}` interop lanes now gate on **Chrome having queried a name it could only have read off
our candidate line** (`WEBRTC_REQUIRE_MDNS_ANSWERED`). With the responder made mute, Chrome still
establishes and still exits 0; only those assertions go red.

### Added — trickled candidates carry the ICE generation they belong to (RFC 8838 §3.1) (#70)

A trickled candidate used to arrive with no generation attached, so it was applied to whichever generation
happened to be current when it landed. Across an ICE restart (RFC 8445 §9) that is a real window in both
directions: a candidate for the peer's *new* generation can overtake the offer announcing it, and one for
its *old* generation can arrive after we have moved on. Untagged, the first is naturalized into a
generation about to be abandoned and dies with it. It survived on two things nobody chose — signaling
being in order, and RFC 8445 §7.3.1.3 peer-reflexive learning rediscovering the path afterwards.

- **`CandidateGeneration`** (`Untagged` | `Tagged(Ufrag)`) is now carried on `IceEvent.AddRemoteCandidate`,
  `IceAgentDriver.addRemoteCandidate`, `CandidateParse.Parsed`/`MdnsHost`, and `IceCandidateLine.format`.
  The agent **routes** on it — applied / superseded / not-yet-applied — instead of guessing.
- **A candidate for a superseded generation is discarded on purpose, and says so**: a new
  `IceOutput.RemoteCandidateDiscarded(candidate, CandidateDiscardReason)`. A candidate dropped in silence
  is indistinguishable from one that never arrived, which is why the one path that throws candidates away
  is the one path that reports.
- **A candidate for a generation whose offer has not arrived yet is held**, bounded at **32** (one FIFO
  across generations, oldest evicted first with a typed overflow reason) and released by the *credentials
  event*, never by a timer — `nextDeadline` is untouched and the core stays sans-io. The retired-ufrag set
  is bounded at 8.
- **Both ufrag carriers are honoured.** `RtcPeerConnection.addIceCandidate(candidate, generation)` mirrors
  the W3C `RTCIceCandidateInit.usernameFragment` (the browser delegates forward it verbatim), and the
  `ufrag` extension attribute (RFC 8839 §5.1) that libwebrtc has stamped on candidate lines for years is
  read off the line. Explicit wins when given; `a=candidate:` lines inside a description are tagged with
  that description's own `a=ice-ufrag`. The one-argument `addIceCandidate(candidate)` remains, as a
  default interface method — **no existing call site changes, and its binary signature is preserved**.
- **Our own trickled candidates are stamped** with the generation that gathered them, taken inside the
  driver's serialized loop so a candidate cannot be tagged with a generation it is not in.
- **Untagged stays untagged.** A candidate carrying no ufrag is applied to the current generation exactly
  as before — the path every peer in the interop matrix uses. Routing that arm as "hold" instead takes
  down 40 of 114 `webrtc-ice` tests, which is the measure of how load-bearing it is.
- **`PeerConnectionConfig.trickleGeneration`** (`TrickleGenerationPolicy.Tagged` | `.Untagged`) turns the
  whole behaviour off in both directions in one line, for a peer whose tags cannot be trusted.

What it buys is measured, not asserted: `PeerConnectionRestartTest` now converges on the **signaled**
`Host` pair where it previously converged peer-reflexively, and `PeerConnectionTrickleGenerationTest` runs
one scripted overtake (candidates released *before* the offer naming them) under both policies — `Host`
tagged, `PeerReflexive` untagged — so the two differ in one config value and nothing else.

### Changed — **SOURCE BREAKING**: `IceAgentDriver.localCandidateGathered` yields a `GatheredCandidate`

`Flow<IceCandidate>` → `Flow<GatheredCandidate>` (the candidate plus the `Ufrag` of the generation it
landed in). Signaling a candidate without saying which generation gathered it is what made a restart's
candidates ambiguous on the wire; a driver always knows the answer, and reading it from the gathering side
instead returns the *old* ufrag for a candidate a restart has already placed in the new generation.
Consumers collecting this flow take `.candidate` (and may now stamp `.ufrag`).

### Changed — **SOURCE-BREAKING** (`webrtc-sdp`): rollback is an event, not a null argument (#77)

`JsepEvent.SetLocalDescription` and `JsepEvent.SetRemoteDescription` were each a `data class(type, description?)`
that could express two illegal states. `SetLocalDescription(SdpType.Rollback, someDescription)` was
constructible and the machine answered it with **silence** — the rollback arm restored the stable snapshot
and never read the argument. `SetLocalDescription(SdpType.Offer, null)` was constructible too, and needed a
runtime `JsepError.MissingDescription` to police from the other side a combination the type should never
have permitted. Both endpoints had the defect; both are fixed the same way.

Each is now a sealed interface with `Apply(type, description)` and a `Rollback` object. `Apply` takes the
new `AppliedSdpType` (`Offer | PrAnswer | Answer`) rather than `SdpType`, so rollback-with-a-description is
not merely discouraged but unrepresentable — the shape proposed in the issue kept `SdpType` and would have
left that half of the defect standing. `JsepOutput.DescriptionApplied.type` narrows to `AppliedSdpType` for
the same reason: a rollback applies nothing and can no longer claim to have applied something.

- **Removed**: `JsepError.MissingDescription` and its runtime check. An exhaustive `when (error)` over
  `JsepError` must drop that branch — the compile error is the point.
- **Migration**: `SetLocalDescription(type, sdp)` → `SetLocalDescription.Apply(AppliedSdpType.of(type)!!, sdp)`;
  `SetLocalDescription(SdpType.Rollback, null)` → `SetLocalDescription.Rollback`. `AppliedSdpType.of` returns
  null for exactly `SdpType.Rollback`, which is how a caller holding a W3C-shaped `SdpType` branches.
- No behaviour change: `RtcPeerConnection.setLocalDescription`/`setRemoteDescription` still take the
  4-valued `SdpType`, and no in-tree caller was affected. The win is entirely for out-of-tree consumers of
  `webrtc-sdp`, the module most likely to be used standalone.

### Added — `a=tls-id`: the explicit statement of DTLS association continuity (RFC 8842 §5.3/§5.5, #72)

We now emit `a=tls-id` in every offer and answer and honour the peer's. RFC 8842 §5.5 uses it as the
explicit signal of whether a re-offer wants the **existing** DTLS association or a new one, where an
unchanged `a=fingerprint` only implies it — so a peer asking for a fresh association can now say so, and is
refused with `DtlsFailureReason.NewAssociationRequested` rather than only being caught by the role-flip
heuristic behind `RoleChangeOnRenegotiation`.

- `TlsId` is a `@JvmInline value class` enforcing the §5.3 grammar (`20*(token-char)`) at construction;
  `TlsId.fromValue` is the total, null-on-malformed parse and `TlsId.random(Random)` draws 144 bits from
  the **injected** entropy seam (directive #2), never `Random.Default`.
- `SdpSection.tlsId(): TlsIdAttribute` is a three-way typed read — `Absent | Present | Malformed` — because
  absent and malformed are different facts. Absent is legal and expected; malformed is a typed reject.
- **Backward compatibility is the feature.** Ours is drawn once per session and never redrawn, so an ICE
  restart re-offers the same value (§5.5: a restart renegotiates ICE and nothing else). A peer that sends
  no `a=tls-id` — which is every peer in the interop matrix — behaves exactly as before, and a malformed
  one falls back to fingerprint inference rather than failing a session the fingerprint vouches for.
  Honouring tls-id only ever *adds* a reason to refuse; it never removes a reason to keep an association.
- `DataChannelParameters.tlsId` defaults to `null` (emit nothing), so an existing caller's SDP is
  byte-identical. `DtlsFailureReason` gains one case, which re-exhausts any `when` over it.

### Removed — **BREAKING**: two public types that named states this stack cannot be in (#83, #82)

Both are removed in the same release deliberately: they are the same defect for the same reason, and
splitting them would make consumers re-exhaust a `when` twice.

**`IceConnectionState.Disconnected` (#82).** The W3C `RTCIceConnectionState` "disconnected" value —
connectivity lost but possibly recoverable. The agent never emitted it, and once RFC 7675 revocation
became terminal it cannot: §5.1 requires a new session or an ICE restart, so consent loss goes straight
to `Failed(ConsentExpired)`. A state meaning *"may recover if a check succeeds again"* describes exactly
the resurrection that #75 removed — modelling it would be modelling a bug. A consumer wanting the W3C
vocabulary maps `Failed` to "failed"; nothing is lost. Only one exhaustive `when` in the repo listed it
(a test helper); `.ci/consumer-smoke` exhausts `PeerConnectionState`, which is unaffected.

**`CandidatePairState` (#83).**

`webrtc-ice` no longer exports `CandidatePairState`. It was public API with **no consumer** — it named
no public signature and was referenced only from inside `IceAgent` — while the agent kept the pair's
in-flight STUN transaction in a *separate nullable field beside it*. Those two fields desynchronised,
and the desync shipped a bug: `clearTransaction` dropped the transaction without touching the state, so
a consent check that timed out left its pair `InProgress` **with nothing in flight, permanently**. The
parked pair then counted as pending in `maybeComplete` (so the agent could never reach `Completed`) and
made `onInboundCheck` take its `InProgress` arm forever — which is what hid the consent-resurrection
bug (#75) for as long as it existed.

The checklist state is now `IceAgent`'s private sealed `CheckState`, whose `InProgress(check)` case
carries the transaction, so retiring a check cannot be written without also saying what the pair
becomes. Nothing public replaces it: the checklist is the agent's own business, and `IceConnectionState`
+ `IcePath` are what a consumer actually observes. The `valid` flag went with it — written only in
lockstep with the state, read only under `allDone` where it could never disagree.

`Generation.remoteCredentials` also stopped being a nullable read through two `!!` (#84); it is a sealed
`RemotePeer` (`Unsignaled | Signaled`), matching the shape the session layer already uses for the same
fact. That one is internal — no API change.

### Fixed — RFC 7675 consent: expiry is terminal (#75), and checks pace instead of retransmitting (#73)

Two defects in the same seam, filed separately and fixed together because **the second was hiding the
first**, and either one alone leaves the agent worse off than both.

- **Consent checks are no longer retransmitting STUN transactions** (#73). RFC 7675 §4.1 sends a fresh
  Binding request with a new transaction id *"transmitted once only"* and paces the next independently.
  Running them through `StunTransaction` instead produced one exponential backoff chain — at the RFC
  defaults, 7 requests spanning **39.5 s against a 30 s revocation window** — which front-loaded every
  probe (0, 0.5, 1.5, 3.5, 7.5, 15.5 s) and then left the last ~16 s before revocation with nothing in
  flight at all. A path that went down and *recovered* inside its own revocation window was declared dead
  anyway, because our retransmit schedule had stopped asking. Checks now go out at a jittered
  0.8–1.2 × `consentInterval` per §4.1, several may be outstanding at once (a path whose RTT exceeds the
  interval must still be able to refresh consent), and the outstanding-id set is bounded by the revocation
  window. `IceRelayLossTest`'s long-standing `Failed(ConsentExpired)` at `loss=0.20 seed=810004` was this.
- **Consent expiry is terminal for the generation** (#75). Expiry used to null the selected pair and go
  `Failed(ConsentExpired)` while leaving the checklist entry `Succeeded` — so `selectPair`'s "first
  nomination wins" guard, which tested only the null, came undone and the next inbound check put the agent
  straight back to `Connected` **on the pair whose consent had just died**. RFC 7675 §5.1 is explicit that
  this is not allowed: *"the same ICE credentials MUST NOT be used on the affected 5-tuple again ... a new
  session, or an ICE restart, is needed"*. A revoked generation now runs no checks, takes no nomination,
  answers nothing, clocks nothing, and is not retained across a restart; recovery is `restartIce()`, and
  that path is tested end to end.
- **The interaction is the reason they are one change.** `startCheck` marks a pair `InProgress`, so while a
  consent check was outstanding — which, with a 39.5 s chain, was essentially always — an inbound check hit
  the `InProgress` arm and was swallowed. Fixing the pacing alone leaves the pair `Succeeded` and **activates**
  the resurrection; this was confirmed by staging the two fixes and watching the #75 fixture go from green
  to red in between. It also explains why #75 stayed invisible for so long: the resurrection republishes
  `path` as `Nominated`, so a fixture reading the pair afterwards sees a healthy agent.

Internally, a generation's nomination is now a sealed `Selection` (`None` | `Nominated` | `Revoked`) rather
than a nullable pair beside a boolean, so "nominated and revoked at once" is unrepresentable and every call
site must say which of *never*, *now* and *no longer* it means. `CheckPurpose.Consent` is gone: a consent
check is not a pair check. `IceConnectionState.Disconnected` is gone (see above) — consent loss is not
recoverable in place, so the state had nothing left to describe.

### Added — ICE restart / renegotiation through JSEP (RFC 8445 §9), with the session surviving it

- **`RtcPeerConnection.restartIce()`** — W3C-faithful: records the intent, and the **next** `createOffer()`
  carries fresh ICE credentials and re-gathered candidates. The deferred shape is why the browser delegate
  maps 1:1 onto `pc.restartIce()` instead of approximating it.
- **The association survives the restart.** DTLS and SCTP do not renegotiate (RFC 8842 §5.5: continuity is
  signaled by the *unchanged fingerprint*, not by the `a=setup` value, so a re-offer keeps `actpass`), every
  open data channel stays open on its stream id, and application data keeps riding the old pair until the
  new generation nominates — the RFC 8445 §9 guarantee, now stated and tested rather than accidental.
- **`PeerConnectionState.Restarting(path)`** names the window, and `runEstablishment` gained a monitor on
  the ICE path so a *mid-session* pair change is finally observable above ICE at all.
- **Peer-initiated restarts** are detected from a remote **offer** whose ufrag *and* pwd both changed (§9
  requires both) — without it our checklist stays bound to a password the peer no longer knows. Answers are
  deliberately exempt: an answer to our own restart offer always carries new credentials, and treating that
  as an independent restart makes both sides restart each other forever.
- **`setLocalDescription(Rollback)` gained its ICE half** (`IceEvent.RollbackRestart`): an abandoned restart
  offer restores the retained generation instead of leaving the agent advertising credentials no peer has
  ever seen.
- **`IceRestartPolicy`** (`Manual` | `OnNetworkChange(monitor)`) on `PeerConnectionConfig`, over the
  webrtc-owned `NetworkMonitor` seam (declared since W3, wired to nothing until now — and deliberately not
  socket's, which lives in socket *core* and vendors a second BoringSSL). Narrow by design: it restarts only
  when the interface carrying the **selected pair's base** goes away, never on any interface-set change, so
  a VPN or virtual adapter coming up cannot churn a healthy session. `Manual` is the default until a target
  ships a real OS-interface actual.
- **`RtcPeerConnection.renegotiationNeeded: Flow<Unit>`** (W3C `negotiationneeded`). A session cannot
  renegotiate on its own — it does not own the signaling channel — so this is what makes the automatic
  policy a feature rather than an intent recorded into a field nobody reads.
- **`s8/restart` interop phase** over a new `carrier-switch` topology, against our own peers.

### Changed — **SOURCE BREAKING**: `PeerConnectionState.Connected` carries a `SelectedPath`

- `Connected(selectedPair: CandidatePair?)` → `Connected(path: SelectedPath)`, where `SelectedPath` is
  `Known(pair)` | `Opaque`. The old null meant "this backend owns pair selection internally" — a fact about
  the *browser delegate* that read at every call site as the far more alarming "there is no pair". Adding
  `Restarting` to the same sealed hierarchy breaks every consumer `when` at compile time, which is the
  intent: a caller that treats a restarting session as connected-and-fine will mis-handle the pair change.
- `IceOutput.SelectedPairChanged(pair)` → `IceOutput.PathChanged(IcePath)` and
  `IceAgentDriver.selectedPair: CandidatePair?` → `path: StateFlow<IcePath>`, where `IcePath` is
  `Unnominated` | `Nominated(pair)` | `Restarting(previous)`. Data continuity across a restart used to work
  *only because* the driver's selected-pair field was never cleared — the right behaviour arrived at by a
  bug, which nothing stated and nothing tested.
- New typed reason `DtlsFailureReason.RoleChangeOnRenegotiation`: a re-answer implying the opposite DTLS
  role is asking for a new association, which we do not do underneath an ICE restart. Refused rather than
  silently ignored, which would leave the peer handshaking against a role we never adopted.

### Fixed — two loss fixtures were asserting over a stale pair

- `IceRelayLossTest` (loss=0.20, seed=810004) converges and *then* legitimately loses RFC 7675 consent while
  its partner is still converging. It passed anyway, because the post-hoc `selectedPair` read returned a pair
  the agent no longer had. Verified against `main`: same seed, same `Failed(ConsentExpired)` — pre-existing
  and masked, not introduced. Both it and `IceNominationLossTest` now read the pair off the state that
  *proved* convergence.

### Added — W7 interop test-matrix expansion: a WebKit (Safari engine) browser lane
- **`webkit-interop` + `jvm-webkit` scenarios** — our offerer (native and JVM) establishes a full WebRTC
  data channel over real NAT kernels against a real headless **WebKit** (Safari's engine, via Playwright's
  cross-platform build — Apple's libwebrtc fork + its own build), echoing `ping`→`pong`. A **third**
  independent browser oracle beyond Chrome + Firefox, and the only way to exercise the Safari family in
  Linux CI without a Mac.
- WebKit exposes **no pref to disable mDNS host-candidate obfuscation** (unlike Chrome's flag / Firefox's
  pref), so it emits `.local` host candidates our peer can't resolve — its lane connects via the coturn
  **srflx/relay** path instead (our ICE agent skips the unresolvable hosts). This exercises the
  relay-carried path against a real browser as a side benefit.
- **Wiring:** the existing `BROWSER`-parameterized image already builds WebKit (`--build-arg BROWSER=webkit`
  → `playwright install webkit`); `driver.mjs` gains a `webkit` launcher (the in-page answerer is
  engine-agnostic W3C APIs); `docker-compose.yml` adds the profile-gated `webkit` service (drop-in for
  `peer_b`); `run-interop.sh` gains the `webkit` `b_impl` case + the two scenarios; `harness-l2.yaml`'s
  `l2-browser` matrix adds `webkit` to its `browser` axis (now `{arch × [chrome,firefox,webkit] × [native,jvm]}`),
  and the `l2` job's `HARNESS_SKIP` drops the two new browser scenarios. `README.md` documents the lane.

### Changed — harness peer dumps its full `PeerConnectionState` transition history on exit
- The interop peer now records every `PeerConnectionState` transition (timestamped off the injected clock
  seam) and prints the whole history on exit, not just the final state. The signal that pins a lossy-path
  handshake stall is the **asymmetry** of the two peers' terminal states — one `Connected` while the other
  never leaves `Connecting` (the lost-final-flight deadlock, PR #27). A single final-state line hid that;
  the timestamped history makes it obvious in each side's log, which the L2 harness already captures and
  uploads as an artifact on failure — so an intermittent CI failure is now diagnosable from that artifact
  without a local reproduction (the exact trace that would have screamed "lost final flight" immediately).

### Fixed — DTLS post-Established handshake-record storm that starved the SCTP handshake under loss
- **The bug (a regression the lost-final-flight fix introduced):** that fix has an `Established` endpoint
  re-send its last flight whenever a handshake-epoch record arrives afterwards (so a peer whose final flight
  was lost can still complete). But the re-send is itself a handshake-epoch record, so **two peers that both
  finished echo each other's re-sends forever** — an unbounded handshake-record storm. It didn't surface in
  the DTLS-only gate (that returns the instant both establish) but wedges the **full stack**: SCTP's
  four-way handshake rides over DTLS as application data, and the storm floods the transport so the SCTP
  `INIT`/`INIT-ACK` never get through. Symptom: both peers `Established` at DTLS but one sits in SCTP
  `CookieWait`/`Closed` — i.e. `PeerConnectionState` stuck at `Connecting` — until the watchdog. This is the
  intermittent `impaired-loss-delay` L2 failure the harness's new per-side state trace localized.
- **The fix (`Dtls13Handshake` **and** `Dtls12Handshake`):** rate-limit the post-Established re-send to at
  most once per `INITIAL_RETRANSMIT` (1 s). A genuinely lost final flight draws the peer's **timer-spaced**
  (≥ 1 s) retransmit and each still gets a response, but the peer's **immediate echo** of our own re-send
  (sub-RTT ≪ 1 s) is suppressed — so the mutual storm dies after a single exchange. The lost-final-flight
  deadlock fix is fully preserved.
- **Deterministic fixtures (directive #5):** `DtlsSctpLossReproductionTest` (webrtc) drives the exact
  `runEstablishment` composition **minus ICE** — a real `DtlsEngine` + `SctpAssociation` per peer, SCTP
  packets tunneled as DTLS application data — over a seeded per-datagram lossy pipe under virtual time.
  Before the fix, 5 % loss stormed **~20 % of seeds** (`dtls=Established sctp=CookieWait`); after, a full
  DTLS→SCTP establishment **always** completes at 5 %/10 % loss (both 1.2 and 1.3) with zero storms and zero
  deadlocks at any rate. `SctpLossReproductionTest` (webrtc-sctp) is the sibling that proves the SCTP
  four-way handshake is loss-robust **in isolation** — pinning the fault to the DTLS↔SCTP boundary, not
  either layer alone. Byte-exact BoringSSL interop is unchanged (the linuxTest differentials still pass).

### Fixed — DTLS lost-final-flight deadlock (a handshake could hang under packet loss)
- **The bug:** on a lossy path, if the peer that sends the **last** handshake flight had a record of that
  flight lost, the handshake **deadlocked** — the sender sat `Established` while the receiver stayed
  `Handshaking`, retransmitting into a peer that ignored it, until the driver's 30 s `handshakeTimeout`
  fired (`DtlsFailureReason.HandshakeTimeout`). Two causes, both fixed in `Dtls13Handshake` **and**
  `Dtls12Handshake` (the last flight is the client's in 1.3, the server's in 1.2):
  1. An `Established` endpoint **ignored** the peer's retransmitted flight (the reassembler deduped the
     already-seen messages to nothing) instead of retransmitting its own last flight. Now, per **RFC 6347
     §4.2.4 / RFC 9147 §5.8.1**, a handshake-epoch record arriving after we finished triggers a re-send of
     our last flight (detected from the record header, no decrypt needed).
  2. `cancelRetransmit()` on every reassembled message dropped our retransmit timer even on a **partial**
     peer flight, so a lost final message could leave us making progress but with **no armed timer** — we
     stopped retransmitting and stalled. The timer is now re-armed (at the initial interval) whenever we
     are still handshaking with an unacked flight.
- **Deterministic fixture (directive #5):** `DtlsLossReproductionTest` drives two pure engines over an
  in-memory per-record-datagram lossy pipe under the engine's virtual clock — seeded, zero wall-clock,
  flake-free. Before the fix, 5 % loss deadlocked ~16 % of seeds (all `Established/Handshaking`); after, a
  full mutually-authenticated handshake **always** completes within budget at 5 %/10 % loss (both DTLS 1.2
  and 1.3), with zero deadlocks at any rate. This is the deterministic sibling of the real-`netem`
  `impaired-loss-delay` L2 lane (which surfaced the intermittent failure but, being kernel-random, could
  not pin it down). Byte-exact BoringSSL interop is unchanged (the linuxTest differentials still pass).

### Added — W7 interop test-matrix expansion: a JVM interop peer (the pure engine on the real wire)
- **`:webrtc-harness-endpoint` is now multiplatform** — it targets the **JVM** alongside Kotlin/Native
  (linuxX64 + linuxArm64). Since the W4b flip DTLS is pure-Kotlin `commonMain` on every target, so the JVM
  now composes the identical production stack (`NativePeerConnection` + `PureKotlinDtls`) over **socket-udp's
  NIO datapath** — a first-class interop endpoint. The shared harness code compiles per-target (the
  KSP-codec layout, now incl. the JVM); the ONLY per-platform code is `readEnv` (`System.getenv` vs posix
  `getenv`). A `peerJar` task assembles an **arch-independent** fat jar (`java -jar` runnable) — one build
  serves both arch runners, unlike the per-arch native `.kexe`.
- **`jvm-native` / `jvm-pion` / `jvm-chrome` / `jvm-firefox` scenarios** — our **JVM** offerer (`peer_a_jvm`,
  a drop-in for the native `peer_a`) establishes a full WebRTC data channel over real NAT kernels against
  our native answerer, Pion (DTLS 1.2), and the real headless browsers Chrome + Firefox (DTLS 1.3), echoing
  `ping`→`pong`. This proves the pure engine on the real wire from a managed runtime — before this, "we
  support JVM" rested on unit tests + compile alone; no JVM peer had established against a real
  browser/Pion.
- **`JvmRealUdpLoopbackTest`** — the deterministic sibling that runs in the ordinary `./gradlew build` (no
  Docker): two JVM peers establish ICE → **pure-Kotlin DTLS 1.3 (X25519)** → SCTP → data channel over real
  **loopback UDP** and echo. Observable-state assertions under a watchdog (directive #4); settles in <1 s.
- **Wiring:** `docker-compose.yml` adds the profile-gated `peer_a_jvm` service (offerer drop-in on
  `lan_a`/`PEER_A_IP`; **no `seccomp=unconfined`** — NIO, not io_uring — only `NET_ADMIN`); `run-interop.sh`
  gains an `a_impl` (offerer `native|jvm`) matrix column beside `b_impl`, resolving the jar the same three
  ways as the native binary and comma-joining compose profiles; `harness-l2.yaml`'s single `build-peer` job
  also assembles the jar once and uploads it (`peer-jar` artifact), the `l2` job runs `jvm-native` +
  `jvm-pion`, and the `l2-browser` matrix gains a `{native, jvm}` offerer axis — every run-only lane reuses
  the build-once artifacts (no per-platform recompile). `peer-jvm/` holds the JVM peer image
  (self-building + prebuilt); `README.md` documents the lanes.

### Added — W7 Phase 2(b): headless-browser interop lanes (Chrome + Firefox) + wasmJs browser delegation
- **`chrome-interop` + `firefox-interop` scenarios** — our native `linuxX64` offerer establishes a full
  WebRTC data channel against a real **headless browser** (Playwright, `test-harness/browser/` — one
  `BROWSER`-parameterized image, two engines) over **DTLS 1.3** (the native peer runs at its production
  default — the opposite of the Pion 1.2 lane), and echoes `ping`→`pong` bidirectionally across a
  port-restricted NAT. Two differential oracles beyond Pion: **Chrome** (Chromium's libwebrtc / BoringSSL /
  dcSCTP) and **Firefox** (a *fully independent* stack — **NSS** DTLS, **nICEr** ICE, **usrsctp** — sharing
  nothing with Chrome). **Both runtime-validated on this box** — native offerer CONNECTED at DTLS 1.3, the
  browser `received "ping" (string=false)` → `echoed "pong"` → offerer got `pong`.
- **Rendezvous HTTP face** — a browser has no raw UDP, so `rendezvous.py` grew a threaded HTTP front door
  (`POST /put` + `GET /poll`, CORS-open) onto the **same** in-memory mailbox the UDP peers use (shared under
  a lock). A browser and a native peer therefore meet in the same slot: the native offerer PUTs its offer
  over UDP, Chrome polls it over HTTP; Chrome PUTs its answer over HTTP, the native peer polls it over UDP.
  Backward-compatible — the native UDP lane still establishes unchanged.
- **wasmJs `peerConnectionSupport()` delegation** — the last open W6 browser gap closed. The wasmJs actual
  now delegates to the browser `RTCPeerConnection` for real (was `NotImplementedError`), mapped through the
  `@JsFun` / `JsString` wasm-interop bridge (opaque `external interface : JsAny` handles; data-channel
  payloads cross as byte-faithful lowercase hex — no `ByteArray`, no webgl externals). **Runtime-validated
  in a real headless Chrome** via a new `wasmJsTest` loopback (mirror of the js delegation Karma test);
  green on `wasmJsBrowserTest` (ChromeHeadless) and no-ops on `wasmJsNodeTest`.
- **Wiring:** `docker-compose.yml` adds profile-gated `chrome` + `firefox` services (drop-ins for the native
  `peer_b` on `nat_b`/`PEER_B_IP`, DTLS 1.3 default, mDNS host-candidate obfuscation disabled per engine so
  our parser is fed real-IP candidates); `run-interop.sh` gains `b_impl=chrome|firefox` cases + the two
  scenarios, plus a positional **allowlist** and a `HARNESS_SKIP` **skiplist** for scenario selection;
  `harness-l2.yaml` runs the browsers as a parallel **`{arch × browser}` matrix** (`l2-browser`) split from
  the native `l2` job (which uses `HARNESS_SKIP` to drop them) — each image builds natively per-arch inside
  its job (Playwright fetches the per-arch engine), no cross-compile, no QEMU; `README.md` documents it.
- **CI cost tuning:** the browser image uses a **Node 24 (current LTS) `-slim` base** (~43% smaller — chrome
  2.0→1.2 GB, firefox 1.8→0.9 GB; Node 20 is EOL) with **Playwright 1.54**, and the `l2-browser` jobs build
  it through a persistent **buildx + gha layer cache**
  (`docker/build-push-action` with `cache-from/to: type=gha`, `load`), so the `playwright install` (engine
  download) layer is restored from cache after the first run instead of re-downloaded. run-interop.sh now
  **builds the peer images first, then starts both peers together in one `up`** (`HARNESS_NO_BROWSER_BUILD=1`
  reuses the cache-warmed image) — which also fixed a latent ordering fragility where starting the offerer
  and answerer in two separate `up` commands could make the offerer skip publishing its offer.
- **Fixed (harness bug this surfaced):** `run-interop.sh`'s scenario loop read the scenario list from
  **stdin**, which `docker compose exec` (the netem `impaired` lane) attaches to and drains — so the matrix
  silently stopped after the first netem scenario, running **7/9** and never reaching `pion-interop` or
  `chrome-interop` (masked until now because Phase 2(a) validated Pion via the single-scenario path). The
  loop now reads from a dedicated fd (`3<<<`), out of reach of any inner command's stdin, so the full matrix
  runs all nine — verified locally: **9/9 pass**, both interop lanes included.

### Added — W7 Phase 1: L2 container harness (native peers ⇄ real NAT kernels)
- **`:webrtc-harness-endpoint`** — a non-published Kotlin/Native executable (`linuxX64` + `linuxArm64`) that
  composes the production `NativePeerConnection` + `BoringSslDtls` over **real UDP** (`socket-udp`) and runs
  as a container endpoint. Config from `WEBRTC_*` env; offer/answer/candidates exchanged over a **UDP
  rendezvous** (a buffer-codec KSP-generated wire schema — the native peer can only link `socket-udp`, not
  socket core/quic, without a BoringSSL duplicate-symbol break); proves the data path with a `ping`/`pong`.
  Applies a new `webrtc.native-executable` build-logic convention (KGP+KSP on one classloader).
- **`test-harness/`** — a docker-compose L2 harness (mirrors socket's): real **coturn** STUN/TURN, a UDP
  **rendezvous** relay, two **NAT gateways** implementing all four RFC 4787 profiles (full-cone /
  address-restricted / port-restricted / symmetric — iptables, fidelity documented), **netem** impairment,
  and two peer containers. `run-interop.sh` drives the scenario matrix (each profile + relay-only + impaired)
  and asserts a two-peer establish + echo in each; `harness-l2.yaml` runs it arch-matched (x64 + arm64).
  **7/7 scenarios pass** locally: two peers establish real ICE → BoringSSL DTLS → SCTP → data channel across
  real Linux NAT kernels.
- **Hardened (real-network bugs the vnet never surfaced):** `webrtc-ice` gathering now threads
  `IceConfig.bufferFactory` into `gatherServerReflexive` (additive param) + `TurnAllocation` — a heap buffer
  is rejected by `socket-udp`'s io_uring `send`, so real srflx/relay gathering needs the injected native
  factory — shipped with its deterministic fixture (`GatheringBufferFactoryTest`, all platforms; proven to
  fail against the pre-fix code). Also documented: io_uring needs `seccomp=unconfined` under Docker, container-router forwarding
  needs host `bridge-nf-call-iptables=0`, and the answerer lingers before teardown so the final `pong` is
  reliably delivered.
- **Adversarial-review gate (5 parallel lanes; confirmed defects fixed + fixtures):**
  - **Signaling correlation + leak** — the UDP rendezvous replies carried no correlator, so a delayed/duplicate
    reply could offset a socket by one and mis-pair every later reply (an answer-SDP fed into `addIceCandidate`,
    a candidate silently dropped); and received datagram payloads were never freed. Fixed: a per-request
    `nonce` echoed in `MailboxResponse`, `awaitReply` drains + frees any non-matching datagram, request freed
    in `finally`, signaling sockets closed after teardown. Fixture: `SignalingCorrelationTest`.
  - **webrtc-ice fixture rigor** — added a driver-level test proving `IceAgentDriver` threads
    `config.bufferFactory` into **both** `gatherServerReflexive` (srflx) and `TurnAllocation` (relay) —
    reverting either wiring line now fails a test (the function-level tests alone did not catch it).
  - **NAT `address-restricted` fidelity** — the `recent`-module rules were dead code (a terminating baseline
    `ACCEPT` preceded them), silently degrading the profile to port-restricted; the recorder now inserts at the
    head of `FORWARD` so the profile is genuinely address-dependent.
  - **Harness hygiene** — `.dockerignore` (the peer build context was the whole repo); the host
    `bridge-nf-call-iptables` sysctl is captured and **restored** on teardown; the impaired lane now
    **fails hard** if netem can't apply (was silently running unimpaired); `no-new-privileges` added alongside
    the io_uring `seccomp=unconfined`.
  - Refuted: the TURN long-term-key concern (relay-only establishes empirically — coturn accepts the peer's
    short-term MI; the long-term-key derivation is a pre-existing, documented L3/real-TURN follow-up).

### Added — W4: `webrtc-dtls` — real BoringSSL DTLS 1.2/1.3, wired into `PeerConnection`
- **`DtlsEngine`** — a caller-clocked, sans-io DTLS endpoint (`expect class`; ARCHITECTURE §5.1): `start` /
  `onDatagram` / `onTimeout` / `send` / `beginClose` + `nextTimeoutMicros`, all in epoch-micros from the
  driver's injected clock. No dispatcher, no `Clock.System`, no I/O, no coroutine inside it. BoringSSL's
  DTLS timers are driven through an injected `current_time_cb`, so a whole handshake — **retransmissions
  included** — replays under `runTest` at zero wall-clock. Sealed `DtlsState`
  (Handshaking/Established/Closed/Failed) + sealed `DtlsFailureReason` (directive #3); `DtlsConfig` seams
  (`bufferFactory`, `enableDtls13`, `handshakeTimeout`).
- **The Kotlin/Native BoringSSL backend (Linux x64 + arm64)** — `webrtc-dtls` provisions a **same-commit**
  (`63893acb`) `libssl.a` and links **only** that, letting libssl's undefined `AES_*`/`SHA256_*` resolve
  against buffer-crypto's single already-linked `libcrypto` — no second copy, so no duplicate-symbol clash
  (`DtlsBackendLinkNativeTest` is the tripwire). Self-signed P-256 certificate + `X509_digest`
  fingerprints, DTLS-SRTP exporter + `use_srtp` (ready for Phase-2 media). The FFI buffer edge is a
  fast/slow split: a native-backed buffer hands BoringSSL its own address (zero staging copy — pass a
  pooled native factory in production), a GC-heap buffer stages through one reusable per-engine native
  scratch. No `ByteArray` anywhere (directive #1).
- **§11.3 resolved on evidence: min DTLS 1.2 / max 1.3, 1.3 ON by default.** Verified by search, not
  assumed: Firefox ships DTLS 1.3 in Release and Chrome/BoringSSL has it on by default (libwebrtc flipped
  in 2025). The 1.2 floor stays purely for breadth — Pion's released v3 is still 1.2-only — and negotiation
  falls back automatically. **Both versions are asserted by tests**, never assumed.
- **`BoringSslDtls`** (webrtc root) — the coroutine **driver** that replaces `PlaintextDtls`: one pump
  coroutine owns the engine and serializes every interaction with it (inbound records from the ICE seam,
  outbound application data, expired DTLS timers) through a single `select`, exactly as `IceAgentDriver`
  clocks the ICE core — which is what makes the not-thread-safe engine safe by construction. It exposes the
  established engine as the `SctpDatagramTransport` the data-channel stack already rode, so DTLS was **a
  swap, not a rewrite**: nothing above (SCTP/PeerConnection) or below (ICE) changed shape.
- **`a=fingerprint` verification (RFC 8122/8827) — the check the whole security model rests on.** BoringSSL
  accepts any certificate by design (WebRTC verifies by fingerprint, never by CA chain), so the driver holds
  the peer's certificate to the digest its SDP advertised and fails the session typed if it differs; a peer
  advertising no usable SHA-256 digest is refused rather than trusted. Certificate identity now lives on the
  **DTLS factory** (`DtlsTransportFactory.localFingerprint`), not in `PeerConnectionConfig`, so advertising
  one fingerprint while presenting another is unrepresentable (DESIGN §4) — this also resolves an ordering
  constraint, since the digest must exist at `createOffer` time but the role only at `a=setup`. Accordingly
  the DTLS **role moved from the `DtlsEngine` constructor to `start(role, now)`**: an endpoint has an
  identity from birth and learns its role from signaling later, as WebRTC models it.
- **One DTLS vocabulary.** The root module's W6-era duplicate `DtlsFailureReason` is **removed**;
  `PeerConnectionFailureReason.Dtls` now composes webrtc-dtls's sealed reason unchanged, exactly as `Ice`
  and `Sctp` compose theirs. `DtlsConfig.handshakeTimeout` closes a liveness hole: DTLS retransmits a lost
  flight forever, so without a budget a peer that goes silent mid-handshake would hang the session (RFC
  §5.3 #5 — reach a state or a typed failure, never hang).
- **Tests.** **The W4 exit fixture** (`webrtc/linuxTest`): two `NativePeerConnection`s complete a full
  session over the vnet with **real DTLS in the seam** — ICE nomination → DTLS handshake → SCTP association
  → data channels both ways, under virtual time — the end-to-end gate W5 and W6 could only prove with the
  plaintext stand-in. Plus: the two-stack handshake fixture (each side verifying the *other's* real cert
  fingerprint, negotiated 1.3) + the 1.2-fallback/Pion interop lane + app-data round-trip; the
  **dropped-flight retransmission** fixture (a timer must arm, not fire early, and the retransmitted flight
  must actually complete the handshake); the fingerprint-**mismatch** and **absent-fingerprint** negatives
  (both fail typed, never connect); the injected-factory/bounded-allocation invariant (directive #6); and
  the libssl/libcrypto single-copy link tripwire.
- **Platform reality (V6_MAC_VALIDATION):** Linux K/N is the only target with a DTLS backend this wave.
  JVM/Android/**Apple** get typed `BackendUnavailable` actuals and are **compile-faithful only** — Apple has
  **no** DTLS backend. JVM/Android/Apple DTLS is deferred to the `boringssl-kmp` binary factory, which
  cannot serve today: it is unpublished, its JVM FFM shim is crypto-only, its Apple lane is unbuilt, and its
  quiche-anchored API-21 pin has no `DTLS1_3_VERSION` (it would ship a 1.2-only stack) and would
  duplicate-symbol against buffer-crypto's BoringSSL on native. See EXECUTION_PLAN "W4 sequencing".

#### Hardened — adversarial-review gate (4 parallel lanes: native/FFI, driver/lifecycle, types/API, tests)
Each confirmed defect ships its regression fixture (directive #5):
- **`CertificateFingerprint` is now unforgeable-by-construction** — the primary constructor is **private**
  and `ofHex` is the only builder; it validates the digest is exactly 64 hex chars and normalizes case +
  colons. Previously a public constructor could store a non-normalized string, making the RFC 8122
  `a=fingerprint` equality check (a security discriminant, RFC 8827) casing-fragile and `sdpValue` render
  garbage. `.api` changed (constructor removed) — cheap now, binary-breaking after release.
  (`CertificateFingerprintTest`.)
- **A fatal record-layer error on the read path now surfaces `Failed(RecordLayerError)`** instead of being
  swallowed as end-of-data — a post-handshake fatal alert can no longer leave a dead transport
  masquerading as `Established`.
- **The GC-heap FFI staging path is bounded** — a datagram larger than the 64 KiB scratch is rejected up
  front rather than read past the buffer's end (native-backed buffers keep the copy-free path).
  (`…rejected_not_over_read`.)
- **The driver-enforced `handshakeTimeout` liveness bound is now covered** — a silent peer fails typed
  (`HandshakeTimeout`) under virtual time rather than hanging. (`DtlsHandshakeTimeoutTest`.)
- **Buffer-leak sources closed** — the memory-BIO leak on a partial-allocation failure in `bd_new`, the
  native-engine leak if construction throws after `bd_new`, and the driver dropping (not releasing) a
  decrypted app-data buffer on a teardown race are all fixed; the allocation test's invariant is scoped
  honestly to bounded-allocation (matching the W3/W5 posture).
- **Read-path T0 robustness** — a malformed datagram fed mid-handshake is dropped, never wedges or crashes
  the engine. (`…malformed_datagrams…`.)

### Added — W6: `webrtc` root — `PeerConnection` + browser delegation + typed error sweep
- **`RtcPeerConnection` + `NativePeerConnection`** (the consumer session API, ARCHITECTURE §3.1) — a caller-clocked,
  seam-injected driver composing the sans-io cores: the `JsepSession` offer/answer machine (webrtc-sdp),
  the `IceAgentDriver` (webrtc-ice) over an injected `IceGatheringPolicy`, the injected
  `DtlsTransportFactory` (`PlaintextDtls` while W4 is parked — the same seam W5 proved SCTP over), and the
  `SctpDataChannelStack` (webrtc-sctp) over the nominated pair. Descriptions and candidates cross as **SDP
  text / `candidate:` lines** (the exact currency `RTCPeerConnection` and the wire speak, so one interface
  backs both native and browser); a data channel **is** a buffer-flow `Connection<ReadBuffer>`
  (`createDataChannel` / `incomingDataChannels`, DESIGN §7). Sealed `PeerConnectionState` carries the typed
  failure reason (no boolean/nullable soup, DESIGN §4). The DTLS/SCTP role is **negotiated from `a=setup`**
  (RFC 8842), not assumed from who offered.
- **ICE→SCTP composition promoted to production** — `IceAgentDriver` (+ the `DatagramBinder` network seam
  and the `IceDataTransport` app-data seam over the selected pair, RFC 7983 STUN/app demux) in
  `webrtc-ice/commonMain`, so the session and a future media layer compose the same transport the W5
  `IceSctpEndToEndTest` proved. `IceCandidateLine` — the RFC 8839 §5.1 `candidate` ↔ typed `IceCandidate`
  codec (typed-reject on malformed, phase-1 UDP/IPv4).
- **Browser delegation (js, Karma-tested)** — `peerConnectionSupport()` (`expect`/`actual`); on a browser
  the js actual maps our API onto the native `RTCPeerConnection` (ARCHITECTURE §1.1: the one target we wrap), with
  a real in-browser loopback Karma test in headless Chrome. Non-browser targets report `Native` and build
  `NativePeerConnection` directly; wasmJs reports `BrowserDelegated` with the external-interface mapping as
  the one documented remaining follow-up.
- **Typed error sweep** — `PeerConnectionFailureReason` (sealed `Ice`/`Dtls`/`Sctp`/`Unknown`, composing
  each layer's typed reason unchanged) + `DtlsFailureReason` (defined ahead of W4) + `WebRtcException`;
  signaling-API misuse is typed `JsepStateException`/`SdpFormatException` (directive #3). Mapping into
  socket's `SocketException` hierarchy (ARCHITECTURE §3.1) is **deferred**: depending on `com.ditchoom:socket`
  duplicate-symbols socket's vendored BoringSSL against buffer-crypto's on every native target — gated on
  an upstream BoringSSL dedup, exactly as DTLS is gated on W4.
- **Tests (all platforms, `runTest` virtual time):** the full offer/answer → ICE → (plaintext DTLS) → SCTP
  → data-channel round-trip with scripted signaling (the W6 exit fixture) — green on
  jvm/linuxX64/jsNode/**jsBrowser (Karma)**/wasmJsNode/wasmJsBrowser/androidHost; lifecycle-liveness
  regressions (close-before-connect terminates, typed signaling errors); the candidate-codec T0; the
  error-sweep mapping. Adversarial-review gate (3 parallel reviewers) ran — every confirmed defect
  (role-negotiation deadlock, five lifecycle/liveness hangs/leaks, six API-surface findings, four
  browser-delegation defects) fixed with a regression fixture. `.api` committed as the public commitment.

### Added — W5: `webrtc-sctp` association + DataChannel (SCTP RFC 4960 subset + RFC 3758 + DCEP 8832 + RFC 8831)
- **Sans-io SCTP association (`SctpAssociation`)** — a pure `handle(event, now): List<Output>` plus
  `nextDeadline(now): Instant?`, **no dispatcher, clock, RNG, or I/O inside** (ARCHITECTURE §5.1). It owns the
  **four-way handshake** (INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK with a stateless State Cookie),
  TSN assignment and **SACK**-driven reliability, **RTO** estimation (RFC 4960 §6.3.1), **congestion
  control** (slow start / congestion avoidance / T3 + fast-retransmit collapse, §7.2), message
  **fragmentation** and ordered/unordered **reassembly**, **RFC 3758 partial reliability** (FORWARD-TSN,
  `maxRetransmits` / `maxPacketLifeTime` abandonment), and graceful + abort **shutdown** (§9). Entropy is
  one injected `Random` seam (directive #2) seeding the Verification Tag + initial TSN, so a full
  session replays bit-for-bit under `runTest` virtual time on every platform. §11.2 resolved: the
  dcSCTP-style subset (no multihoming, no stream interleaving).
- **Type model, illegal states unrepresentable:** sealed `SctpAssociationState` (Closed → CookieWait →
  CookieEchoed → Established → the four shutdown phases), sealed `SctpEvent` / `SctpOutput`, sealed
  `SctpReliability` (Reliable | MaxRetransmits | MaxLifetime — never a nullable pair), and exhaustive
  `SctpFailureReason` (`AbortReceived`, `RetransmissionLimitReached`, `HandshakeTimeout`,
  `ProtocolViolation(ProtocolViolationKind)`) — typed reasons, never strings (directive #3).
- **DCEP (RFC 8832) + `DataChannel` as a buffer-flow `StreamMux`** — `SctpDataChannelStack` implements
  `StreamMux<ReadBuffer>`: `openBidirectional()` gives a `Connection<ReadBuffer>` whose `send` is one
  data-channel message and whose `receive` is the inbound message flow (DESIGN §7 — the consumer
  contract is the mux). It drives the association over an injected **`SctpDatagramTransport`** (the
  clean DTLS-shaped seam where W4 slots in), an injected `CoroutineScope`, and an injected clock;
  DATA_CHANNEL_OPEN/ACK are wired to the association, even/odd stream ids follow RFC 8832 §6, and empty
  messages ride the RFC 8831 §6.6 empty-marker PPIDs.
- **Tests (all platforms, `runTest` virtual time):** a deterministic sans-io two-endpoint conductor
  (handshake, ordered-reliable **no-reorder / no-drop under 30 % loss**, unordered, fragment/reassemble,
  partial-reliability convergence, shutdown); a coroutine DataChannel end-to-end over an impaired
  in-memory transport (bidirectional, lossy-reliable, empty-message); and the **W5 composition** — the
  real `SctpDataChannelStack` running over the actual **W3 `IceAgent` nominated pair** across the vnet
  (`IceDriver.sctpTransport` + RFC 7983 STUN/app demux). A **loop-until-dry invariant campaign**
  (260 seeds of randomized loss/dup/delay/jitter) upholds the SCTP invariants — no crash, liveness, no
  intra-stream reorder, no unacked drop, no duplicate delivery. The **Jazzer `sctpCodecFuzz` lane** now
  also feeds hostile bytes into `association.handle` (T0 totality at the association layer); a 3 M-run
  campaign was clean. `CountingBufferFactory` proves the `BufferFactory` is threaded through the hot
  paths and an idle association allocates nothing per tick (directive #6).
- **Adversarial-review gate (5 parallel reviewers) — confirmed defects fixed, each with a regression
  fixture** (directive #5): a lone FORWARD-TSN now elicits a SACK (RFC 3758 §3.6); T3 retransmits are
  **paced by cwnd** (§6.3.3 E3) instead of dumping the whole flight; a fast-retransmitted chunk resets
  its missing-report count (no infinite re-fast-retransmit); partial-reliability abandonment runs on the
  SACK path too (a timed message is no longer retransmitted forever when T3 never fires); a **reflected
  T-bit ABORT** from a peer that lost its TCB is accepted (§8.5.1) so a dead-peer restart tears us down;
  a gap-ack-block offset beyond a `u16` is **omitted** rather than wrapped into a malformed `end < start`
  block; ordered delivery **wraps the SSN** (no stall after 65535 ordered messages); the RFC 7053 I-bit
  and gap-fill now force a prompt SACK; a cross-stream/SSN fragment splice is rejected; the DataChannel
  driver **completes pending `open`/`send` deferreds exceptionally on teardown** (was: caller hangs
  forever), stops the loop on a received ABORT, validates incoming-OPEN stream-id parity, and buffers
  data that races ahead of its DCEP OPEN. The Jazzer lane was strengthened to re-stamp a valid CRC so
  the association handlers are actually exercised (edge coverage 1052 → 1472); the invariant campaign was
  split into an all-platform smoke set + a JVM deep-run (hundreds of seeds + fragmentation-under-loss),
  and the sim conductor now throws on non-convergence so a livelock can never pass silently.

### Added — W3: `webrtc-ice` (ICE agent — RFC 8445 + trickle 8838 + consent 7675)
- **Sans-io ICE agent core (`IceAgent`)** — a pure `handle(event, now): List<Output>` plus
  `nextDeadline(now): Instant?`, with **no dispatcher, clock, RNG, or socket inside** (ARCHITECTURE §5.1). It
  owns the checklist, the connectivity-check state machine (retransmission via the W1 `StunTransaction`),
  Ta-paced scheduling, triggered checks, peer-reflexive learning, **regular nomination**, RFC 7675
  **consent freshness**, **role-conflict** resolution (487 + tie-breaker), and **ICE restart**. Entropy
  is one injected `Random` seam (directive #2) seeding the tie-breaker, credentials, and every STUN
  transaction id, so a full establishment (and a 90-second field saga) replays bit-for-bit under
  `runTest` virtual time on every platform.
- **Type model, illegal states unrepresentable:** `IceCandidate` (host/srflx/prflx/relay) with RFC 8445
  §5.1.2 priority; `CandidatePair` + §6.1.2.3 pair priority (computed in `ULong` — the `2^32·min` term
  exceeds a signed `Long`); `CandidatePairState`; `Foundation` (§5.1.1.3); value-class `ComponentId`,
  `IceRole`, unsigned `TieBreaker`, `NetworkId`; `IceCredentials.random` (ICE-char ufrag/pwd); a sealed
  `IceConnectionState` and exhaustive `IceFailureReason`.
- **ICE STUN attributes** (PRIORITY / USE-CANDIDATE / ICE-CONTROLLING / ICE-CONTROLLED) built on the
  additive public `RawAttribute.ofRaw(type, value)` / `ofXorAddress(type, addr, txid)` escape-hatches
  added to `webrtc-stun` — the ICE checks reuse the W1 STUN client and MESSAGE-INTEGRITY/FINGERPRINT.
- **Gathering drivers (production, over injected seams):** `gatherServerReflexive` (STUN Binding →
  srflx); `TurnAllocation` — a full RFC 8656 relay client presented **as a `DatagramChannel`** (Allocate
  with 401 challenge, CreatePermission, Send/Data encapsulation, response demux) so the relay's
  complexity stays out of the core; `NetworkMonitor` / `MdnsResolver` seams (mDNS **resolve-only**, RFC
  §11.4). Trickle (RFC 8838) falls out of the driver's single-inbox design.
- **The vnet grew a NAT layer** (`webrtc-ice` commonTest): the four RFC 4787 profiles (full-cone /
  address-restricted / port-restricted / symmetric as mapping × filtering), a **virtual TURN server**
  bound as an ordinary endpoint, a **virtual STUN server**, and a **seeded impairment pipe**
  (loss/reorder/dup/delay on virtual time) — topologies-as-data builders (`Vnets`).
- **Canonical fixtures + invariants (all under `runTest`, all platforms):** two-agent host-to-host,
  role-conflict glare, full-cone srflx hole-punch, **dual-symmetric-NAT → relay** (the ARCHITECTURE §5.2
  load-bearing case), candidate-flap mid-check, `NetworkId`-change → restart, consent expiry, and a
  typed `AllPairsFailed` terminal; RFC-formula conformance for priority/foundation; a pinned-seed
  **timeline fuzz smoke** (establishes under 20% loss + jitter, deterministic replay, every NAT profile
  reaches a terminal state — the liveness/determinism invariants). NAT-model property tests prove each
  profile filters per its RFC 4787 definition.
- **One core bug found + fixed with its fixture** (directive #5): consent expiry used a strict `>`
  while `nextDeadline` armed exactly `lastResponse + consentTimeout`, spinning the driver at that
  instant without advancing virtual time — now `>=`, with `consent_expiry` as the regression.
- **Adversarial review gate (EXECUTION_PLAN §1) — 5 parallel reviewers; confirmed defects fixed, each
  with a regression fixture:** the role-conflict comparison was **inverted** in the Controlled branch
  (RFC 8445 §7.3.1.1 — the larger tie-breaker ends up controlling in *both* directions), so
  controlled-vs-controlled glare thrashed; added a one-shot resolution latch + pacing re-arm on a 487
  retry. A **global establishment failsafe** closes three liveness hangs (nomination-check failure,
  a peer that never nominates, zero compatible candidates → the now-emitted typed `NoCandidatePairs`).
  The `nominationInFlight` latch is released on any nominating-check outcome (+ an on-timer retry). The
  connectivity check reads only the **MESSAGE-INTEGRITY-covered prefix** (RFC 8489 §14.5), defeating a
  USE-CANDIDATE splice. `pruneRedundant` is state-aware (never evicts an in-flight/valid/selected pair).
  Driver/vnet hardening: `select`-based drive loop (no lost trickled candidate), `close()` unbinds the
  vnet endpoint (flap frees it; no false delivery/leak), the vnet TURN server validates REALM/NONCE
  like coturn, srflx gathering retransmits, `toTransportAddress` typed-rejects non-v4.
- **BufferFactory injectable end-to-end (directive #6):** the whole datagram build path uses the
  caller's `IceConfig.bufferFactory` (a consumer can hand in a `buffer` pool); `BufferLifecycleTest`
  validates pool-injectability and **steady RSS** (allocations grow with messages, not per timer tick).
- Green on **JVM, JS-node, wasmJs-node, Linux/native, and Android host**; Apple lanes CI-validated on
  the macOS runner. Nothing published to Central (`skip-release`).

### Added — W5 (codec floor): `webrtc-sctp` (SCTP chunk codec + DCEP messages)
- **SCTP common header (RFC 4960 §3.1)** as a `buffer-codec` KSP `@ProtocolMessage` schema
  (`SctpCommonHeaderCodec`) — a straight-line 12-byte network-order decode; the chunk TLV framing
  (type/flags/length, pad to a 4-byte boundary) and the nested parameter/error-cause sub-TLVs are
  hand-written, because SCTP's "length counts the 4-byte header + value but not the trailing pad" is
  outside what the declarative codec expresses (the STUN attribute discipline).
- **Sealed chunk hierarchy (`SctpChunk`):** DATA, INIT, INIT-ACK, SACK, HEARTBEAT, HEARTBEAT-ACK,
  ABORT, SHUTDOWN, SHUTDOWN-ACK, ERROR, COOKIE-ECHO, COOKIE-ACK, SHUTDOWN-COMPLETE, FORWARD-TSN
  (RFC 3758), plus an `Unrecognized` variant that preserves an unknown chunk verbatim (RFC 4960 §3.2
  forward-compat). A receiver's `when(chunk)` is exhaustive with no `else`. Variable regions (user
  data, cookies, parameter/cause values) are **zero-copy slice views** over the datagram (ARCHITECTURE §6).
- **CRC32c (RFC 4960 §6.8 / RFC 3309):** the Castagnoli checksum, self-contained (`Crc32c`) — a
  256-entry table held in a **managed `ReadBuffer`, not an `IntArray`** (directive #1), word-batched
  input read matching buffer's `crc32`. Stored little-endian per RFC 4960 Appendix B; verified/placed
  in-place without mutating the datagram. Validated against the published `0xE3069283` known answer and
  cross-checked against an independent bitwise reference over thousands of random inputs.
- **Typed identifiers (value classes):** `Tsn` (with RFC 1982 serial arithmetic), `StreamId`,
  `StreamSequenceNumber`, `PayloadProtocolId` (WebRTC PPID constants), `VerificationTag`; bitwise
  fields wrapped behind named accessors (`DataChunkFlags` I/U/B/E, `SctpChunkType.unrecognizedAction`).
- **DCEP (RFC 8832):** `DataChannelMessage` sealed pair — `Open` (channel type, priority, reliability,
  UTF-8 label/protocol) and `Ack`. `ChannelType` exposes an exhaustive typed projection (`ordered` +
  sealed `Reliability`) over the preserved wire byte. Decode is total with typed rejects; invalid UTF-8
  in a label/protocol is a typed miss, never a throw.
- **Typed rejects (T0):** `SctpPacket.decode` and `DataChannelMessage.decode` are total — a hostile or
  truncated datagram yields a sealed `SctpRejectReason` / `DataChannelRejectReason`, never a throw.
- **Tests:** every chunk type round-trips (typed fields + byte-exact re-encode + checksum), frozen
  RFC-layout golden wire vectors (INIT, SACK, DCEP-over-DATA), a malformed corpus + a 20k-input
  totality property + single-byte-mutation totality, wrapper-transparency (non-zero-offset slice), and
  the CRC32c conformance suite — **green on JVM, JS, wasmJs, Linux/native, and Android host**.
- **Coverage-guided Jazzer fuzz lane** (`sctpCodecFuzz`, time-boxed at 120s in CI) with a committed
  seed corpus; a 90s local run was ~26M executions crash-free. One find during bring-up — a
  `valueSize` computed from the untruncated padded length of a malformed final sub-TLV, which shrank
  the re-encode buffer under the checksum's read — is fixed with its committed regression fixture.
- SCTP decode / checksum-verify throughput benchmark tracked in `PERFORMANCE.md`. Committed `.api` +
  detekt baseline.
- **Scope:** this is the pure codec + DCEP-message floor only (commonMain, zero I/O). The SCTP
  association state machine (handshake, TSN/SACK/RTO, congestion control, reassembly) and the
  `DataChannel` `StreamMux` are the rest of W5 — they sit above this on the DTLS/UDP track.

### Added — W6 (partial): `webrtc-sdp` (SDP text codec + sans-io JSEP machine)
- **SDP parser/serializer (RFC 8866):** a hand-written line codec (SDP is text — no `buffer-codec`
  schema). The datagram is decoded to a `CharSequence` exactly once and parsed index-based into a
  round-trip-faithful model (`SessionDescription` → session lines + `MediaDescription`s), each line
  kept verbatim so parse→encode reproduces a canonical CRLF document **byte-for-byte** (the text
  analogue of STUN's view-based decode).
- **Typed rejects (T0):** `SessionDescription.parse` is total — a hostile or non-UTF-8 datagram yields
  a sealed `SdpRejectReason`, never a throw. Semantic breakage of a single line (`o=`/`m=`/
  `a=fingerprint`) is a null typed-reader miss, not a whole-document reject (the `RawAttribute`
  discipline for text).
- **Typed field surface:** value-class `Mid`; `Origin`, `MediaLine`, `Fingerprint`, `SetupRole`,
  `SdpType`, `SignalingState`; on-demand interpreters for the JSEP data-channel attributes
  (`ice-ufrag`/`ice-pwd`/`fingerprint`/`setup`, `sctp-port`/`max-message-size`, `candidate`/
  `end-of-candidates`, `group:BUNDLE`) at session or media level (RFC 8829 §5.2.1 fallback).
- **`SessionDescriptionBuilder`** + `dataChannelDescription` — programmatic offer/answer assembly
  (RFC 8841 data-channel shape); a built document round-trips through `parse` unchanged.
- **Sans-io JSEP offer/answer machine:** `JsepSession.handle(event, now)` + `nextDeadline()` (always
  null — JSEP arms no timers), enforcing the RFC 8829 §3.5.1 signaling transition table with rollback;
  illegal edges are typed `JsepError.InvalidTransition` outputs that leave state untouched. Entropy is
  injected (`Random`) — the `o=` session id is `CryptoRandom` in production, replayable in tests.
- **Tests:** real-world Chrome/Firefox/Pion data-channel offer/answer vectors (parse + typed fields +
  byte-exact round-trip), malformed corpus + two 20k-input totality properties + single-line-drop
  mutation, wrapper-transparency (pooled buffer / non-zero-offset slice), builder round-trips, and the
  full JSEP transition table incl. rollback/pranswer/close — **36 tests green on JVM, JS, wasmJs,
  Linux/native, and Android host**.
- **Coverage-guided Jazzer fuzz lane** (`sdpCodecFuzz`, time-boxed in CI) with a committed seed corpus
  (7 seeds); a 30s local run turned 1M+ executions crash-free.
- SDP parse/encode throughput benchmark tracked in `PERFORMANCE.md`.

### Added — W1: `webrtc-stun` (STUN/TURN codec + sans-io transactions)
- **STUN message codec (RFC 8489):** the 20-byte header (bit-interleaved message type, magic cookie,
  96-bit transaction id) as a `buffer-codec` KSP `@ProtocolMessage` schema (`StunHeaderCodec`); the
  TLV attribute layer hand-written for STUN's 4-byte value padding and the in-place MESSAGE-INTEGRITY /
  FINGERPRINT computations. Attributes decode as **zero-copy slice views** over the datagram (ARCHITECTURE §6).
- **Typed attribute surface:** value-class `StunMessageType` / `StunMethod` / `StunAttributeType` /
  `TransactionId`; MAPPED-ADDRESS + XOR-MAPPED-ADDRESS (IPv4/IPv6, array-free `IpAddress`), USERNAME /
  REALM / NONCE / SOFTWARE, ERROR-CODE, plus TURN (RFC 8656) attribute types (codec-only).
- **MESSAGE-INTEGRITY (HMAC-SHA1) + FINGERPRINT (CRC-32)** verified/appended in place over buffer
  slices, using the new `buffer-crypto` `hmacSha1` and `ReadBuffer.crc32` (DitchOoM/buffer#288).
  MESSAGE-INTEGRITY is compared **constant-time** (`constantTimeEquals` — a MAC compare is a timing
  oracle otherwise); **MESSAGE-INTEGRITY-SHA256** (RFC 8489 §14.6, truncation-aware) via `hmacSha256`.
- **Typed rejects (T0):** `StunMessage.decode` is total — a hostile datagram yields a sealed
  `StunRejectReason`, never a throw.
- **Sans-io transaction machine:** `StunTransaction.handle(event, now)` + `nextDeadline()` with the
  RFC 8489 §6.2.1 retransmission schedule (RTO doubling, `Rc`/`Rm`), injected clock + seeded
  transaction ids — runs under virtual time on every platform.
- **Tests:** RFC 5769 §2.1–2.3 interop vectors (decode + MI/FINGERPRINT recompute + XOR-address +
  byte-exact round-trip), malformed corpus + 20k-input totality property, wrapper-transparency
  (pooled buffer / non-zero-offset slice), builder round-trips — **34 tests green on JVM, JS, wasmJs,
  Linux/native, and Android host**.
- **Coverage-guided Jazzer fuzz lane** (`stunCodecFuzz`, time-boxed in CI) with a committed seed
  corpus; the two bugs it found in W1 (non-UTF-8 text throwing; short MESSAGE-INTEGRITY/FINGERPRINT
  length reading past the datagram) are fixed with committed regression fixtures + corpus seeds.
- Parse-throughput benchmark tracked in `PERFORMANCE.md`.

**Depends on** DitchOoM/buffer#288 (`hmacSha1` + `ReadBuffer.crc32`); pinned to `6.10.0-SNAPSHOT` from
mavenLocal during development — swap to the released `buffer` before merge.

### Added — W0: foundations (repo skeleton)
- Multi-module Gradle build across the full KMP target matrix (JVM, Android, JS Node/Browser, wasmJs,
  Linux x64/arm64, Apple), JDK 21 toolchain.
- `build-logic` convention plugin (`webrtc.multiplatform-library`) owning all per-module build config —
  targets, publishing, signing, versioning, ktlint, dokka, kover, binary-compatibility validation — so
  a module build file carries only its dependencies.
- Phase-1 module tree (placeholders): `webrtc`, `webrtc-sdp`, `webrtc-stun`, `webrtc-ice`,
  `webrtc-dtls`, `webrtc-sctp`, `webrtc-testsuite`.
- kotlinx-benchmark wired into the convention (shared `src/commonBenchmark/kotlin`, JVM + Linux K/N,
  `main`/`quick` profiles), tracked in `PERFORMANCE.md`.
- CI: `review.yaml` (PR build/test/validate), `merged.yaml` (label-driven release), reusable
  `build-linux` / `build-apple` / `validate-artifacts`, `publish-to-central` / `release` / `released`
  (Central Portal), and `standing-directives.yaml` (No-array + seamed-entropy greps).
- PR labels (`.github/labels.yml` + sync workflow), dependabot.
- Docs: `ARCHITECTURE.md`, `EXECUTION_PLAN.md`, `CLAUDE.md`, `DESIGN_PRINCIPLES.md`, `TESTING.md`
  (unit → integration → interop strategy, harness, external vectors, per-wave test exit criteria),
  `PERFORMANCE.md`, `README.md`.

_No published release yet; the first `publishToMavenLocal` produces `0.0.1`._

# Architecture — `com.ditchoom:webrtc`

How this library is put together and why. Companion documents: [`DESIGN_PRINCIPLES.md`](./DESIGN_PRINCIPLES.md)
(the type-safety and zero-copy house style, with worked examples) and [`TESTING.md`](./TESTING.md)
(how the claims below are held true).

It is built on `com.ditchoom:buffer` (zero-copy buffers, codec, crypto, flow) and `com.ditchoom:socket`
(the transport model, the typed error vocabulary, `NetworkMonitor`, real UDP actuals). Section numbers
here are referenced from KDoc throughout the source as `ARCHITECTURE §n`.

---

## 1. The one decision everything else follows from

**The protocol stack is common Kotlin; it does not wrap libwebrtc.**

| | Wrapping libwebrtc | This |
|---|---|---|
| Zero-copy | Impossible — every message crosses a JNI/ObjC boundary as a `ByteArray`/`NSData` copy | `ReadBuffer`/`WriteBuffer` end to end; the no-primitive-array rule holds |
| Determinism | None — libwebrtc owns its threads, timers and RNG | Every state machine is caller-clocked; the whole stack runs under `runTest` virtual time |
| Testing | Black box; a field bug is unreproducible | Timeline fixtures, seeded fuzz, a shrinker — a field bug becomes a committed regression test |
| Platforms | Android/iOS | The full target matrix, JVM and Linux servers included |

The precedent is `socket-quic-quiche`: a full transport protocol already runs on our own driver over a
UDP seam on every platform. WebRTC is the same shape — plus ICE in front and SCTP behind — except that
here the protocol cores are **ours**, which is what buys §5.1.

### 1.1 The browser exception

A browser page has no raw UDP. That is physics, not an API gap, so it is the one place we wrap rather
than reimplement: `peerConnectionSupport()` returns a `BrowserDelegated` value whose `create()` is
backed by the platform's own `RTCPeerConnection`. The result implements the same `RtcPeerConnection`
interface as the native stack, so everything above the branch is shared code.

The same constraint shapes the dependency graph: the sans-io cores are `commonMain` with no socket
dependency at all, so `webrtc-stun`, `webrtc-sdp`, and the ICE/SCTP/DTLS cores compile and run
everywhere — browsers included — and only the platform-edge actuals (§4) are missing there.

## 2. Scope

Data channels: ICE + DTLS + SCTP + DCEP + JSEP/SDP. That is the part of WebRTC with no codec or
hardware dependency, and it slots into the existing `StreamMux`/`MultiplexingTransport` world, so
MQTT/RPC/codec consumers ride a peer-to-peer data channel with no new API.

Media (RTP/RTCP/SRTP) is a later phase: packetization and crypto would be pure common Kotlin over
`buffer-crypto`, while codec encode/decode stays platform-native and outside this library permanently.

**Signaling is a seam, never an implementation.** Descriptions and candidates cross as SDP text and
`candidate:` lines through an interface the app supplies — no HTTP, no WebSocket, no opinion. This is
correct layering (WebRTC standardizes no signaling protocol) and it is what makes the offer/answer
state machines fully deterministic in `commonTest`.

## 3. Module map

One core, thin layers, each depending only downward.

```
webrtc            PeerConnection + JSEP state machine + DataChannel (the consumer API)
├── webrtc-sdp    SDP parse/serialize — hand-written text codec, no I/O
├── webrtc-stun   STUN/TURN wire codec (RFC 8489/8656) + sans-io client machines
├── webrtc-ice    ICE agent (RFC 8445 + trickle 8838) — sans-io core + gathering seams
├── webrtc-dtls   DTLS 1.2/1.3 + the DTLS-SRTP exporter — pure Kotlin
├── webrtc-sctp   SCTP subset over DTLS (RFC 8831) + DCEP (RFC 8832) — pure Kotlin, sans-io
└── webrtc-testsuite  the published consumer harness: vnet, timeline engine, control plane
```

The pure-codec modules (`-sdp`, `-stun`) have **zero** platform code and zero I/O. Platform code exists
in exactly two places: the UDP and mDNS actuals in `webrtc-ice` (§4), and the interface-enumeration and
change-trigger halves of `systemNetworkMonitor()`.

### 3.1 The consumer API surface

- `RtcPeerConnection` is a **Layer-2 session**: `establish` is signaling-shaped, not host:port-shaped,
  so WebRTC is only ever a session type and never pretends to be a `Transport.connect(host, port)` —
  that would lie about addressing.
- A data channel **is** a buffer-flow `Connection<DataChannelPayload>`. Anything written against
  `StreamMux`-style mux code runs over WebRTC unchanged, once it names the message kind: a payload is
  `Text` or `Binary`, which is the distinction RFC 8831 §6.6 draws on the wire (PPID 51 vs 53) and the
  one a browser peer sees as `String` vs `ArrayBuffer` on `event.data`. `Binary` carries the buffer
  itself and is never copied; `Text` carries characters, so a message claiming to be a string cannot
  hold bytes that are not valid UTF-8.
- Capability by type, no stubs: `peerConnectionSupport()` is sealed, so the browser/native branch is
  exhaustive at compile time and there is no runtime "unsupported operation" for a statically
  impossible call.
- **One thrown vocabulary.** Everything maps into socket's `SocketException` hierarchy with exhaustive
  sealed causes — `IceFailureReason.NoCandidatePairs`, `.ConsentExpired`, and so on. Strings are
  diagnostics, never discriminants.
- Non-fatal observations that are not lifecycle states get their own stream, `diagnostics`, rather than
  being folded into `PeerConnectionState` — a session that dropped a peer's malformed candidate is
  still genuinely `Connected`, and making "connected" mean two things would cost more than it saves.

## 4. What this is built on

The library owns the protocols and borrows everything beneath them. Which artifact supplies what is
load-bearing, because it is also what decides where the stack runs.

| Concern | Comes from | Notes |
|---|---|---|
| Zero-copy buffers, slices, pools, native handles | `buffer` | The slice-lifetime contract is what makes view-based parsing safe over pooled datagrams (§6) |
| Wire codecs | `buffer-codec` | KSP-generated from `@ProtocolMessage` schemas for STUN and SCTP chunks; SDP is text, so it gets a hand parser held to the same rigor |
| Crypto primitives | `buffer-crypto` | AEAD, HKDF (`extractInto`/`expandInto` separately — the TLS 1.3 key-schedule shape), X25519/P-256, ECDSA, streaming SHA-2, constant-time compare, `secureFixedPool` |
| The datagram seam | `buffer-flow` `AddressedDatagramChannel` | The interface both the vnet and real UDP implement. The cores target **this**, never a socket |
| Real UDP + multicast | `socket-udp` | Only at the platform edge — `udpDatagramBinder()`, `MulticastMdnsEndpoint`. Ships jvm/android/linux and **all eleven** Apple targets since 4.1.6 (tvOS/watchOS included); **not** wasm, which is the browser delegation of §1.1 |
| Network reactivity | `com.ditchoom:network-monitor` | *When* did the network change. We do not hand-roll it. One artifact on every leaf — jvm, android **and** the K/N ones: socket#275 gave `:network-monitor` its own netlink and Apple cinterops, so `com.ditchoom:socket` core is no longer a dependency of this repo at all |
| Interface enumeration | ours (`java.net.NetworkInterface` / `getifaddrs(3)`) | *Which local addresses exist* — socket's monitor reports link identity and carries no addresses, while ICE compares the selected pair's local IP. The two answer different questions and both are needed |

## 5. Determinism architecture

### 5.1 Sans-io, caller-clocked cores

Because the cores are ours, the rule is absolute:

> Every protocol state machine (ICE checklist, STUN transactions, DTLS, SCTP, DCEP, JSEP) is a pure
> `handle(event, now): List<Output>` plus a `nextDeadline(now): Instant?`. No dispatcher, no
> `Clock.System`, no `Random.Default`, no I/O, no coroutine inside a core. **Drivers own I/O; cores own
> truth.**

Consequences:

- A full ICE + DTLS + SCTP establishment completes under `runTest` at **zero wall-clock** on every
  target. A 90-second field ICE saga — consent timeouts, TURN refresh, nomination flaps — replays in
  milliseconds, forever.
- There is no real-time residue anywhere in the stack, because DTLS is ours too (§11.5): handshake
  retransmission is driven from the injected clock like everything else.
- Entropy is seeded from the start rather than retrofitted: one injected `Random` feeds the ICE
  tie-breaker, ufrag/pwd, STUN transaction ids and foundations; one injected clock feeds every timer.
  Production defaults are supplied at the driver edge, never hardwired inside a core.

A driver is the mirror image: it owns exactly one coroutine that serializes every interaction with its
core. `IceAgentDriver` merges inbound datagrams and posted events into a single inbox and realizes
`nextDeadline` as a `select` against virtual time; `PureKotlinDtls` does the same for the DTLS engine.
The cores are not thread-safe, and this is what makes that safe by construction rather than by
convention.

### 5.2 The vnet

ICE bugs live in NAT behaviour, so there is a pure-Kotlin **virtual network** implementing the same
`AddressedDatagramChannel` seam production uses:

- NAT profiles — full-cone, address-restricted, port-restricted, symmetric — with configurable mapping
  lifetimes, hairpinning and per-direction filtering, each a small pure state machine.
- Topologies as data: two peers behind distinct symmetric NATs plus a virtual TURN server is the
  canonical relay-only fixture; double NAT, IPv6-only, routed-v6 firewalls, dual-stack fallback and a
  Wi-Fi→cellular interface change mid-session are all timelines rather than lab setups.
- Because the seam is the production one, the **entire real stack** runs through simulated NATs in
  `commonTest` on every platform. The only substitution is the packet and clock plumbing beneath ICE.

`bind(host, 0)` assigns an ephemeral port there exactly as a kernel does — a seam that quietly bound
port zero would be a seam where a candidate advertising `:0` passes every test.

### 5.3 Timelines, fixtures, invariants

Input events (`DatagramIn(bytes, from)`, network changes, clock advances, signaling input) drive the
seams; observation snapshots (ICE pair states, nomination, DTLS state, SCTP cwnd/RTO, buffer
accounting) are golden trajectories, not just crash-avoidance. Seeded timeline fuzz and a ddmin
shrinker run over the vnet. The standing invariants are listed in [`TESTING.md`](./TESTING.md) §4.

## 6. Zero-copy datapath

The packet path is one pooled `PlatformBuffer` per datagram, end to end:

1. **Receive** — the driver takes a buffer from the pool and `AddressedDatagramChannel.receive` fills
   it (direct `ByteBuffer`, `NWConnection` dispatch data, or pinned native memory).
2. **Demux without copying (RFC 7983)** — the first byte routes STUN (0–3), DTLS (20–63), RTP
   (128–191). Routing passes the *same buffer*; parsers are positional views, never extractions.
3. **STUN parse is views** — attributes decode as offsets into the datagram buffer;
   MESSAGE-INTEGRITY and FINGERPRINT verify in place.
4. **DTLS is in-Kotlin** — records are processed over buffers with no FFI edge and no memory-BIO copy,
   which is a direct consequence of the engine being ours rather than a native library's.
5. **SCTP** — user messages are `ReadBuffer` slices chained into chunks; fragmentation and reassembly
   are lists of retained slices, coalesced only when the consumer asks.
6. **Factory and pool discipline** — one `BufferFactory` constructor parameter everywhere (a size-class
   pool in production, a tracking factory in tests), lifecycle through `use { }` /
   `readBufferScoped { }`. The buffer **slice-lifetime contract** (a slice must not outlive its
   parent's pool scope) is what makes view-based parsing safe: a parsed packet's views die when the
   driver returns the datagram buffer, and anything that must outlive it pays an explicit `copy*`-verb
   cost — visible in the API name. Key material lives in `buffer-crypto`'s `secureFixedPool`, wiped on
   free.

## 7. Testing tiers

Summarized here; the operational detail is in [`TESTING.md`](./TESTING.md).

| Tier | What | Where |
|---|---|---|
| **T0 — codec floor** | round-trip + property tests + a committed malformed corpus; a parse failure is a typed reject, never a throw-through or a crash | commonTest, all platforms |
| **T0′ — coverage-guided fuzz** | Jazzer over the pure-Kotlin parsers, which have real JVM-bytecode coverage feedback | jvmTest, time-boxed |
| **TA — timeline replay** | fixtures + seeded fuzz + shrinker over the vnet, virtual time | commonTest, all platforms |
| **TB — real-stack vnet** | the full stack through simulated NATs and impairment; golden trajectories | commonTest, native + JVM |
| **TP — platform adapter** | the thin actuals the deterministic tiers stub out, against the real OS API | jvm / native / androidHost tests |
| **Integration** | container harness: coturn, NAT-profile containers, netem, toxiproxy on signaling | harness CI job |
| **Interop** | our stack against Pion, werift, Chrome, Firefox and WebKit | harness CI job |
| **Consumer** | `webrtc-testsuite` resolved by coordinate from a cold repository, then compiled, linked and run | `consumer-smoke` |
| **Benchmarks** | kotlinx-benchmark in `commonBenchmark`, tracked in [`PERFORMANCE.md`](./PERFORMANCE.md) | on demand + release |

Assertion discipline throughout: observable state plus a watchdog, never a wall-clock budget; `scenario
= port`; wrapper transparency (everything must work when handed a pooled or tracked buffer, not just a
raw `PlatformBuffer`).

## 8. Build, CI, publishing

The same target matrix as socket (JVM, Android, JS, wasmJs, Linux x64/arm64, Apple), a JDK 21
toolchain, blocking ktlint and non-blocking detekt (the only analyzer that sees Native/JS/wasm
actuals), binary-compatibility validation with checked-in per-module `.api` files, kover, Dokka, and
actions pinned to SHAs. Versioning is auto-derived from Maven Central metadata with PR-label bumps;
publishing is gated on an aggregate check plus the consumer-smoke lane, and **every** published
artifact — `webrtc-testsuite` included — goes through artifact validation from its first release.

All of it lives in one convention plugin,
`build-logic/src/main/kotlin/webrtc.multiplatform-library.gradle.kts`. A module's own build file
carries only its dependencies; structural identity (artifact id, JS module name, Android namespace) is
derived from the module name.

## 9. Where the stack stops

Sixteen targets publish. Not all of them can establish a session, and the reasons are structural rather
than incidental — worth stating plainly, because "it compiles" is not the same claim as "it connects".

- **jvm, android, linux ×2, macOS ×2, iOS ×3, tvOS ×3, watchOS ×2** — real UDP and a real handshake.
  The full thing.
- **Browsers (js, wasmJs)** — the delegation path of §1.1. Nothing of ours runs on the wire there.
- **Node (js)** — no `RTCPeerConnection` to delegate to, and the native path cannot handshake: DTLS
  needs a *blocking* raw-ECDH premaster, and `buffer-crypto`'s js key agreement is WebCrypto, which is
  async only. It fails with a typed `DtlsFailureReason.BackendUnavailable` rather than hanging. Node's
  own `crypto.createECDH()` **is** synchronous, so this is closable upstream, not a wall.
- **watchOS, on a real watch** — not a target at all, and the one place the "publishes but cannot
  establish" shape survives in weaker form. The five tvOS/watchOS targets used to sit here, blocked on
  `socket-udp` publishing no artifact for them; **socket 4.1.6 published all six**, so they establish
  like any other Apple target and moved to the first bullet. What did not close is `watchosArm64` — the
  32-bit `arm64_32` *device*. `buffer-crypto` publishes no klib for it and our matrix omits it to match,
  so both watchOS artifacts we ship are simulator ones. Simulator coverage is real coverage (the tvOS
  simulator lane runs the whole suite on the same `appleMain` sources), but a watch app cannot link this
  library until that klib exists upstream. Also unproven on tvOS/watchOS specifically: mDNS, because no
  test anywhere binds real multicast — every mDNS fixture substitutes an in-memory binder, so the
  multicast entitlement those platforms require has never been exercised.
- **Windows** — through the JVM. There is no Kotlin/Native Windows target in the matrix.

## 10. Non-goals

- Wrapping libwebrtc on any non-browser platform (§1).
- A signaling implementation — seam only (§2).
- Codec encode/decode inside the transport library.
- Legacy interop breadth (DTLS 1.0, SDES-SRTP, RTP over TCP/ICE-TCP). Modern profile only, until an
  interop matrix demands otherwise; each exception must arrive with a harness lane.

## 11. Decisions that bind

Design choices that constrain what may be built next. Each is settled; what follows from it is not
optional.

### 11.2 SCTP is the data-channel subset

dcSCTP-shaped: one path, no multihoming, no RFC 8260 stream interleaving, no HEARTBEAT — **ICE consent
freshness owns path liveness**, so a second liveness mechanism would be a second source of truth. Full
RFC 9260 is not needed for `RTCDataChannel` semantics and is not a goal. RFC 6525's four non-originated
reconfiguration request types are decoded and explicitly refused rather than silently ignored.

### 11.4 mDNS candidate privacy goes both ways

A browser hides its LAN address behind a `<uuid>.local` precisely so the signaling server learns nothing
about the private network. We resolve a peer's names **and** publish our own, because publishing ours in
the clear would make a page using this library strictly less private than the same page using
`RTCPeerConnection`.

The default therefore depends on **who can see a socket**, and the two answers differ on purpose:

- **`nativePeerConnection(…)` advertises by default** (`mdns = true`, issues #100 / #135). It is in
  `socketMain`, so it can construct the `MulticastMdnsEndpoint` that makes the promise good, and a
  browser does this unconditionally — a page using this library should not be strictly less private
  than the same page using `RTCPeerConnection`.
- **A hand-built `PeerConnectionConfig` is opt-in** (`MdnsAdvertisePolicy`, wired through
  `withMulticastMdns(…)`), and that is structural rather than conservative: `PeerConnectionConfig` is
  `commonMain` and cannot construct a multicast responder, so a default of "advertise" *there* would
  mean "advertise with nobody answering" — which costs the peer the candidate outright and is worse
  than publishing the address.

Everything but the socket is `commonMain`: the codec, the RFC 6762 §6 policy and the dispatch loop run
over the vnet, with only the 5353 bind-and-join at the edge.

### 11.5 DTLS is ours, in `commonMain`

DTLS was once the single exception to §1 — the one native dependency — and it was the exception that
cost the most: cinterop provisioning, a duplicate-symbol hazard, a deferred error-vocabulary bridge, all
of it existing solely because we linked BoringSSL. What that library supplied was the *protocol* (the
handshake FSM, the record layer, retransmission, self-signed X.509 generation, fingerprints), not the
crypto; the primitives were already in `buffer-crypto`. So the protocol was written over them, and the
native dependency is gone. Every non-browser target now has a real handshake with no backend gap, no FFI
edge and no memory-BIO copy.

Two things follow. Certificate handling is a **bounded** ASN.1 DER slice — emit a fixed self-signed
template, and from the peer extract only what CertificateVerify needs — never a general-purpose parser.
And BoringSSL stays permanently as a **differential-testing oracle** under `linuxTest`: handshaking
pure-Kotlin against it in both directions is the best available validation of a from-scratch TLS stack.

### 11.6 One UDP socket, shared with QUIC-P2P

**The cores never open a socket.** They take an injected `DatagramBinder`, and the library does not
depend on `socket` in `commonMain` or in the root consumer module. `socket-udp` is one production
*default* a driver may inject — `udpDatagramBinder()` — not a coupling.

That injection is what preserves a single demultiplexed UDP socket. On one port, inbound datagrams split
by first byte (RFC 7983 already specifies this for STUN/DTLS/RTP; the table extends to QUIC's long and
short headers). A consumer owns **one** channel, hands WebRTC a binder yielding only the STUN/DTLS
packets and `socket-quic` the QUIC packets — same socket, same 5-tuple, same NAT binding, same gathered
candidate set. It composes today, with no change to this library, because WebRTC only ever sees an
injected channel.

The concrete future that protects: `draft-seemann-quic-nat-traversal` (implemented in quic-go and
libp2p) does ICE-style address discovery plus QUIC path validation to hole-punch with no DTLS or SCTP.
Running that *and* WebRTC data channels over one socket and one candidate set needs a shared
connectivity substrate — gather once, punch once, demux the established path. A socket-owning factory
cannot participate.

**So there is no batteries-included factory that opens its own socket, and there must not be.** A
convenience helper has to accept an externally owned channel so it can be handed the very socket QUIC is
using. `udpDatagramBinder()` is deliberately the smaller thing: it binds when asked, owns no lifecycle
and holds no state.

That helper now exists, and it obeys the rule structurally rather than by promise: `nativePeerConnection`
(and the `systemIceGathering()` policy beneath it, issue #136 / #135) takes the `DatagramBinder` as a
**required parameter with no default**, so there is no code path in either that can bind something the
caller did not hand over. Pass `udpDatagramBinder()` for a session that owns its sockets, or a demuxed
view of an existing one to share it with QUIC-P2P. This is why the factory was deferred twice before it
was written: the constraint had to be expressible in the signature, not in a comment above it.

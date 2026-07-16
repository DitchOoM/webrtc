# Design principles — `com.ditchoom:webrtc`

The one-line version: **the type system is the first correctness proof, and every byte on the wire is
a view into a pooled buffer, never a copy.** This file is the worked-examples companion to the
standing directives in `CLAUDE.md`. The examples below are the real placeholder types in the module
tree — grep for them.

---

## 1. Zero-copy: no `ByteArray`, no primitive arrays, in production

A `ByteArray`/`IntArray`/`LongArray` in a hot path is a guaranteed memory copy. This library exists to
avoid that, so production (`*Main/`) source sets use `ReadBuffer` / `WriteBuffer` / `PlatformBuffer`
and positional **slice views** end to end (RFC §6, the zero-copy datapath):

- Received datagrams are one pooled `PlatformBuffer`; RFC-7983 demux routes the *same buffer* to STUN
  / DTLS / RTP parsers by first byte.
- Parsers decode attributes as offsets into that buffer (`slice()`), never extractions.
  MESSAGE-INTEGRITY / fingerprint verify in place.
- The DTLS FFI edge uses native-memory BIOs fed with `toNativeData()` handles — no `ByteArray` at the
  boundary.

The **slice-lifetime contract** makes this safe: a view must not outlive its parent buffer's pool
scope. Anything that must outlive it pays an explicit `copy*`-verb cost — the cost is visible in the
API name. CI (`standing-directives.yaml`) greps `*Main/` for every `*Array` type; a genuine platform
edge annotates the line `@Suppress("NoByteArrayInProd")` naming the API surface.

## 2. Value classes wrap every identifier

Zero runtime cost (`@JvmInline`), maximum compile-time safety. An identifier is never a bare
`String`/`Int`/`Long` at an API boundary — the compiler then refuses to pass the wrong one.

```kotlin
@JvmInline value class Ufrag(val value: String)
@JvmInline value class IcePassword(val value: String)   // distinct type, same underlying String

fun authenticate(ufrag: Ufrag, password: IcePassword)   // callers cannot swap the arguments
```

Real examples in the tree: `TransactionId` (webrtc-stun), `Ufrag`/`IcePassword` (webrtc-ice),
`StreamId`/`Tsn` (webrtc-sctp), `Mid` (webrtc-sdp), `CertificateFingerprint` (webrtc-dtls). Where an id
has an invariant (a STUN transaction id is 96
bits; an SCTP stream id is a u16), the `init { require(...) }` enforces it at construction, so an
invalid id cannot exist.

## 3. Sealed hierarchies + exhaustive `when`, no `else`

Message types, states, and failure reasons are sealed. A `when` over them compiles without an `else`;
adding a variant becomes a compile error at every call site until it is handled — the compiler drives
the change through the codebase for you.

```kotlin
sealed interface IceFailureReason {
    object NoCandidatePairs : IceFailureReason
    object ConsentExpired : IceFailureReason
    data class AllPairsFailed(val pairsTried: Int) : IceFailureReason
}
```

Prefer a sealed hierarchy to an enum when variants carry data (`AllPairsFailed` above). Use an enum
only for a genuinely dataless, closed set (`DtlsRole { Client, Server }`, `StunClass`) — and reach for
an enum instead of an `Int`-with-a-range-check where the set really is closed: `ComponentId` is an enum
(`Rtp = 1`, `Rtcp = 2`), so an illegal component id is unrepresentable and there is no `require(...)` to
forget.

A result's **failure branch is often itself a sealed hierarchy**, so the *cause* is exhaustive rather
than a single lumped sentinel that quietly means three different things (the same overloading sin as a
`null`). `gatherServerReflexive` returns `ServerReflexiveResult { Discovered(address) | Unavailable }`,
where `Unavailable` splits into `NoResponse | Rejected | MalformedResponse`. A caller that only needs
success-or-not matches `is Unavailable`; one that wants the reason `when`s over the variants — both
exhaustive, both driven through the codebase by the compiler when a variant is added.

## 4. No boolean soup, no nullable soup — no impossible states

Do **not** model a lifecycle as a bag of flags and nullables:

```kotlin
// WRONG — encodes impossible states: connected AND failed, closed with a live pair id, etc.
class BadState(
    val connecting: Boolean,
    val connected: Boolean,
    val failureReason: String?,
    val selectedPairId: Long?,
)
```

Model it as a sealed hierarchy where **each state carries exactly the data valid in it, and nothing
that isn't**:

```kotlin
sealed interface PeerConnectionState {
    object New : PeerConnectionState
    object Connecting : PeerConnectionState
    data class Connected(val selectedPairId: Long) : PeerConnectionState   // pair id only exists here
    data class Failed(val reason: String) : PeerConnectionState
    object Closed : PeerConnectionState
}
```

The illegal combinations are now unrepresentable — there is no value of `PeerConnectionState` that is
both connected and failed. This is the single most important rule for the state-machine cores.

**The same rule applies to data models, not just lifecycle states.** An ICE candidate has fields that
are valid for some kinds and meaningless for others: a *host* candidate has no server-reflexive
"related address", and a *relay* candidate's base **is** its address rather than a separate local
socket. Modeling it as one class with nullable/duplicated fields (`relatedAddress: TransportAddress?`,
a free `base`) makes "a host candidate carrying a relay's related address" representable. A **sealed
hierarchy per type** makes it unrepresentable — each variant carries exactly its valid fields:

```kotlin
sealed interface IceCandidate {
    val address: TransportAddress          // where a peer sends to reach this candidate
    val base: TransportAddress             // the local socket we send from
    val priority: Long
    val type: CandidateType                // the discriminant
    // …common fields…

    data class Host(/* address, component, … */) : IceCandidate {
        override val base get() = address                       // a host candidate's base IS its address
        override val type get() = CandidateType.Host
    }
    data class ServerReflexive(
        override val base: TransportAddress,                    // the local host we reflected from
        val relatedAddress: TransportAddress,                  // required and present — never null
        /* address, … */
    ) : IceCandidate { override val type get() = CandidateType.ServerReflexive }
    data class Relayed(
        val relatedAddress: TransportAddress,
        /* address, … */
    ) : IceCandidate {
        override val base get() = address                       // a relay candidate's base is the relayed address
        override val type get() = CandidateType.Relayed
    }
}
```

`relatedAddress` is now non-null and exists only where it means something; `base` is *derived* for the
variants where it isn't a free field. Grep `IceCandidate` in `webrtc-ice`.

The discipline runs **inside** a core too. The ICE `PairEntry` bundles a check's transaction with its
purpose — `InFlightCheck(transaction, CheckPurpose)` — so a purpose (nomination / consent / ordinary)
cannot exist without a live check, and "a nomination is in flight" is **derived** from the checklist
rather than stored in a latch that can wedge stale. A stored `nominating`/`consentCheck`/`nominationInFlight`
soup is exactly what let an earlier version hang; the derived, unified model makes that bug unrepresentable.

## 5. Nullability is a deliberate signal

A nullable type means exactly one thing: **genuinely absent**. It is never:
- a stand-in for an error → that is a typed sealed reason (directive #3);
- an "uninitialized" placeholder → that is a distinct state in a sealed hierarchy (§4);
- a lazy "maybe I'll set it later" → construct the object when you have the data.

`nextDeadline(now): Instant?` returning `null` has one meaning — "no timer is armed" — and that is
the whole point of the sans-io clock contract. (It stays a nullable `Instant`, not a sealed
`Armed | Idle`, precisely because that single meaning is stable and it is the *uniform* contract across
every sans-io core — STUN, ICE, SCTP — with zero per-call allocation in the driver loop.)

A corollary: if a field is **present in some variants and absent in others**, it is not a nullable
field on one class — it is a field on the variants that have it. The sealed `IceCandidate` in §4 is the
worked example: `relatedAddress` lives on `ServerReflexive` / `PeerReflexive` / `Relayed` as a required
field, never as a nullable on a single catch-all class. Splitting the type beats overloading `null`.

## 6. Errors are typed, cores are sans-io

Every failure surfaces as a value in a sealed hierarchy that maps into `socket`'s `SocketException`
vocabulary. Strings are diagnostics attached to a typed reason, never the discriminant. Parse
failures are typed *rejects* (`DecodeResult.Reject`), never a throw-through or a crash (T0).

And the cores never reach for ambient state: `handle(event, now): List<Output>` + `nextDeadline` —
no dispatcher, no `Clock.System`, no `Random.Default`, no I/O. Time, entropy, and concurrency are
injected seams with production defaults, which is what makes the whole stack replayable under virtual
time. CI greps `*Main/` for unseamed `Clock.System` / `Random.Default` / `Dispatchers.*`.

## 7. Swappable transports via buffer-flow primitives

WebRTC is one transport among several. The whole point of building on `buffer-flow` is that consumers
program against its **`StreamMux` / `ByteStream`** primitives, not against WebRTC directly — so the
transport underneath is swappable without touching consumer code. There are two swap seams:

- **Consumer-facing (the mux).** `DataChannel` *is* a `StreamMux`: `openBidirectional()` gives a
  `ByteStream`. Anything written against `MultiplexingTransport`-style mux code (MQTT, RPC, a codec
  pipe) runs over a WebRTC data channel, a TCP socket, or a QUIC stream **unchanged** — you swap the
  transport by swapping which `StreamMux` you hand it. This is why `webrtc`, `webrtc-ice`, and
  `webrtc-sctp` depend on `buffer-flow`: the mux abstraction is the public contract, WebRTC is one
  implementation of it. For a test, a consumer can drive the exact same code over an in-memory
  `StreamMux` double — no sockets, no signaling.
- **Internal (the I/O seams).** Below the mux, the cores take injected seams — the `DatagramChannel`
  (the vnet in tests, real UDP in production) and the signaling interface — so the *network itself* is
  swappable. Tests run the real ICE/DTLS/SCTP stack over a simulated NAT topology under virtual time;
  production runs it over real sockets. Same cores, different seam.

So "swap the transport for testing" happens at whichever layer you need: replace the whole session with
a fake `StreamMux`, or keep the real protocol stack and replace only the packets/clock beneath it.

---

These rules are not style preferences; each one buys a specific property — zero-copy throughput,
deterministic replay, compiler-enforced correctness, or transport-swappability — that the RFC's
architecture depends on.

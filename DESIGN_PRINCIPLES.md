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
`StreamId`/`Tsn` (webrtc-sctp), `DataChannelId` (webrtc), `Mid` (webrtc-sdp),
`CertificateFingerprint` (webrtc-dtls). Where an id has an invariant (a STUN transaction id is 96
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
only for a genuinely dataless, closed set (`DtlsRole { Client, Server }`, `StunClass`).

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

## 5. Nullability is a deliberate signal

A nullable type means exactly one thing: **genuinely absent**. It is never:
- a stand-in for an error → that is a typed sealed reason (directive #3);
- an "uninitialized" placeholder → that is a distinct state in a sealed hierarchy (§4);
- a lazy "maybe I'll set it later" → construct the object when you have the data.

`nextDeadline(now): Instant?` returning `null` has one meaning — "no timer is armed" — and that is
the whole point of the sans-io clock contract.

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

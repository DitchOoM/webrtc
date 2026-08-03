# webrtc

**WebRTC data channels for Kotlin Multiplatform — zero-copy, sans-io, and deterministic under test.**

`com.ditchoom:webrtc` is a WebRTC stack written in common Kotlin on top of the DitchOoM
[`buffer`](https://github.com/DitchOoM/buffer) and [`socket`](https://github.com/DitchOoM/socket)
libraries. ICE, DTLS, SCTP and the JSEP/SDP machinery are **ours**, in `commonMain` — this is not a
wrapper around libwebrtc, and there is no native blob to ship. The one exception is the browser, where
raw UDP does not exist and the implementation delegates to the platform's own `RTCPeerConnection`.

It establishes and carries data channels against Chrome, Firefox, WebKit, [Pion](https://github.com/pion/webrtc)
and [werift](https://github.com/shinyoshiaki/werift-webrtc) over real NAT kernels in CI, on IPv4, IPv6
and dual-stack.

```kotlin
dependencies {
    implementation("com.ditchoom:webrtc:0.14.0")
}
```

Media (RTP/SRTP) is not implemented. This is the data-channel half of WebRTC — the part that carries
bytes, and the part with no codec or hardware dependencies.

## Quickstart

Three things have to be decided before a session exists, and the library asks for all three rather than
guessing: **which sockets to bind**, **which addresses to gather on**, and **what identity to present**.

```kotlin
fun peerConnection(
    scope: CoroutineScope,
    clock: () -> Instant, // Clock.System::now in production
    seed: Long,
    stunServer: SocketAddress? = null, // SocketAddress.resolve("stun.example.org", 3478)
) = NativePeerConnection(
    scope = scope,
    clock = clock,
    random = Random(seed),
    // The one seam between a virtual-time test and a real kernel.
    binder = udpDatagramBinder(),
    // Which sockets to bind. Port 0 asks the OS for an ephemeral one — a pinned port cannot
    // survive an ICE restart, which re-gathers while the old sockets are still bound.
    gathering =
        IceGatheringPolicy { driver ->
            val snapshot = systemInterfaceEnumerator().enumerate()
            val interfaces = (snapshot as? InterfaceSnapshot.Enumerated)?.interfaces.orEmpty()
            for (local in interfaces) {
                driver.gatherHost(local.address.host, port = 0, stunServer = stunServer)
            }
        },
    // One factory is one endpoint identity: its certificate is the a=fingerprint we offer.
    dtls = PureKotlinDtls(scope, clock),
)
```

That block is not an illustration — it is compiled and run on every build, as
[`ReadmeQuickstartTest`](webrtc/src/jvmTest/kotlin/com/ditchoom/webrtc/ReadmeQuickstartTest.kt), which
stands two peers up over real loopback UDP and echoes a message between them.

Then run the ordinary offer/answer dance and ship the results over **your** signaling:

```kotlin
val pc = peerConnection(scope, Clock.System::now, seed = Random.nextLong(), stunServer = stun)
val chat = pc.createDataChannel(DataChannelConfig(label = "chat"))

val offer = pc.createOffer()
pc.setLocalDescription(SdpType.Offer, offer)
signaling.send(offer)                                  // your transport, your protocol

pc.setRemoteDescription(SdpType.Answer, signaling.awaitAnswer())

// Trickle both ways (RFC 8838)
scope.launch { pc.localIceCandidates.collect { signaling.send(it) } }
scope.launch { signaling.remoteCandidates.collect { pc.addIceCandidate(it) } }

pc.connectionState.first { it is PeerConnectionState.Connected }
```

**Signaling is a seam, never an implementation.** Descriptions and candidates cross as SDP text and
`candidate:` lines — the exact currency a browser `RTCPeerConnection` speaks — and how they reach the
peer is yours. WebRTC standardizes no signaling protocol, and keeping it out is also what makes the
offer/answer machine testable without a network.

### Sending and receiving

A data channel **is** a buffer-flow `Connection<ReadBuffer>`, so anything written against
`StreamMux`-style code runs over WebRTC unchanged:

```kotlin
chat.send(buffer)
chat.receive().collect { incoming -> /* a ReadBuffer, not a copy */ }

pc.incomingDataChannels.collect { channel -> /* the peer opened one (ondatachannel) */ }
```

Channels are ordered and reliable by default; `DataChannelConfig` selects `DeliveryOrder.Unordered` and
the partial-reliability modes — `SctpReliability.MaxRetransmits(n)` or `.MaxLifetime(duration)`
(PR-SCTP, RFC 3758).

### On a browser

`peerConnectionSupport()` is a sealed type, so the branch is checked at compile time rather than
discovered at runtime:

```kotlin
val pc = when (val support = peerConnectionSupport()) {
    is PeerConnectionSupport.BrowserDelegated -> support.create(scope, iceServers)
    PeerConnectionSupport.Native              -> NativePeerConnection(/* as above */)
}
```

Both arms return the same `RtcPeerConnection`, so everything after this point is shared code.

## Platform support

| Platform | Status |
|---|---|
| JVM, Android | **Full** — real UDP, pure-Kotlin DTLS |
| Linux (x64, arm64) | **Full** |
| macOS, iOS (x64, arm64, simulator) | **Full** |
| Browser (js, wasmJs) | **Full**, by delegating to the platform `RTCPeerConnection` |
| Node (js) | **Not usable.** There is no `RTCPeerConnection` to delegate to, and the native path's DTLS handshake fails with a typed `DtlsFailureReason.BackendUnavailable` — the raw-ECDH primitive it needs is async-only on that target |
| tvOS, watchOS | Publishes and compiles; **cannot establish** — `socket-udp` ships no UDP actual for these targets yet, so there is no binder |
| Windows | Via the JVM. There is no Kotlin/Native Windows target |

DTLS 1.2 and 1.3 are pure Kotlin in `commonMain` on every non-browser target, so there is no platform
where the handshake depends on a native library being present.

## What it does

- **ICE** (RFC 8445) with trickle (RFC 8838), host / server-reflexive / TURN-relay candidates, consent
  freshness (RFC 7675), and **ICE restart** — including the part most stacks skip: the session *survives*
  it. DTLS and SCTP are not renegotiated (RFC 8842 §5.5), open channels keep their stream ids, and data
  keeps riding the old pair until the new one nominates.
- **mDNS candidate privacy** (RFC 8828), both directions — resolve a peer's `<uuid>.local` and publish
  your own instead of your LAN address. Opt-in via `PeerConnectionConfig(mdnsAdvertising = …)`.
- **DTLS 1.2 / 1.3** with the RFC 8122 fingerprint check binding the signaling channel to the data path.
- **SCTP** (RFC 8831) + **DCEP** (RFC 8832): ordered/unordered, reliable/partially-reliable, fragmentation
  and reassembly, per-channel and graceful shutdown.
- **A network monitor** — `systemNetworkMonitor()` is push-based where the OS offers a signal
  (`ConnectivityManager`, `AF_NETLINK`, `NWPathMonitor`, the JDK-21 routing socket) and polls where it
  does not. Pair it with `IceRestartPolicy.OnNetworkChange` to restart automatically when the selected
  pair's interface goes away. The default stays `Manual`, because a restart is a renegotiation only your
  signaling channel can carry.

Deliberately **not** implemented: SCTP multihoming, RFC 8260 interleaving, and HEARTBEAT (ICE consent
freshness owns path liveness); RFC 6525's four non-originated reconfiguration request types (decoded and
explicitly refused); and establishing a *new* DTLS association on renegotiation (a re-answer implying the
opposite role is refused with a typed reason).

## Why an own stack

| | Wrapping libwebrtc | This |
|---|---|---|
| Copies | Every frame crosses a JNI/ObjC boundary as a `ByteArray`/`NSData` | `ReadBuffer`/`WriteBuffer` end to end |
| Determinism | None — libwebrtc owns its threads, timers and RNG | Every core is caller-clocked; the whole stack runs under `runTest` virtual time |
| Reproducing a bug | Black box | A field capture becomes a committed fixture that replays in milliseconds, forever |
| Platforms | Android/iOS | The full KMP matrix, JVM and Linux servers included |

Every protocol state machine is a pure `handle(event, now): List<Output>` plus a
`nextDeadline(now): Instant?` — no dispatcher, no `Clock.System`, no `Random.Default`, no I/O inside a
core. Drivers own I/O; cores own truth. The practical consequence is that a full ICE + DTLS + SCTP
establishment completes at zero wall-clock on every target, and a 90-second field saga replays in
milliseconds.

## Testing your own code against it

`com.ditchoom:webrtc-testsuite` publishes the harness this project tests itself with: an in-memory
virtual network with NAT profiles, a TURN server, and an impairment pipe — all under `runTest` virtual
time, on every platform, with no Docker and no OS sockets.

```kotlin
dependencies {
    testImplementation("com.ditchoom:webrtc-testsuite:0.14.0")
}
```

```kotlin
runTest {
    withWebRtcHarness(scope = backgroundScope, clock = virtualClock) {
        natType(NatType.Symmetric)      // both peers behind a symmetric NAT (RFC 4787)
        relayOnly()                     // force the TURN-relay path
        impaired(loss = 0.05)           // 5% packet loss
        assertEquals("ping", roundTrip("ping"))
    }
}
```

## Building

```bash
./gradlew build        # all modules, all host-available targets
./gradlew allTests     # tests across every module + platform
```

Requires **JDK 21** (via toolchain). Apple targets build on macOS only.

## Modules

`webrtc` is the only artifact most consumers need; it brings the rest transitively.

| Module | What |
|---|---|
| `webrtc` | `PeerConnection`, the JSEP state machine, data channels — the consumer API |
| `webrtc-sdp` | SDP parse/serialize — no I/O |
| `webrtc-stun` | STUN/TURN wire codec (RFC 8489/8656) + sans-io client machines |
| `webrtc-ice` | ICE agent (RFC 8445, 8838) — sans-io core, gathering seams, `udpDatagramBinder()` |
| `webrtc-dtls` | DTLS 1.2/1.3 + the DTLS-SRTP exporter |
| `webrtc-sctp` | SCTP (RFC 8831) + DCEP (RFC 8832) |
| `webrtc-testsuite` | The published harness above |

## Documentation

Every published artifact ships a Dokka javadoc jar, and the KDoc is where the detail lives — most types
here document the decision behind them, not just the signature. Alongside it:
[CHANGELOG](./CHANGELOG.md) ·
[Design principles](./DESIGN_PRINCIPLES.md) ·
[Testing strategy](./TESTING.md)

## License

Apache 2.0 — see [`LICENSE.md`](./LICENSE.md).

# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Project overview

`com.ditchoom:webrtc` — WebRTC **data channels** for Kotlin Multiplatform: zero-copy, sans-io, and
deterministic under test. Built on DitchOoM `buffer` (buffers, codec, crypto, flow) and `socket`
(transport model, typed errors, `NetworkMonitor`, real UDP actuals). The protocol cores are **ours**, in
common Kotlin — we do not wrap libwebrtc on any non-browser target. Browsers are the sole exception:
there `peerConnectionSupport()` delegates to `RTCPeerConnection`. Media (RTP/SRTP) is not implemented.

**Read these first, in order** (a resumed session starts here):

1. [`ARCHITECTURE.md`](./ARCHITECTURE.md) — how the pieces fit and why. Sections are cited from KDoc
   throughout the source as `ARCHITECTURE §n`, so keep the numbering stable.
2. [`DESIGN_PRINCIPLES.md`](./DESIGN_PRINCIPLES.md) — the type-safety + zero-copy manifesto, with code
   patterns.
3. [`TESTING.md`](./TESTING.md) — the tiers, the harness, the L1↔L2 parity matrix, external vectors.
4. [`README.md`](./README.md) — what a consumer sees. Its quickstart is compiled and diff-checked by
   `ReadmeQuickstartTest`; edit the two together or the build fails.

## Current state

Released on Maven Central; the data-channel stack is complete. It establishes and carries data channels
against Chrome, Firefox, WebKit, Pion and werift over real NAT kernels in CI across
`{x64, arm64} × {v4, v6, dual}`, and every lane also gates on the data-channel *semantics* sequence
(fragmentation, unordered, PR-SCTP, multiplexing, reverse-direction, per-channel close, graceful
shutdown). Every interop lane runs a **Linux or JVM** peer, which is why Android being non-functional
(Traps, below) went unseen for so long: no lane anywhere executed on ART until the emulator lane landed,
and the full common suite — 611 tests — now runs there per PR. Pinned at **socket 4.2.0 + buffer
6.28.1**. socket
4.1.0 + buffer 6.25.0 is the pair that introduced `DatagramCapabilities.requiresNativeMemoryBuffers`,
which is what the send-side buffer check consumes, and that seam is why the two normally move together.
Buffer rides ahead deliberately: 6.26.0 is the Apple AEAD ownership fix and #343 the Android X25519
fix (both below), pure internal fixes with no API change, so resolving buffer up underneath a socket
built against 6.25.0 is safe. socket-udp 4.2.0's POM still declares buffer 6.25.0, so that skew is
unchanged — re-align on a socket release that pins 6.26.0 or later. socket itself has since moved to
4.3.1, which this pin has not yet taken; `socket-udp-watchosdevicearm64` is still absent there, so the
watchOS row below is unchanged by it.

**6.28.0 is the one buffer version in this line to never resolve to**, and the reason is worth keeping
even though the pin no longer depends on it. For one night the highest number was not the newest
content: 6.28.0 was tagged from #342 *before* #343 merged, while #343 shipped as 6.27.1 afterwards from
a commit whose parent is #342's — so 6.27.1 strictly contained 6.28.0, and pinning it meant Gradle
(which resolves conflicts **up**) would silently revert the X25519 fix for anything naming 6.28.0.
**6.28.1 closes this**: it is both the highest number and content-complete, so resolving up is safe
again. The long note lives at the pin in `libs.versions.toml`; the durable habit is to check the
published `-sources.jar` rather than the version order.

### Capabilities that are easy to under-estimate

- **ICE restart survives the session.** `restartIce()` records intent; the next `createOffer()` carries a
  fresh generation; a peer's own restart is detected from an offer whose ufrag *and* pwd both changed;
  `setLocalDescription(Rollback)` restores the retained generation. DTLS and SCTP never renegotiate
  (RFC 8842 §5.5), open channels keep their stream ids, and data keeps riding the old pair until the new
  one nominates. Proven in **both** directions: the `carrier-switch` lanes prove a production stack
  answers a restart we initiate, and the `foreign-restart` lanes prove we detect and answer one that
  Pion, Chrome, Firefox or WebKit originates.
- **Trickled candidates carry their generation** (RFC 8838 §3.1), stamped inside the driver's serialized
  loop so a candidate cannot be tagged with a generation it is not in. An incoming candidate is *routed*
  by that tag: one for a superseded generation is discarded with a typed reason, one for a generation
  whose offer has not arrived is held (bounded, oldest evicted) and released by the credentials event —
  never by a timer, so the core stays sans-io. Untagged candidates apply to the current generation. Opt
  out with `TrickleGenerationPolicy.Untagged`.
- **mDNS goes both ways** (RFC 8828) — opt-in, and it also redacts the `raddr` and the foundation, both
  of which would otherwise spell the host address out on the same line.
- **`systemNetworkMonitor()` is push-first**, composing socket's *reactivity* with our own *address
  enumeration* (ARCHITECTURE §4 — they answer different questions). A platform with no interface table
  says so in the type (`NetworkMonitorSupport.Unavailable`); one that can enumerate but has nothing
  pushing returns `Degraded(monitor, reason)`, so "it will be slower, and here is why" is answerable at
  config time rather than by inspecting a live session.
- **`PeerConnection.diagnostics`** is a sealed, non-fatal observation stream: watcher stopped, remote
  candidate discarded, interface probe failed, transmit failed, relay permission refused. Channel-backed
  rather than a `SharedFlow` on purpose — a Channel buffers from construction, and the most important
  diagnostic is emitted during start-up, which no caller can reliably subscribe ahead of. The last two
  exist because the alternative is a *silent* failure that looks like the network: a socket refusing
  every send and a TURN server answering `443 Peer Address Family Mismatch` both otherwise present
  identically to a peer that stopped answering. `RelayPermissionRefused.error` is a protocol code and
  therefore a real discriminant, unlike the `Throwable` payloads beside it.
- **`IceRestartPolicy` defaults to `Manual`** deliberately — an automatic restart is a renegotiation only
  the app's signaling channel can carry, so it is opt-in rather than a default flip.
- **Four SCTP capabilities are implemented but default OFF, which is exactly how they get rebuilt by
  mistake.** Read the `SctpConfig` knob before concluding any of them is missing: `pathMtu`
  (RFC 8899 discovery — a HEARTBEAT+PAD probe, so HEARTBEAT *is* originated here, scoped to sizing and
  never to liveness), `zeroChecksum` (RFC 9653 — additionally gated on what the transport underneath
  guarantees, so a policy alone never grants it), `streamGrowth` (RFC 6525 ADD STREAMS), and
  `receiveOverrun` (the aggregate receive-buffer ceiling, distinct from `receiveMessageLimit`'s
  single-message one). Each is off by default because each changes bytes on the wire against every peer.
- **Receive flow control is real and the credit is not optional.** `SctpOutput.MessageReceived` carries a
  `DeliveryReceipt` that must come back as `SctpEvent.MessageConsumed`, or the endpoint closes its own
  a_rwnd one message at a time and stalls a peer that is behaving perfectly — silently and cumulatively.
  The credit is fused with the buffer release wherever a message is not delivered onward, so forgetting
  one means forgetting the other and `assertPoolDrained` catches it.
- **Stream-id exhaustion is an answer, not a crash.** RFC 8832 §6 gives each side half a 16-bit space and
  the cursor never comes back down except through the reuse ledger; past the end, `open()` returns a typed
  `DataChannelOpenRefusal` with the association still Established. It used to throw from inside the
  serialized drive loop, which on Kotlin/Native is process death rather than a catchable exception.
- **TURN is long-lived.** The allocation refreshes at a fraction of the *granted* LIFETIME, permissions
  are re-installed (§9), every request retransmits, and the long-term-credential key is the RFC 8489
  §9.2.2 `MD5(user:realm:pass)` — pure-Kotlin MD5 in `webrtc-stun`, pinned by the RFC 5769 §2.4 vector.
- **The native entry point exists**: `nativePeerConnection()` in `webrtc`'s `socketMain` over
  `systemIceGathering()` in `webrtc-ice`'s. Both take the `DatagramBinder` as a **required** parameter,
  so neither can own a socket (ARCHITECTURE §11.6). `IceGatheringPolicy`, `IceServer` and
  `IceServerCredentials` live in `webrtc-ice`; `com.ditchoom.webrtc` keeps typealiases, but Kotlin cannot
  reach a *nested* classifier through one, so `IceServerCredentials.LongTerm` must be imported from the
  new package. mDNS defaults **on** in the factory only; a hand-built `NativePeerConnection` is
  unchanged. What it cannot honour is refused by typed reason rather than dropped: `turns:`,
  `?transport=tcp`, a credential-free `turn:`, an unresolvable name.

### Buffer ownership: every seam is owned, and gated at zero

The rule is written once on `IceProtocol.releaseReceived` and restated at each module's seam. A buffer
has exactly one owner; a loop that receives one either **consumes** it (release before the next
iteration) or **transfers** it (the receiver then owes it). A decoded attribute or wire field is
neither — it is a **borrow**, a slice that must not outlive its owner. On a pooled buffer a borrow is
also an `addRef`, so it has to be handed back too, which is why `assertNoLeaks` is not sufficient
anywhere: it proves `freeNativeMemory()` was *called*, and is structurally blind to a refcount that
never reached zero. **`assertPoolDrained` is the gate.**

| seam | fixture |
|---|---|
| received datagrams | `PooledReceiveChunkTest`, `ReceivedDatagramOwnershipTest` |
| ICE send | `SessionSeamOwnershipTest` |
| SCTP send | `SctpSendSeamOwnershipTest` |
| DTLS record (both 1.2 and 1.3) | `DtlsRecordSeamOwnershipTest`, `DtlsSessionBufferOwnershipTest` |
| mDNS responder, TURN relay | `MdnsTurnSeamOwnershipTest` |

**Consumers can assert this too**, as of `WebRtcHarnessScope.assertNoBufferLeaks()` / `bufferCensus()` in
`webrtc-testsuite` — a pool-backed tracking factory over the published vnet, measured after the harness
closes both peers, **joins** every coroutine it launched, and unbinds the vnet. Building it is what found
three production leaks of the class `assertNoLeaks` cannot see, all in `TurnAllocation`: every **Data
indication**'s decoded views (i.e. one pinned receive chunk per inbound packet on any relayed session),
`close()`'s deallocating Refresh, and a response that settles after its awaiter is gone. The shape they
share is worth remembering — **a decode whose result nobody returns is where a release goes missing**,
because there is no caller to notice and no `consuming {}` to structure it.

**Every seam in that table is now gated at zero, with no exemptions.** The last one was upstream rather
than ours: buffer-crypto's Apple AEAD `open` took two `absoluteView` slices of the ciphertext it was
handed (`Aead.apple.kt` / `AeadBridge.apple.kt`) and released neither, so on Apple every opened DTLS
record pinned the *receive* chunk twice, and nothing here could reach those slices.
`DtlsRecordSeamOwnershipTest` carried an `assertNoLeaks`-only exemption on its wire stand-in because of
it. Fixed upstream in **buffer PR #335** (pointer offsets instead of slices), shipped in **buffer
6.26.0**, which we now pin — so that fixture's wire tracker is `assertPoolDrained` like the rest. Do not
re-derive the exemption from an old comment; check the assertion.

Blast radius is **Kotlin/Native Linux only**: it is the sole target where `BufferFactory.Default` is a
GC-heap buffer, so `networkBuffer()` falls back to `deterministic()` there and a buffer nobody releases
stays allocated. Everywhere else `Default` is native *and* auto-reclaimed. `BufferPool(factory =
BufferFactory.deterministic())` — native-backed *and* refcounted — is the recommended consumer shape.

Two things about measuring it, both learned expensively:

- **Measure at the pool's backing factory** (`created - currentPoolSize`). Every formula derived from
  `PoolStats` has been wrong, in both directions. A *decorating* tracker perturbs its own measurement,
  because the liveness probe takes a slice.
- **One tracker per seam per peer**, and never a seam shared with harness scenery. A single tracker
  pointed at two seams produces a number that cannot be attributed to either.

Two facts about buffer-crypto that a caller has to know, because the types do not say them:
`AesGcmKey.of`, `VerifyKey.ecdsaP256` and `HmacSha256Mac` **copy** their input, so the source buffer is
spent at the call; `KeyAgreementPublicKey.of` **slices** it and the type it returns is not
`AutoCloseable`, so the caller has to hand `peer.encoded` back itself. Release also implies **wipe** for
anything derived: both key schedules allocate through `BufferFactory.secure()`, because an unwiped
traffic secret handed to a shared pool is a chunk the next `allocate()` gets — a leak traded for key
disclosure, which is worse.

An injected factory the send path cannot transmit from is refused at the bind that precedes the first
send, as a typed `UnsendableBufferFactoryException` naming the `WireBufferSeam` to change. The question
is put to the **channel** (`DatagramCapabilities.requiresNativeMemoryBuffers`), never to a platform table
and never as "is this buffer native": the JVM/NIO and Node send paths take a heap buffer happily, so the
buffer-side phrasing would break three working configurations to fix one. The 1-byte probe only runs once
a channel has said it needs a raw address, so a vnet run costs nothing. Checked at both `IceAgentDriver`
binds and at `MdnsEndpoint.socketFor` — the last deliberately *outside* `SocketUdpMdnsBinder`, whose
catch-all maps every exception to "mDNS is unavailable here" and would swallow the diagnosis.

### What is left

- **TURN is done.** The bullet that used to sit here — "realm rotation and per-provider quota semantics
  genuinely need a commercial provider" — was **wrong on both halves**, and is the ninth instance of this
  file's recurring failure mode. Neither needed a provider; one needed a fixture and the other needed
  reading the code.
  - *Realm rotation* was already implemented (`requestWithChallengeRetry` adopts the challenge's REALM and
    re-derives the key through `asChallenge()`) and asserted **nowhere**, because every TURN fixture ran a
    server whose realm was a `val` fixed for its life. A client that derived its key once and cached it
    forever passed the entire corpus. Now pinned by `TurnAllocationRealmRotationTest` over
    `RealmPolicy.RotateAfter`. The load-bearing part is the vnet server's `keyProvider`, which is keyed on
    `(username, realm)` — a provider closing over one fixed realm agrees with a cached-key client and the
    fixture proves nothing. A rotated REALM is strictly harder than a rotated NONCE: the nonce is opaque
    and gets copied back, the realm is an *input to the key* (RFC 8489 §9.2.2), so the client must
    re-derive. **No L2 lane, deliberately**: coturn reads `realm` at startup, so rotating it means
    restarting the process, which drops every allocation and destroys the property under test.
  - *Per-provider quota* needs nothing at all, and this is a claim about the code rather than a plan:
    `TurnAllocation` **never branches on the error code**. A refusal becomes
    `Unavailable.Rejected(settled.error)`, passing the server's own `StunErrorCode` through with no
    allow-list. A provider answering 508 Insufficient Capacity instead of 486 therefore arrives typed and
    non-fatal on exactly the path 486 already takes, which is proven at L1 (`TurnAllocationQuotaTest`) and
    L2 (`turn-quota`). There is no per-code handling left to get wrong, so a provider could only teach us
    *which* codes it emits — which changes nothing here.
- The three behaviours coturn's defaults hid (438 Stale Nonce, an allocation refresh, 486 quota) are
  seen from real coturn: `turn-lifecycle` compresses the server's clock (`stale-nonce=10`,
  `max-allocate-lifetime=20`) and holds a relay-pinned session past its granted LIFETIME, and `turn-quota`
  sets `user-quota=1` so one peer's relay is refused 486 and the session establishes anyway. Both assert
  from **coturn's own log** — the server saying what it did, not the session merely surviving — and both
  first check that coturn echoed the directive at startup, because "the setting is in the file" has never
  been evidence the process applied it. Measured, not assumed: against coturn 4.6.3 a real
  `TurnAllocation` refreshes at t+15 s and that Refresh is answered 438 then granted. Read the *client's*
  cadence rather than coturn's `new, lifetime=` line — that one prints 600 here, because coturn clamps a
  **requested** lifetime and our Allocate sends no LIFETIME attribute, while the response still carries 20.
- **Platforms:** Node needs blocking raw-ECDH plus a shipped binder (#133). tvOS/watchOS establish as of
  socket 4.2.0 (#127 closed), but **no watchOS *device* target is linkable end-to-end**, on either ABI —
  every watchOS artifact we ship is a simulator one and no watch app can link this yet. The two ABIs are
  blocked in opposite repos, which is why one release cannot clear both:
  - `watchosArm64` (**arm64_32**, 32-bit pointers) — blocked in **buffer**. buffer PR #342 **declined**
    it deliberately rather than closing it: arm64_32 is the only Apple target with a 32-bit `size_t`, and
    while each target compiles individually, `compileAppleMainKotlinMetadata` rejects merely *naming* a
    `size_t`-typed CommonCrypto/Security function across a width-mixed target set (112 errors over 17
    files). `.convert()` cannot help — the reference offends, not the argument. Admitting it means
    splitting `buffer-crypto`'s `appleMain` by pointer width. `buffer-crypto-watchosarm64` is still a 404
    on Central at 6.28.1; `socket-udp-watchosarm64` publishes fine, so socket is not the blocker here.
  - `watchosDeviceArm64` (64-bit device — Series 9 / Ultra) — blocked in **socket**, and our own matrix
    omits the target entirely. buffer #342 added it everywhere including `buffer-crypto`, but
    `socket-udp-watchosdevicearm64` is a 404 at 4.2.0 **and still at 4.3.1**, so this one needs a socket
    PR plus a target registration here — a plain socket bump will not deliver it.
  - **Do not read #342 as "arm64_32 is unblocked"** — an earlier revision of this file did, from the PR
    title alone. It adds the 64-bit device and states in a comment why the 32-bit one stays out.
- **Android's floor is API 28, and it is measured rather than chosen.** Two floors stack, and the
  declared minSdk of 21 satisfied neither.
  - *Runtime floor, 24.* The emulator lane ran at 21 and reported that 21 cannot host this stack at
    all: ART's `sun.misc.Unsafe` has no `allocateMemory` before 24 (a dexdump of the API-21 class lists
    only the CAS / field-offset / park set — `copyMemory`, `addressSize` and `getByte(long)` are absent
    too), which is what `BufferFactory.secure()` allocates every key schedule through; and
    `DatagramChannel.bind(SocketAddress)` does not exist before 24 either, which is what
    `UdpSocket.bind` calls. Both arrived with Android 7.0's OpenJDK-derived `core-oj`, and both land as
    `NoSuchMethodError` — nothing on our side routes around either. The two upstream defects behind
    them: buffer's `UnsafeAllocator.isSupported` probes only that the `theUnsafe` **field** is
    reachable, never that the **methods** exist (and its `catch (_: Exception)` could not have seen a
    `NoSuchMethodError` regardless), and socket's `UdpSocket.jvm.kt` uses the API-24 `bind` where
    `channel.socket().bind(...)` works everywhere.
  - *Dependency floor, 28 — the binding one.* `buffer-crypto-android` has declared
    `minSdkVersion="28"` in its published manifest since at least 6.22.0, and `webrtc-dtls` takes it as
    `api`. An Android app below 28 fails the manifest merge on it whatever we declare. **AGP does not
    propagate a dependency's floor into our modules**, which is precisely why this went unseen: on the
    API-21 leg `:webrtc-dtls:connectedAndroidDeviceTest` ran instead of being skipped, so nothing in
    our CI ever saw the merge that a consumer would perform. `consumer-smoke` cannot catch it either —
    it resolves K/N and JVM, never an Android app.
  - The emulator leg and minSdk move in lockstep: above the floor the leg stops proving it, below the
    floor it certifies a configuration no consumer can build.
- **mDNS silently receives nothing on Android**, and nothing here or in socket acquires a
  `WifiManager.MulticastLock` — without one the Wi-Fi driver filters inbound multicast not addressed to
  the device's own MAC, so queries go out and no response ever arrives. mDNS defaults *on* in
  `nativePeerConnection()`. Belongs in socket beside `bindMulticast` (`socket-udp`'s androidMain manifest
  already declares INTERNET, and `CHANGE_WIFI_MULTICAST_STATE` is `protectionLevel="normal"` — no user
  prompt). Note `socket-udp` does **not** depend on `network-monitor`, so the application `Context` is
  not reachable there either; that PR needs its own androidx.startup capture. An emulator cannot prove
  this half — it has no Wi-Fi driver. mDNS on tvOS/watchOS is unproven for a different reason: no test
  anywhere binds real multicast, so the entitlement those platforms require has never been exercised.
- **Media** (RTP/SRTP), which remains out of scope.

## Traps

Things that have cost real time here. Read before acting on a premise that sounds settled.

- **Stale premises are this codebase's recurring failure mode** — ten instances so far, each costing
  between a wrong comment and ~1000 wrong lines. When a comment explains why something *cannot* be done,
  check whether it still can't before building around it. One instance was **this file**, which is the
  worst place for one; correct this document as soon as the state it describes changes, and keep the
  correction itself in git history rather than here.
- **A capability is a property of the RUNTIME, not of the platform** — and the tenth instance above is
  this one, which shipped a non-functional platform. `EcdheKeyExchange.generate` `check()`ed that the
  *configured* curve was available, under a comment reading "browsers delegate; the engine never runs
  here". Android is a `Native` target where the engine is the whole story, and buffer-crypto reported
  X25519 `Unavailable` there at every API level (Conscrypt's `XDH` `KeyPairGenerator` refuses every
  `AlgorithmParameterSpec`). So every Android peer threw inside `DtlsEngine.start`, the throw unwound
  into the session pump, and the consumer saw `Dtls(HandshakeTimeout)` — **no data channel could
  establish on any Android device.** P-256 was available the whole time and already advertised. Fixed by
  choosing every group over `availableGroups`. Upstream buffer#343 (pinned via 6.28.1) restores X25519
  on **Android 14+ only** — API 28–33 genuinely lack it, so our half is load-bearing at every level the
  minSdk admits, and the two are complementary rather than one superseding the other.
- **A test that SKIPS an unavailable capability is blind to that capability being wrongly reported.**
  This is why the above shipped: buffer-crypto's `KeyAgreementTest` skips curves the target calls
  unavailable, so its entire X25519 suite passed on Android by never running. Assert the *agreement
  between the probe and the provider*, not just the happy path.
- **Gating a fixture on a capability is the safe half; silent degeneration is the dangerous half.**
  `Dtls13HelloRetryRequestTest` did not fail on a one-group runtime — the server fell back to the
  client's group, no HelloRetryRequest was ever sent, both peers established, and every assertion still
  passed. A green test named for a path it no longer exercises is worse than a red one.
- **An Android *unit* test is a host-JVM test.** Nothing ran on ART until the emulator lane existed, and
  it found the above on its first run. `withDeviceTestBuilder { sourceSetTreeName = "test" }` is the
  load-bearing line — it grafts the device compilation onto `commonTest`; without it the lane builds an
  empty APK and passes. `androidDeviceTest` is also a `socketTest` leaf, which is the only way real UDP
  is exercised on Android.
- **A fix reaches a release as *content*, not as a commit.** Rebases, squashes and merge commits all
  detach a subject line from the sha that shipped it, so `git tag --contains <sha>` answers "was this
  object released", which is a different question. **Check the tree at the tag** (`git show v<x>:<file>`)
  before writing down that something is unreleased — and before building a workaround around the belief.
- **"The setting is in the file" is not evidence the process applied it.** coturn's `-n` means "do not
  use a configuration file", so `exec turnserver -c "$CONF" -n` ran an **open relay** for months while
  `lt-cred-mech`, `user`, `realm` and the port range sat inert. It survived review because stock
  `coturn/coturn:4.6`'s own entrypoint re-expands args with `eval "echo $i"`, where `echo -n` prints
  nothing — so every `docker run … -c cfg -n` example online *does* read the config while our direct
  `exec` did not. The tell was in the data: `harness.env` pins `TURN_MIN_PORT=49160`/`MAX=49200` and
  green runs handed out ports in coturn's *default* 49152–65535 range. **A configured value that never
  shows up in the output is evidence the config is not being read**, and checking the allocated port
  range is now the cheapest regression check there is.
- **Read the dependency's own startup log, and reach for its own client before suspecting ours.** A bare
  `external-ip` is accepted ONCE and then applied to every family: coturn kept the first (v4), logged
  `ERROR: You cannot define external IP more than once`, and reported every **IPv6** allocation at the
  **v4** address, so every permission drew `443: Peer Address Family Mismatch`. The error sat in the
  startup log 40 lines above the failure — unreadable only because the log never left the container.
  Our stack was not wrong anywhere, which `turnutils_uclient -x` confirmed by failing identically.
- **`send` does not consume.** socket's datagram channels transmit the window `[position, limit)` without
  advancing it, on **all four** backends — io_uring reads `nativeAddress + position()`, the NIO and Node
  paths take their own internal `slice()`, Apple reads `position()`/`remaining()` directly. So re-sending
  one encoded request across retransmissions is correct. Defending against a hazard socket does not have
  is not free: `PooledBuffer.slice()` takes a **reference**, so a slice per retransmission that nobody
  releases pins the chunk for good. Slice when something else needs a second live view — not to survive a
  send.
- **A slice is safe to release on a pool and unsafe to hold on a bare `deterministic()`, and the reverse
  for its parent.** `NativeBufferSlice.freeNativeMemory()` is a no-op and every read `checkOpen()`s the
  parent, so freeing a parent while a slice is live is a use-after-free there while a pool's refcount
  hides it. **Both regimes have to be right**, and a fixture that only runs on one will not tell you.
- **`linkTopology()` erases the reachability verdict on purpose.** socket's `NetworkState` ladder carries
  `Routable(id, Pending|Confirmed)`, and on real hardware Android grants `INTERNET` ~1s before
  `VALIDATED` on *every* reassociation. Forwarding that transition as an interface change would
  re-enumerate on a link whose addresses never moved, so the trigger projects the verdict away and keeps
  everything else. `LinkTopologyTest` pins both halves.
- **`InterfaceSnapshot` is sealed for one specific reason:** a failed `getifaddrs` reported as an *empty*
  interface set reads to `pathRidesOneOf` as "the selected pair's interface is gone", which would restart
  a healthy session on every probe failure. A failure is `Unavailable(reason)`, never an empty
  `Enumerated`.
- **A side effect placed after `emit` does not run for the two most common ways a flow is read.**
  `first()` and `take(n)` terminate a flow *through* `emit` — by throwing an internal cancellation from
  inside it — so `emit(x); credit(x)` silently never credits for either. This cost real time in the
  receive-window seam, where the symptom is not an exception but a window that shrinks by one message per
  read and a peer that eventually stalls while behaving correctly. Anything owed after a value is handed
  out belongs in a `finally` around the `emit`, not after it.
- **A fixture that counts the entries in its own list is not a coverage gate.** `ZeroChecksumWireTest`
  asserted "every `SctpChunk` variant appears in this table" by counting distinct classes among the chunks
  it names — so adding `SctpChunk.Pad` left it **green** while the claim became false. Kotlin has no
  common-source enumeration of sealed subtypes to close that. The exhaustive `else`-free `when` is the
  real gate (a compile error the moment a variant is added); a table like that only checks the arm chosen
  is the intended one. Do not let the two be confused in a comment — that is how a green test starts lying.
- **A deterministic "flake" is usually a harness observation bug, not a stack bug.** A red lane whose peer
  logs show success has, more than once, been the harness reading `docker compose logs` twice or matching
  only RUNNING containers. The same applies to leak fixtures: a harness that slices without releasing, or
  measures before a cancelled coroutine's `finally` has had a dispatch, has invented a production leak
  three times.
- **`webrtc-ice`'s `socketMain` is the only place `socket-udp` may appear in production code**, and the
  cores must never depend on socket in `commonMain` (ARCHITECTURE §11.6). A binder that owns its socket
  forecloses sharing one demuxed UDP socket with QUIC-P2P.
- **socket core does not vendor a second BoringSSL.** It was true once, outlived its truth in four
  separate comments, and acting on it produced a hand-rolled implementation of something already
  published. `LinuxSockets`'s cinterop klib embeds only `liburing.a`, and socket and `buffer-crypto`
  resolve to the *same* `boringssl-canonical`, which Gradle dedupes.

## Standing directives

Non-negotiable. The first two are enforced by CI (`.github/workflows/standing-directives.yaml`); all are
checked in the adversarial review gate.

1. **No `ByteArray` — and no primitive array of any kind** (`IntArray`, `LongArray`, `ShortArray`, …) in
   production (`*Main/`) source sets. A primitive array in a hot path is a guaranteed copy; this library
   exists to avoid that. Use `ReadBuffer` / `WriteBuffer` / `PlatformBuffer` and slice views. Genuine
   platform edges (an FFI call that demands a `ByteArray`) annotate the line
   `@Suppress("NoByteArrayInProd")` with a comment naming the specific API surface.
2. **No hardwired `Clock.System` / `Random.Default` / `Dispatchers.*` inside cores.** Every source of
   time, entropy and concurrency is a constructor-injected seam with a production default. This is what
   lets the whole stack run under `runTest` virtual time. A genuine production-default construction
   annotates the line `@Suppress("UnseamedEntropy")`.
3. **Errors are typed, never stringly.** Everything maps into the `SocketException` sealed hierarchy with
   exhaustive sealed reasons (`IceFailureReason.NoCandidatePairs`, `.ConsentExpired`, …). Strings are
   diagnostics, never discriminants.
4. **Assert observable state + a watchdog, never wall-clock budgets.**
5. **Every bug fix ships with its deterministic fixture in the same PR.** The corpus only grows.
6. **Buffers are factory-injected, pooled in hot paths, `use {}`/scoped lifecycle**, with a tracking
   factory in every test harness. The invariant is `assertPoolDrained` — every chunk back in the pool —
   not `assertNoLeaks`, which cannot see an unreleased borrow.
7. **The PR description states which platform lanes were runtime-validated vs compile-faithful** (the
   `V6_MAC_VALIDATION` convention: Apple/Android runtime-validated on runners).

## Type-safety house style (make illegal states unrepresentable)

The cores are state machines; the type system is the first line of correctness. See
[`DESIGN_PRINCIPLES.md`](./DESIGN_PRINCIPLES.md) for worked examples. In short:

- **Value classes wrap every identifier.** `TransactionId`, `Ufrag`, `StreamId`, `Tsn`, `DataChannelId`,
  `Mid`, `CertificateFingerprint` are each `@JvmInline value class` around their payload — zero runtime
  cost, but the compiler refuses to pass a `Ufrag` where an `IcePassword` is expected. IDs are never bare
  `String`/`Int`/`Long` at an API boundary.
- **Sealed hierarchies + exhaustive `when`, no `else`.** Message classes, connection states and failure
  reasons are sealed. A `when` over them compiles without an `else`; adding a case is a compile error at
  every call site until handled. Prefer this to enums when variants carry data.
- **No boolean or nullable soup.** Do not model a state as `connected: Boolean` + nullable
  `failureReason` (which can encode "connected AND failed"). Model it as a sealed `PeerConnectionState`
  where each state carries exactly the data valid in it — the illegal combinations are unrepresentable.
- **Nullability is a deliberate signal, not a default.** A nullable type means "genuinely absent"; never a
  stand-in for an error (that is a typed reason) or an uninitialized field (that is a different state in
  the sealed hierarchy). `nextDeadline(now): Instant?` returns null to mean "no timer armed" — one real
  meaning.
- **Parse failures are typed rejects, never throws-through or crashes** (T0 discipline).

## Build commands

```bash
./gradlew build                 # build all modules, all host-available targets
./gradlew allTests              # tests across every module + platform
./gradlew apiCheck              # binary-compatibility validation against checked-in .api files
./gradlew apiDump               # regenerate .api files after an intentional public-API change
./gradlew ktlintCheck           # lint  (ktlintFormat to auto-fix)
./gradlew detektAll             # multiplatform static analysis (non-blocking; sees Native/JS/WASM)
./gradlew publishToMavenLocal   # publish to ~/.m2  (runs prePublishCheck first)
./gradlew :webrtc-stun:jvmTest --tests "com.ditchoom.webrtc.stun.StunTest"
```

Requires **JDK 21** (enforced via toolchain). Apple targets build on macOS only.

## Build logic — the convention plugin (no copy-paste)

All per-module build configuration lives in **one** convention plugin,
`build-logic/src/main/kotlin/webrtc.multiplatform-library.gradle.kts`. It owns the KMP target matrix, the
JDK-21 toolchain, Android, ktlint, dokka, kover, binary-compatibility validation, Maven Central
publishing, signing and version derivation. A module's own `build.gradle.kts` therefore contains **only
its dependencies**:

```kotlin
plugins { id("webrtc.multiplatform-library") }
kotlin { sourceSets { commonMain.dependencies { api(libs.buffer); api(libs.buffer.codec) } } }
```

Structural identity is derived from the module name (artifactId, JS module name `<name>-kt`, Android
namespace `com.ditchoom.<name-dots>`). Per-module POM prose lives in `<module>/gradle.properties`
(`POM_NAME`, `POM_DESCRIPTION`); shared POM/developer/license fields are in the root `gradle.properties`.
Plugin versions are declared once in `gradle/libs.versions.toml`.

To add a module: create the dir + `src/commonMain` + `src/commonTest`, add a `build.gradle.kts` (as
above) and a `gradle.properties`, and `include(":…")` it in `settings.gradle.kts`. Nothing else.

## CI/CD

- **The version is derived exactly ONCE per run**, by `compute-version.yaml`, and threaded into every
  lane as `-Pversion=` (the convention plugin's `computeNextVersion` is guarded on
  `version == "unspecified"`, so it never runs in CI; it remains the local/dev `-SNAPSHOT` path). It used
  to be derived per Gradle *invocation* — `computeNextVersion` reads Central's `<latest>` at
  configuration time, and build-linux made four invocations, build-apple another four on a different
  runner. **A value derived twice is two values**: in run 31504316359 build-linux computed 0.33.1, #172's
  release published 0.33.1 to Central ten seconds later, and that job's own `publishToMavenLocal` then
  published 0.33.2 — so `validate-artifacts`, handed the first derivation, reported "missing umbrella
  artifact" for all seven modules against a repo where all seven were present under the other number. On
  the release path the same skew is worse and quieter, because the tag, the GitHub release and the
  Central upload name all came from the FIRST derivation while the bundle carried a LATER one. It costs
  about **+3 minutes** end-to-end, and the reason is worth knowing before trying to optimize it away:
  the old `Compute version` step (133s Linux / 192s Apple) was not pure overhead — it was also the
  Gradle **warm-up**, compiling `build-logic`, configuring every project and starting the daemon that
  the next step then reused. Measured across the two runs, deleting it grew the following step by about
  as much as the step itself had cost (Linux 957s → 1105s, Apple 281s → 690s), so the prefix job's
  ~2m25s is genuinely additional rather than relocated. Cheaper is possible — a root-only task under
  `--configure-on-demand`, or re-implementing the bump in shell — but the shell route would recreate the
  two-derivations-disagree family of bug it exists to remove.
- **PR** (`review.yaml`): `standing-directives` greps + `compute-version` → `build-linux` + `build-apple` →
  `validate-artifacts` → `consumer-smoke` (`.ci/consumer-smoke`, a standalone build resolving
  `com.ditchoom:webrtc` + `webrtc-testsuite` by coordinate; compiles, K/N-links, and runs
  `withWebRtcHarness { natType(); relayOnly(); impaired() }` against a **cold** resolve — throwaway
  `GRADLE_USER_HOME`, no build cache).
- **Release** (`merged.yaml`): version bump controlled by PR labels (`major` / `minor`, else patch;
  `skip-release` / `draft-release` change the flow) → `compute-version` (the label's bump is consumed
  *here* and nowhere after: from this job on, the version is a literal) → build → validate →
  `consumer-smoke` (maven-local,
  both hosts — `publish` needs it, so a consumer-breaking release never reaches Central) →
  `publish-to-central` → finalize (tag + GitHub release). `release.yaml` completes/cancels a draft.
- **What proves the publish is `consumer-smoke-central`, a job inside `merged.yaml`** — it resolves the
  just-pushed version from Maven Central and nothing else (no `mavenLocal()` fallback), both hosts, cold.
  **Not `released.yaml`**, which hangs off a tag *push* and therefore never fires: the tag is created
  through the REST API with `secrets.GITHUB_TOKEN`, for which GitHub dispatches no workflow events. An
  empty run list there is **expected and not a broken gate**; reading it as one costs an investigation.
- **Merging three PRs in quick succession silently drops the middle one's release.** `merged.yaml` is
  `concurrency: {group: deploy, cancel-in-progress: false}`, which keeps at most one *pending* run per
  group: the first runs, the second queues, the third's arrival supersedes it. The second's commit is
  still on `main`, so it normally rides out in the next release — **unless that next PR is docs-only**,
  because the `Check if release is needed` gate correctly skips a change touching only `*.md` /
  `.github/*` and every downstream job with it. That pair is how #160 ended up merged and unreleased.
  The tree at the tag is the only answer to "did this ship" (`git log --oneline -1 v<latest>` against
  `main`); a green run list is not. Recovery is built in and needs no sham PR — `merged.yaml`'s
  `workflow_dispatch` path takes the bump directly and builds from `main`:
  `gh workflow run merged.yaml -f version-bump=minor -f flow=release`.
- Version is auto-derived from Maven Central metadata + the label bump.
- Every published artifact (including `webrtc-testsuite`) goes through `validate-artifacts` from its
  first release.

## Source docs in sibling repos to consult

`socket`: `RFC_DETERMINISTIC_SIMULATION.md`, `TESTING_STRATEGY.md`, `RFC_UNIFIED_ESTABLISHMENT.md`,
`CLAUDE.md`. `buffer`: `CLAUDE.md`, `MODULE.md`, `ANDROID_ART_ALLOCATOR.md`. Sibling repos live at
`../git/buffer` and `../git/socket`.

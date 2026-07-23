# IPv6 / dual-stack ICE — design note (Phase 1.5-A)

**Status:** design complete, verified against buffer-flow/`socket`/webrtc-stun. Implementation pending.
**Branch:** `ipv6-dual-stack-ice`. **Scope:** one focused PR, webrtc-stun (keystone) + webrtc-ice.

## The one-paragraph truth

The entire IPv6 gap is a **text/address-bridge problem plus one priority seam** — the sans-io ICE core,
the STUN wire codec, and buffer-flow's `SocketAddress` are all already v6-ready (verified below). The
core already pairs v6↔v6 and refuses cross-family (`IceAgent.sameFamily`, `IceAgent.kt:656`); the STUN
codec already encodes/decodes V6 XOR addresses (RFC 5769 v6 vector passes); `SocketAddress.ofLiteral`
already parses bare v6 (compressed `::`, embedded-v4 tail) and exposes `family: AddressFamily`. What's
missing lives entirely at the **webrtc-ice text/address boundary** and one **priority default**.

## Verified foundation (not assumed)

- `buffer-flow/…/SocketAddress.kt` — `AddressFamily` enum (L5), `SocketAddress.family` (L44), `ofLiteral`
  routes v6 → `parseIpv6` (L164–168); tests `ofLiteralParsesIpv6`, `…FullAndCompressedIpv6Equal`,
  `…EmbeddedV4Ipv6` pass. **Trap:** `LiteralSocketAddress.toString()` wraps v6 in `[host]:port` (L149) —
  so wire/candidate rendering must use `IpAddress.V6.toString()` (bare), never the SocketAddress form.
- webrtc-stun — `StunAttribute.kt:141-159` / `StunAttributeDecoders.kt:42-47` fully handle V6 XOR
  addresses; RFC 5769 v6 vector green. `IpAddress.V6` exists (`hi:ULong,lo:ULong`) but has **no**
  `toString()` and **no** literal parser (the only real gap in stun). `V6.Companion` is empty (verified
  in `webrtc-stun.api`), so `parse()` is the sole new public symbol in the whole PR.
- webrtc-ice core — `sameFamily`/`compatible` already correct; only ever exercised on v4 fixtures today.

## The five changes

### 1. KEYSTONE — `webrtc-stun/…/TransportAddress.kt` (land first, everything calls it)
- `IpAddress.V6.toString()` → canonical **RFC 5952** (lowercase, leading-zeros suppressed, leftmost-longest
  ≥2-zero run compressed to `::`, a *lone* zero hextet **not** compressed, **unbracketed**), via ULong
  shifts only.
- `IpAddress.V6.Companion.parse(literal): IpAddress.V6?` — array-free two-ULong hex parser: strip `%zone`,
  reject brackets, single `::` split + gap-fill, accept embedded-v4 tail (`::ffff:1.2.3.4`), typed `null`
  on malformed (never throw). **Directive #1:** accumulate into two `ULong`s by shifts — no `ByteArray`
  (buffer-flow's own `parseIpv6` returns a `ByteArray` and cannot be reused).

### 2. `webrtc-ice/…/IceAddress.kt` (internal — no apiDump)
- `toTransportAddress()` → exhaustive `when (family)`: IPv4 keeps the dotted-quad fold; IPv6 →
  `IpAddress.V6.parse(host)`. `toSocketAddress()` V6 arm: `error(…)` → `SocketAddress.ofLiteral(addr.toString(), port)`.
- Un-fencing these two internal converters gives **TURN v6** (XOR-PEER/RELAYED) and the whole server
  plane for free — every gather/send/inbound path funnels through them.

### 3. `webrtc-ice/…/IceCandidateLine.kt` (public object, signatures unchanged — no apiDump)
- `transportAddress(ip, port)`: `if (ip.contains(':'))` → `IpAddress.V6.parse(ip)` (feeds **both** the main
  addr token and the `raddr` tail); v4 branch unchanged. `format()` needs **no change** — `${a.ip}` renders
  canonical bare v6 for free via the keystone `toString()`. RFC 8839 §5.1 connection-address is **raw**
  (unbracketed) — add/strip no brackets.

### 4. `webrtc-ice/…/IceCandidate.kt` — priority seam (internal, injectable-ready — no apiDump)
- New **`internal fun interface CandidatePreferencePolicy { fun localPreference(ip, interfaceIndex): Int }`**
  with a `Default` implementing **RFC 6724 precedence** via pure ULong-shift classification: IPv6-GUA
  `2000::/3` → 40, IPv4 → 35, IPv6-ULA `fc00::/7` → 3, IPv6-LL `fe80::/10` → 1, other-v6 → 40. Value:
  `(familyPref shl 8) or (0xFF - (interfaceIndex and 0xFF))`.
- **Injectable-ready, not yet injected** (consumer decision, 2026-07-23): shaped as a `fun interface` so a
  future `IceConfig.candidatePreferencePolicy` can override candidate ordering (family / per-interface
  steering) in a one-line addition, but it stays **`internal`** this PR — no public surface, no apiDump.
  Browsers deliberately don't expose raw candidate priority. The driver uses `…Policy.Default`.
- **Per-interface preference — considered and wired, minimally** (consumer steer, 2026-07-23): the SAM's
  `interfaceIndex` is first-class (the low byte). The driver assigns a **per-family gather-ordinal** as the
  index (`gatherHost` is caller-clocked, once per local address), so every multi-homed host of the same
  family gets a **unique** `localPreference` (RFC 8445 §5.1.2.2 "SHOULD be unique per same-type candidate"),
  breaking same-family cross-interface ties deterministically (first-gathered wins). Pure commonMain (a
  small per-family counter in the driver) — **no** `NetworkMonitor.interfaces()` enumeration, no platform
  code, no public API. The richer *semantic* per-interface metric (cost/type via `NetworkMonitor`) is the
  documented follow-up the seam already fits. First v4 host still = 9215 (index 0), so existing fixtures
  are unaffected; a second same-family host = 9214 (strictly lower, unique).
- **`MAX_LOCAL_PREFERENCE` (65535) and the public `computePriority`/`host()` defaults stay untouched** — so
  `apiCheck` and the exact-value `IcePriorityTest` (host `2130706431L` via the 65535 default) stay green;
  the change is purely additive.

### 5. `webrtc-ice/…/IceAgentDriver.kt` — consume the seam at the three gather sites
- `gatherHost` (L141), srflx (L161), relay (L201): pass `localPreference = CandidatePreferencePolicy.Default
  .localPreference(<base>.ip, ifaceIndex)`. The driver references `CandidatePreferencePolicy.Default`
  **directly** (not via `IceConfig`) this PR — adding an `internal` field to the public `IceConfig` data
  class would tangle its generated `copy()`/`componentN()` for zero present benefit; the `IceConfig` field
  is the trivial future injection point. `ifaceIndex` comes from a private per-family gather-ordinal counter
  (`nextInterfaceIndex(family)`) — host+srflx share the index assigned once at the top of `gatherHost` (same
  socket/interface); `gatherRelay` binds its own socket and takes its own index.
- Without this the un-fenced converters produce v6 candidates priority-**tied** with v4 → the "v6 preferred"
  outcome becomes a coin-flip; and same-family multi-homed hosts would tie (violating §5.1.2.2 uniqueness).

## Priority decision (and the one deliberate deviation)

RFC 8445 §5.1.2.2 says `localPreference` SHOULD prefer IPv6, deferring family/scope ordering to RFC 8421
→ RFC 6724. We adopt the **RFC 6724 precedence** ordering (GUA > v4 > ULA > LL) rather than a naive
2-tier "all v6 > all v4" — because 2-tier would rank a **ULA-only** v6 host *above* v4, contradicting
RFC 6724 (ULA precedence 3 < v4 35) and happy-eyeballs.

**Documented deviation:** a v4-only single-address agent now gets driver-gathered `localPreference` 9215,
not the §5.1.2.2 SHOULD-65535. This is interop-safe: `localPreference` orders only an agent's *own*
same-type candidates and pair priority (§6.1.2.3) is role-symmetric. Relative ordering within v4 is
unchanged; single-interface fixtures have one host per type, so selected-pair mirroring is unaffected.

## API impact
**One** new public symbol, webrtc-stun only: `IpAddress$V6$Companion.parse(String): IpAddress$V6?`.
`V6.toString()` is a behavior override of the already-dumped data-class `toString()` — not a signature
change. `webrtc-ice`: **zero** public-API change by design. → `./gradlew :webrtc-stun:apiDump` (one new
line), `apiCheck` stays green on webrtc-ice as the guard that `localPreferenceFor` stayed internal.

## Deterministic test plan (corpus only grows — directive #5)

| Test | Module | Observable assertion |
|---|---|---|
| RFC 5952 render + array-free parse round-trip | webrtc-stun (new) | canonical render of RFC 5769 vector; `::1`, leading-zero suppression, lone-zero-not-compressed, embedded-v4, `%zone` strip; `::1::2`/`[::1]`/9-group → null |
| v6 SocketAddress bridge, no-throw | webrtc-ice (new `IceAddressV6Test`) | `ofLiteral(v6).toTransportAddress()` round-trips; `toSocketAddress().family==IPv6`; no bracket contamination |
| v6 host+srflx candidate lines round-trip + reject | `IceCandidateLineTest` (extend) | Host/ServerReflexive with v6 addr **and** v6 `raddr`; `format(parse(x))==x`; `::1::2` → null |
| localPreference GUA>v4>ULA>LL | `IcePriorityTest` (extend) | ordering asserts; host-of-either-family still outranks srflx (type dominates); exact-default test stays green |
| cross-family still `NoCandidatePairs` | `IceReviewRegressionTest` (reword only) | keep the reject green; only reword the "v6 unsupported"-sounding comment |
| **the FLIP** — v6-local pairs v6-remote → Connected | webrtc-ice (new `IceDualStackTest`) | non-empty checklist → Connected (not `NoCandidatePairs`), under a watchdog |
| host↔host over v6 vnet | `IceConnectivityTest` (extend) | both reach connected; selected pairs mirror |
| **dual-stack selects the v6 pair** | `IceConnectivityTest` (new) | each binds v4+v6 GUA host; `selectedPair.local.address.ip is IpAddress.V6` |
| v6 vnet echo accounting | `VnetDatagramSeamTest` (extend) | payload+peer match; `allocations==2` (family-independent copy path) |
| v6 NAT translation family-agnostic | `vnet/VnetNatTest` (extend) | ULA `fd00:a::/…` box: cone/symmetric/restricted parity; `owns()` over match + non-match |

## vnet substrate
`ofLiteral` needs **no** socket-side work for v6. `Topology.kt` gains v6-GUA server constants
(`2001:db8::/32` doc range), a v6-only meetup, and a **dual-stack** meetup (each agent binds v4 `10.0.0.x`
+ v6 `2001:db8:a::x`). NAT boxes use ULA `fd00:a::`/`fd00:b::` prefixes — `Nat.owns()` is textual
`startsWith`, so **every v6 fixture literal must use one canonical spelling** of a prefix. `StunServer`/
`TurnServer` need no change — they reflect/relay v6 automatically once the converters un-fence.

## Implementation order (single PR, strict dependency chain)
1. stun keystone (`V6.toString()` + `parse()`) + `TransportAddressV6TextTest`; `:webrtc-stun:apiDump`.
2. `VnetDatagramSeamTest` v6 echo (no production dependency — first-light seam gate).
3. Un-fence `IceAddress.kt` + `IceAddressV6Test`.
4. Un-fence `IceCandidateLine.transportAddress()` + extend `IceCandidateLineTest`.
5. `IceCandidate.localPreferenceFor` + wire the 3 `IceAgentDriver` gather sites + extend `IcePriorityTest`.
6. `Topology.kt`/vnet v6 substrate + `VnetNatTest` v6 case.
7. Flip + connectivity in lockstep: reword `IceReviewRegressionTest`, add `IceDualStackTest` + the two
   `IceConnectivityTest` v6/dual-stack sagas.
8. Gate: `apiDump`, `apiCheck`, `ktlintCheck --rerun-tasks`, `detektAll`, `allTests`, standing-directives grep.

## Risks (top)
- **Array-free v6 parser** (directive #1, CI-greped): the exact spot a `ByteArray`/`UShortArray` creeps in.
  Guard: zero `Array`/`ByteArray` tokens in `TransportAddress.kt` + the parse corpus.
- **Bracket/scope-id contamination**: if `V6.toString()` ever emits `[…]` or `%zone`, `ofLiteral` rejects it
  and every v6 send throws. Locked by the `ofLiteral(V6.toString())` round-trip.
- **RFC 5952 canonicalization** subtlety (leftmost-longest, lone-zero-not-compressed) → two spellings split
  local foundations. Pinned by exact-string asserts.
- **Link-local without zone id** can't pair cross-host (buffer-flow collapses `%zone` into an equality
  collision) — rank LL lowest, keep scope-ids out of fixtures; genuine scoping needs a buffer-flow SPI
  (out of scope, flag to the socket workstream).

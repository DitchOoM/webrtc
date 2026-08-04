# Performance

Throughput benchmarks for the hot paths, via kotlinx-benchmark in each module's shared
`src/commonBenchmark/kotlin` source set (the buffer pattern). Numbers are tracked here per platform
and regression-checked at release.

## Running

```bash
# One module, full run (main profile: 3 warmups, 5 iterations)
./gradlew :webrtc-stun:jvmBenchmarkBenchmark
./gradlew :webrtc-stun:linuxX64BenchmarkBenchmark      # Linux K/N, on a Linux host

# Fast validation pass (quick profile: 1 warmup, 2 iterations)
./gradlew :webrtc-stun:jvmBenchmarkQuickBenchmark
```

Benchmarks are on-demand — they are not part of `build` / `check`.

## Coverage

| Benchmark | Module | Status |
|---|---|---|
| STUN attribute decode + MESSAGE-INTEGRITY verify over a datagram slice | `webrtc-stun` | measured |
| SDP parse / encode | `webrtc-sdp` | measured |
| SCTP chunk decode / reassembly | `webrtc-sctp` | measured |
| SCTP association round trip (send → SACK → drain) | `webrtc-sctp` | measured |

## Results

### `webrtc-stun`

`StunBenchmark` over the RFC 5769 §2.2 IPv4 response (an 80-byte datagram: header + SOFTWARE +
XOR-MAPPED-ADDRESS + MESSAGE-INTEGRITY + FINGERPRINT):

| Benchmark | What it covers | JVM (quick) |
|---|---|---|
| `decode` | header decode + TLV walk (zero-copy views) + XOR-MAPPED-ADDRESS un-XOR | ~2.5M ops/s |
| `decodeAndVerify` | `decode` + FINGERPRINT (CRC-32) + MESSAGE-INTEGRITY (HMAC-SHA1) in place | ~0.42M ops/s |

Indicative only — `quick` profile (1 warmup, 2 iterations) on a dev workstation, not a release
baseline. The decode path is allocation-light (attribute values are slices over the datagram); the
verify path is dominated by the two message-spanning digests. Re-run with
`./gradlew :webrtc-stun:jvmBenchmarkBenchmark` for the `main` profile, and add the Linux K/N column
from `linuxX64BenchmarkBenchmark` at release.

### `webrtc-sdp`

`SdpBenchmark` over a realistic Chrome data-channel offer (a 16-line, ~430-byte document: session
block + BUNDLE + one `m=application … webrtc-datachannel` section with the ICE/DTLS/SCTP attributes):

| Benchmark | What it covers | JVM (quick) |
|---|---|---|
| `parse` | datagram → typed model: one UTF-8 decode + line walk + session/media split | ~1.5M ops/s |
| `parseAndReadFields` | `parse` + the typed reads a session layer runs per description (bundle, fingerprint, sctp-port, mid, setup) | ~0.53M ops/s |
| `encode` | typed model → datagram: serialize back to CRLF text bytes | ~0.70M ops/s |

Indicative only — `quick` profile (1 warmup, 2 iterations) on a dev workstation, not a release
baseline. SDP is a text codec: the datagram is decoded to a `CharSequence` exactly once and the line
walk produces value substrings, so `parse` is dominated by that single decode + the per-line
`substring`. The typed readers are on-demand `String` scans (no precompute), which is why
`parseAndReadFields` costs a further pass. Re-run with `./gradlew :webrtc-sdp:jvmBenchmarkBenchmark`
for the `main` profile, and add the Linux K/N column at release.

### `webrtc-sctp` (codec floor)

`SctpBenchmark` over a 44-byte INIT packet (common header + INIT chunk with Forward-TSN-Supported and
Supported-Extensions parameters):

| Benchmark | What it covers | JVM (quick) |
|---|---|---|
| `decode` | common-header decode + chunk TLV walk + INIT parameter sub-TLV walk (zero-copy views) | ~8.6M ops/s |
| `decodeAndVerify` | `decode` + CRC32c (Castagnoli) checksum over the whole packet, in place | ~5.7M ops/s |

Indicative only — `quick` profile (1 warmup, 2 iterations) on a dev workstation, not a release
baseline. The decode path is allocation-light (chunk values are slices over the datagram); the verify
path adds the table-driven CRC32c fold over the packet (word-batched input read, matching buffer's own
`crc32`). A native-accelerated CRC32c belongs upstream in buffer core (the `ReadBuffer.crc32`
precedent) if a hot bulk-checksum path ever appears. Re-run with
`./gradlew :webrtc-sctp:jvmBenchmarkBenchmark` for the `main` profile, and add the Linux K/N column at
release.

The same class also benchmarks the **association round trip** — one user message pushed through a pair
of established associations on a lossless, zero-latency link and driven until both sides are drained:
fragment + encode + CRC on the sender, decode + verify + reassemble on the receiver, SACK back,
cumulative-ack processing. The round trip is the unit deliberately: timing the send call alone flatters
any change that merely *defers* work past accept (a window-blocked sender queues chunks it has not
encoded yet), which is exactly the trap the directive-#6 measurement below had to avoid.

| Benchmark | What it covers | JVM (main) |
|---|---|---|
| `sendSmallMessageRoundTrip` | 1200-byte message — one DATA chunk, the data-channel common case | ~110K ops/s, ±50% |
| `sendFragmentedMessageRoundTrip` | 16 KiB message — 14 fragments, so fragmentation dominates | ~6K ops/s, ±50% |

**Those error bars are the harness, not the hardware, and they are not yet a usable baseline.** A round
trip allocates several buffers per op (the packet, the reassembly copy, the SACK), so at ~100K ops/s
this benchmark is partly measuring GC scheduling, and its per-iteration results are bimodal (86K–132K
within one 5-iteration run). The codec benchmarks above, running in the same JVMs interleaved with it,
hold ±1–5% — so the variance is specific to this workload's allocation churn. Treat the numbers as
order-of-magnitude only until the harness is conditioned (pooled buffers in the fixture, longer
iterations/more forks, or measuring allocation *bytes* instead of ops/s) and re-baselined on a quiet
machine.

Directive #6, send-path copy reduction: the retransmission queue must own bytes past `send()` (the
caller's payload is borrowed for one `handle` call), so **one** copy of the user data is architecturally
required — but there used to be two, because `fragment()` allocated and copied each fragment (even a
sub-MTU one) and the packet encoder then copied it again into the datagram. `fragment()` now emits
zero-copy views and the queue retains the *encoded wire packet*, so the encode **is** the owned copy and
a retransmit re-emits the same bytes (CRC included) instead of re-encoding. Paired A/B runs of this
benchmark put the new path ahead on both shapes, but the spread above is far too wide to publish a
percentage, so **the claim this change actually stands on is the allocation count**, asserted exactly
and on every platform by `BufferLifecycleTest.send_allocates_one_buffer_per_fragment`: one buffer per
fragment, previously two (mutation-checked — restoring the old `copyOf` fails it).

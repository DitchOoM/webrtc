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

## Planned coverage

| Benchmark | Module | Wave |
|---|---|---|
| STUN attribute decode + MESSAGE-INTEGRITY verify over a datagram slice | `webrtc-stun` | W1 |
| SDP parse | `webrtc-sdp` | W6 |
| SCTP chunk decode / reassembly | `webrtc-sctp` | W5 |
| RTP header parse, SRTP seal/open ops/sec | `webrtc-rtp` / `webrtc-srtp` | P2 |

## Results

### `webrtc-stun` (W1)

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

### `webrtc-sdp` (W6)

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

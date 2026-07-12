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

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

_No baselines yet — the current benchmark is a placeholder that validates the wiring. Real numbers
land with each module's codec._

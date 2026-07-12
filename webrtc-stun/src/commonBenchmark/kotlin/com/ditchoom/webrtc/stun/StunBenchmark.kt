package com.ditchoom.webrtc.stun

import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Scope
import kotlinx.benchmark.State

/**
 * Placeholder benchmark that exercises the shared `commonBenchmark` wiring end to end. Real
 * STUN parse-throughput benchmarks (RFC §7 — MESSAGE-INTEGRITY verify, attribute decode over a
 * datagram slice) land with the W1 codec and get tracked in PERFORMANCE.md.
 */
@State(Scope.Benchmark)
class StunBenchmark {
    // NB: a @Benchmark must NOT return an inline value class — Kotlin mangles the JVM method name
    // (transactionIdConstruction-HHWokXc) and JMH rejects it. Return the underlying value (or a
    // Blackhole-consumed result) instead. This still exercises the value class's construction + init.
    @Benchmark
    fun transactionIdConstruction(): String = TransactionId("0123456789abcdef01234567").hex
}

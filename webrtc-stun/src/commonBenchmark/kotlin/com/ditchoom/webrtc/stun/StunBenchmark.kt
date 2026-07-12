package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State

/**
 * STUN parse-throughput benchmarks (RFC §7 / PERFORMANCE.md) over the RFC 5769 §2.2 response — the
 * hot receive path: header decode + TLV walk + XOR-MAPPED-ADDRESS un-XOR, and the in-place
 * FINGERPRINT (CRC-32) / MESSAGE-INTEGRITY (HMAC-SHA1) verifications. Run:
 * `./gradlew :webrtc-stun:jvmBenchmarkBenchmark`.
 *
 * A `@Benchmark` must not return an inline value class (JMH mangles the method name); these return
 * plain scalars a Blackhole can consume.
 */
@State(Scope.Benchmark)
class StunBenchmark {
    private lateinit var datagram: PlatformBuffer
    private lateinit var key: PlatformBuffer

    private val ipv4Response =
        "0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000080001a1" +
            "47e112a643000800142b91f599fd9e90c38c7489f92af9ba53f06be7d780280004c07d4c96"

    @Setup
    fun setup() {
        datagram = bufferOfHex(ipv4Response)
        val password = "VOkJxbRl1RmTxUk/WvJxBt"
        key = BufferFactory.Default.allocate(password.length, ByteOrder.BIG_ENDIAN)
        key.writeString(password)
        key.resetForRead()
    }

    /** Header + attribute walk, returning the attribute count (Blackhole-consumed). */
    @Benchmark
    fun decode(): Int {
        datagram.position(0)
        return when (val r = StunMessage.decode(datagram)) {
            is StunDecodeResult.Success -> r.message.attributes.size
            is StunDecodeResult.Reject -> -1
        }
    }

    /** Decode + FINGERPRINT (CRC-32) + MESSAGE-INTEGRITY (HMAC-SHA1) verification. */
    @Benchmark
    fun decodeAndVerify(): Boolean {
        datagram.position(0)
        val msg = (StunMessage.decode(datagram) as StunDecodeResult.Success).message
        key.position(0)
        return msg.verifyFingerprint() && msg.verifyMessageIntegrity(key)
    }

    private fun bufferOfHex(hex: String): PlatformBuffer {
        val n = hex.length / 2
        val buf = BufferFactory.Default.allocate(n, ByteOrder.BIG_ENDIAN)
        for (i in 0 until n) buf.writeByte(hex.substring(i * 2, i * 2 + 2).toInt(16).toByte())
        buf.resetForRead()
        return buf
    }
}

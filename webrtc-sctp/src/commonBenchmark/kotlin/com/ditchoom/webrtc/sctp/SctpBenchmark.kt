package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.managed
import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State

/**
 * SCTP codec throughput benchmarks (RFC §7 / PERFORMANCE.md) over an INIT packet — the hot receive
 * path: common-header decode + chunk TLV walk + parameter sub-TLV walk, and the in-place CRC32c
 * verification (Castagnoli, the table-driven fold). Run:
 * `./gradlew :webrtc-sctp:jvmBenchmarkBenchmark`.
 *
 * A `@Benchmark` must not return an inline value class (JMH mangles the method name); these return
 * plain scalars a Blackhole can consume.
 */
@State(Scope.Benchmark)
class SctpBenchmark {
    private lateinit var initPacket: PlatformBuffer

    private val initHex =
        "13881388000000001d7a606e" +
            "01000020" + "11223344" + "00100000" + "04000400" + "aabbccdd" +
            "c0000004" + "80080005c0000000"

    @Setup
    fun setup() {
        initPacket = bufferOfHex(initHex)
    }

    /** Header + chunk walk, returning the chunk count (Blackhole-consumed). */
    @Benchmark
    fun decode(): Int {
        initPacket.position(0)
        return when (val r = SctpPacket.decode(initPacket)) {
            is SctpDecodeResult.Success -> r.packet.chunks.size
            is SctpDecodeResult.Reject -> -1
        }
    }

    /** Decode + CRC32c checksum verification (the Castagnoli fold over the whole packet). */
    @Benchmark
    fun decodeAndVerify(): Boolean {
        initPacket.position(0)
        val packet = (SctpPacket.decode(initPacket) as SctpDecodeResult.Success).packet
        return packet.verifyChecksum()
    }

    private fun bufferOfHex(hex: String): PlatformBuffer {
        val n = hex.length / 2
        val buf = BufferFactory.managed().allocate(n, ByteOrder.BIG_ENDIAN)
        for (i in 0 until n) buf.writeByte(hex.substring(i * 2, i * 2 + 2).toInt(16).toByte())
        buf.resetForRead()
        return buf
    }
}

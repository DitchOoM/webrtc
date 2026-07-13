package com.ditchoom.webrtc.sdp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State

/**
 * SDP parse/serialize throughput (RFC §7 / PERFORMANCE.md) over a realistic Chrome data-channel offer
 * — the hot signaling path: the single UTF-8 decode, the line walk, the session/media split, then the
 * typed field reads a session layer performs on every applied description. Run:
 * `./gradlew :webrtc-sdp:jvmBenchmarkBenchmark`.
 *
 * A `@Benchmark` must not return an inline value class (JMH mangles the method name); these return
 * plain scalars a Blackhole can consume.
 */
@State(Scope.Benchmark)
class SdpBenchmark {
    private lateinit var datagram: PlatformBuffer
    private lateinit var parsed: SessionDescription

    private val offer: String =
        listOf(
            "v=0",
            "o=- 4611731400430051336 2 IN IP4 127.0.0.1",
            "s=-",
            "t=0 0",
            "a=group:BUNDLE 0",
            "a=msid-semantic: WMS",
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
            "c=IN IP4 0.0.0.0",
            "a=ice-ufrag:4ZcD",
            "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlB5",
            "a=ice-options:trickle",
            "a=fingerprint:sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:3B:8B:8A:1B:12:1C:AA:E9:2F:6A:0A:5F",
            "a=setup:actpass",
            "a=mid:0",
            "a=sctp-port:5000",
            "a=max-message-size:262144",
        ).joinToString("\r\n", postfix = "\r\n")

    @Setup
    fun setup() {
        val n = offer.encodeToByteArray().size
        datagram =
            BufferFactory.Default.allocate(n, ByteOrder.BIG_ENDIAN).apply {
                writeString(offer, Charset.UTF8)
                resetForRead()
                setLimit(n)
            }
        parsed = (SessionDescription.parse(datagram) as SdpParseResult.Success).description
    }

    /** Datagram → typed model: UTF-8 decode + line walk + session/media split (Blackhole-consumed count). */
    @Benchmark
    fun parse(): Int {
        datagram.position(0)
        return when (val r = SessionDescription.parse(datagram)) {
            is SdpParseResult.Success -> r.description.mediaDescriptions.size
            is SdpParseResult.Reject -> -1
        }
    }

    /** parse + the typed field reads a session layer runs on every applied description. */
    @Benchmark
    fun parseAndReadFields(): Int {
        datagram.position(0)
        val sdp = (SessionDescription.parse(datagram) as SdpParseResult.Success).description
        val m = sdp.mediaDescriptions[0]
        var acc = sdp.bundleGroups().size + m.fingerprints().size
        acc += (m.sctpPort() ?: 0) + (m.mid()?.value?.length ?: 0)
        if (m.setup() != null) acc++
        return acc
    }

    /** Typed model → datagram: serialize the parsed offer back to CRLF text bytes. */
    @Benchmark
    fun encode(): Int = parsed.encode().remaining()
}

package com.ditchoom.webrtc.sctp.fuzz

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.SctpDecodeResult
import com.ditchoom.webrtc.sctp.SctpPacket
import com.ditchoom.webrtc.sctp.asSupportedExtensions
import com.ditchoom.webrtc.sctp.dcep.DataChannelDecodeResult
import com.ditchoom.webrtc.sctp.dcep.DataChannelMessage

/**
 * Coverage-guided **Jazzer** fuzz target over the SCTP + DCEP decoders — the module's real adversarial
 * surface. The code under test is **pure Kotlin**, so Jazzer's JVM instrumentation gives genuine edge
 * coverage of the common-header decode, the chunk TLV walk, the parameter/error-cause sub-TLV walks,
 * the in-place CRC32c, and the DCEP field parse.
 *
 * **Invariant** (T0): [SctpPacket.decode] and [DataChannelMessage.decode] are **total** — for *any*
 * input they return a `Success` or a `Reject`, never a throw. And everything reachable on a decoded
 * value — re-encode, checksum verification, every typed accessor — must also not throw on hostile
 * content. So this target wraps nothing in a `try`: ANY `Throwable` (buffer underflow, IOOBE, NPE,
 * `IllegalArgumentException`, OOM, hang) bubbles out and Jazzer records a `crash-*` repro. This is the
 * dynamic counterpart to the seeded `SctpMalformedCorpusTest` totality property.
 *
 * Run it via the `sctpCodecFuzz` Gradle task. The target uses the `byte[]` entry-point form, so it has
 * no compile-time dependency on Jazzer. Intentionally not a `@Test`.
 */
object SctpCodecFuzzer {
    private const val INPUT_CAP = 4096
    private val factory = BufferFactory.managed()

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val len = if (data.size > INPUT_CAP) INPUT_CAP else data.size
        if (len == 0) return
        // The single byte[] → buffer conversion at the driver ABI boundary; everything below is buffers.
        val source =
            factory.allocate(len, ByteOrder.BIG_ENDIAN).apply {
                writeBytes(data, 0, len)
                resetForRead()
                setLimit(len)
            }

        when (val result = SctpPacket.decode(source)) {
            is SctpDecodeResult.Reject -> Unit // a typed reject is the correct outcome, not a finding
            is SctpDecodeResult.Success -> exercisePacket(result.packet)
        }

        // The same bytes are also a candidate DCEP message (the DATA-chunk payload surface).
        source.position(0)
        when (val dcep = DataChannelMessage.decode(source)) {
            is DataChannelDecodeResult.Reject -> Unit
            is DataChannelDecodeResult.Success -> exerciseDcep(dcep.message)
        }
    }

    private fun exercisePacket(packet: SctpPacket) {
        packet.encode() // re-serialization must not throw
        packet.verifyChecksum() // CRC32c over the decoded span
        for (chunk in packet.chunks) {
            when (chunk) {
                is SctpChunk.Init -> {
                    chunk.supportsForwardTsn()
                    chunk.parameters.forEach { it.asSupportedExtensions() }
                }
                is SctpChunk.InitAck -> chunk.stateCookie()
                is SctpChunk.Data -> drain(chunk.userData)
                is SctpChunk.CookieEcho -> drain(chunk.cookie)
                is SctpChunk.Abort -> chunk.causes.forEach { drain(it.value) }
                is SctpChunk.Error -> chunk.causes.forEach { drain(it.value) }
                is SctpChunk.Unrecognized -> drain(chunk.value)
                else -> Unit
            }
        }
    }

    private fun exerciseDcep(message: DataChannelMessage) {
        when (message) {
            is DataChannelMessage.Open -> {
                message.encode()
                message.channelType.reliability
                message.channelType.ordered
            }
            DataChannelMessage.Ack -> message.encode()
        }
    }

    // Touch a value view end-to-end so any slice/offset bug on a malformed length surfaces.
    private fun drain(view: com.ditchoom.buffer.ReadBuffer) {
        var i = view.position()
        val n = view.limit()
        while (i < n) {
            view.get(i)
            i++
        }
    }
}

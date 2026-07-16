package com.ditchoom.webrtc.sctp.fuzz

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.SctpDecodeResult
import com.ditchoom.webrtc.sctp.SctpPacket
import com.ditchoom.webrtc.sctp.SctpPacketBuilder
import com.ditchoom.webrtc.sctp.VerificationTag
import com.ditchoom.webrtc.sctp.asSupportedExtensions
import com.ditchoom.webrtc.sctp.association.SctpAssociation
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.association.SctpEvent
import com.ditchoom.webrtc.sctp.dcep.DataChannelDecodeResult
import com.ditchoom.webrtc.sctp.dcep.DataChannelMessage
import kotlin.random.Random
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

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
@OptIn(ExperimentalTime::class)
object SctpCodecFuzzer {
    private const val INPUT_CAP = 4096
    private val factory = BufferFactory.managed()
    private val fuzzEpoch = Instant.fromEpochSeconds(0)

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

        // T0 totality at the ASSOCIATION layer: feeding hostile bytes to handle(DatagramReceived) must
        // never throw, in any state. Fed to a fresh (Closed) machine and one mid-handshake (CookieWait).
        exerciseAssociation(source)
    }

    private fun exerciseAssociation(source: com.ditchoom.buffer.ReadBuffer) {
        // 1. Raw bytes to a fresh + a mid-handshake machine — the decode-reject / bad-CRC drop paths.
        val rawClosed = SctpAssociation(SctpConfig(), Random(1))
        source.position(0)
        rawClosed.handle(SctpEvent.DatagramReceived(source.slice()), fuzzEpoch)

        // 2. If the bytes are structurally a packet, RE-STAMP them with a valid CRC32c and a matching
        // verification tag and feed those — otherwise the checksum/tag gates in onDatagram reject virtually
        // every undirected input before the chunk state machine runs, and the association-layer handlers
        // (onInit/onInitAck/onCookieEcho/onData/onSack/onForwardTsn/onShutdown) get zero coverage. This is
        // what makes the "totality at the association layer" claim actually tested (review finding R5-1).
        source.position(0)
        val packet = (SctpPacket.decode(source.slice()) as? SctpDecodeResult.Success)?.packet ?: return

        val closed = SctpAssociation(SctpConfig(), Random(3))
        feedRestamped(closed, packet, VerificationTag(0u)) // pre-TCB: INIT (tag 0) + local-tag-0 acceptance

        val handshaking = SctpAssociation(SctpConfig(), Random(4))
        handshaking.handle(SctpEvent.Associate, fuzzEpoch)
        feedRestamped(handshaking, packet, handshaking.localVerificationTag) // CookieWait: pass the tag gate
    }

    // Rebuild [packet]'s chunks under a header carrying [tag] (or 0 when the first chunk is INIT, per the
    // tag rule) with a freshly computed valid checksum, and drive it into [assoc].
    private fun feedRestamped(
        assoc: SctpAssociation,
        packet: SctpPacket,
        tag: VerificationTag,
    ) {
        val headerTag = if (packet.chunks.firstOrNull() is SctpChunk.Init) VerificationTag(0u) else tag
        val builder = SctpPacketBuilder(packet.sourcePort, packet.destinationPort, headerTag)
        for (chunk in packet.chunks) builder.add(chunk)
        val encoded = builder.encode(factory)
        encoded.position(0)
        assoc.handle(SctpEvent.DatagramReceived(encoded.slice()), fuzzEpoch)
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

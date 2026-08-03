package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.association.SctpAssociation
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.association.SctpEvent
import com.ditchoom.webrtc.sctp.association.SctpOutput
import com.ditchoom.webrtc.sctp.association.SctpSendOptions
import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
import kotlin.random.Random
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * SCTP codec throughput benchmarks (ARCHITECTURE §7 / PERFORMANCE.md) over an INIT packet — the hot receive
 * path: common-header decode + chunk TLV walk + parameter sub-TLV walk, and the in-place CRC32c
 * verification (Castagnoli, the table-driven fold). Run:
 * `./gradlew :webrtc-sctp:jvmBenchmarkBenchmark`.
 *
 * A `@Benchmark` must not return an inline value class (JMH mangles the method name); these return
 * plain scalars a Blackhole can consume.
 */
@OptIn(ExperimentalTime::class)
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

    /**
     * One complete user message pushed through a pair of established associations on a lossless,
     * zero-latency link: fragment + encode on the sender, decode + CRC-verify + reassemble on the
     * receiver, SACK back, cumulative-ack processing on the sender — driven until both sides are drained,
     * so nothing is deferred out of the measurement.
     *
     * The **round trip** is the unit deliberately: the send path alone would flatter any change that
     * merely defers work past the accept call (a window-blocked sender queues chunks it has not encoded
     * yet). This is where directive #6's copy reduction shows — `fragment()` now hands out views over the
     * caller's payload and the one owned copy is the encode into the datagram, so a message of `n` bytes
     * is copied once on the send side instead of twice, and its CRC32c is computed once for the chunk's
     * whole lifetime rather than once per transmission.
     *
     * The payload is sub-MTU (one DATA chunk — the data-channel common case). The pair is re-established
     * every [SENDS_PER_ASSOCIATION] messages so congestion state does not drift arbitrarily far; the
     * handshake is amortized ~1/512 and does not move the number.
     *
     * **Not yet a baseline** (see PERFORMANCE.md): a round trip allocates several buffers per op, so this
     * measures GC scheduling as much as CPU and its per-iteration results are bimodal — ±50% where the
     * codec benchmarks in the same JVM hold ±1–5%. Conditioning it (pooled fixture buffers, longer
     * iterations/more forks, or measuring allocation bytes rather than ops/s) is the open follow-up.
     */
    @Benchmark
    fun sendSmallMessageRoundTrip(): Int = roundTrip(smallPayload)

    /** As [sendSmallMessageRoundTrip] but a 16 KiB message — 14 fragments, so fragmentation dominates. */
    @Benchmark
    fun sendFragmentedMessageRoundTrip(): Int = roundTrip(largePayload)

    // ── send-path fixture ──

    private val epoch = Instant.fromEpochSeconds(0)
    private val sendConfig = SctpConfig()
    private val sendOptions = SctpSendOptions(StreamId(0), PayloadProtocolId.WebRtcBinary)
    private lateinit var smallPayload: PlatformBuffer
    private lateinit var largePayload: PlatformBuffer
    private lateinit var sender: SctpAssociation
    private lateinit var receiver: SctpAssociation
    private var sendsThisAssociation = 0
    private var now: Instant = Instant.fromEpochSeconds(0)
    private var delivered = 0

    @Setup
    fun setupSendPath() {
        smallPayload = bufferOfSize(sendConfig.maxPayloadBytes)
        largePayload = bufferOfSize(16 * 1024)
        establish()
    }

    private fun roundTrip(message: PlatformBuffer): Int {
        if (sendsThisAssociation >= SENDS_PER_ASSOCIATION) establish()
        sendsThisAssociation++
        delivered = 0
        message.position(0)
        pump(fromSender = true, outputs = sender.handle(SctpEvent.SendMessage(sendOptions, message), now))
        drainTimers()
        // Guards the premise rather than the result: if the drive loop ever stopped short of reassembling
        // the whole message, the benchmark would silently be timing a partial round trip.
        check(delivered == 1) { "round trip did not complete: delivered=$delivered" }
        return delivered
    }

    // The four-way handshake is entirely event-driven (no timers), so pumping each side's outputs into
    // the other until quiescent completes it.
    private fun establish() {
        sender = SctpAssociation(sendConfig, Random(1))
        receiver = SctpAssociation(sendConfig, Random(2))
        sendsThisAssociation = 0
        pump(fromSender = true, outputs = sender.handle(SctpEvent.Associate, now))
    }

    // Advance virtual time to each armed deadline in turn until neither side has a timer — the delayed
    // SACK flushes, the sender's window reopens, and any remaining fragments go out. `nextDeadline` being
    // null on both sides is exactly "nothing outstanding, nothing pending" (ARCHITECTURE §5.1).
    private fun drainTimers() {
        var steps = 0
        while (steps++ < MAX_DRAIN_STEPS) {
            val senderDeadline = sender.nextDeadline(now)
            val receiverDeadline = receiver.nextDeadline(now)
            val next = listOfNotNull(senderDeadline, receiverDeadline).minOrNull() ?: return
            if (next > now) now = next
            if (senderDeadline != null && senderDeadline <= now) pump(true, sender.handle(SctpEvent.TimerFired, now))
            if (receiverDeadline != null && receiverDeadline <= now) pump(false, receiver.handle(SctpEvent.TimerFired, now))
        }
    }

    private fun pump(
        fromSender: Boolean,
        outputs: List<SctpOutput>,
    ) {
        for (output in outputs) {
            when (output) {
                is SctpOutput.Transmit -> {
                    output.packet.position(0)
                    val peer = if (fromSender) receiver else sender
                    pump(!fromSender, peer.handle(SctpEvent.DatagramReceived(output.packet.slice()), now))
                }
                is SctpOutput.MessageReceived -> delivered++
                else -> Unit
            }
        }
    }

    private fun bufferOfSize(n: Int): PlatformBuffer {
        val buf = BufferFactory.managed().allocate(n, ByteOrder.BIG_ENDIAN)
        for (i in 0 until n) buf.writeByte((i and 0xFF).toByte())
        buf.resetForRead()
        return buf
    }

    private companion object {
        private const val SENDS_PER_ASSOCIATION = 512
        private const val MAX_DRAIN_STEPS = 1024
    }

    private fun bufferOfHex(hex: String): PlatformBuffer {
        val n = hex.length / 2
        val buf = BufferFactory.managed().allocate(n, ByteOrder.BIG_ENDIAN)
        for (i in 0 until n) buf.writeByte(hex.substring(i * 2, i * 2 + 2).toInt(16).toByte())
        buf.resetForRead()
        return buf
    }
}

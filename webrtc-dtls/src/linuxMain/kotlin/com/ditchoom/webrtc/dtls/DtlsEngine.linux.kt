package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.NativeBuffer
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.nativeMemoryAccess
import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_do_handshake
import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_feed
import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_free
import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_handle_timeout
import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_local_fingerprint
import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_new
import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_peer_fingerprint
import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_pending
import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_read_app
import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_shutdown
import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_take
import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_timeout_us
import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_version_negotiated
import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_write_app
import kotlinx.cinterop.CArrayPointer
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.toCPointer

// Return codes — mirror the #defines in boringsslssl.def. Byte-count wrappers (bd_read_app/bd_take)
// report "nothing available" as BD_NO_DATA (0) and errors as negatives, so a count can never be
// confused with a status; only bd_do_handshake uses the positive BD_WANT_READ.
private const val BD_OK = 0
private const val BD_NO_DATA = 0
private const val BD_FATAL = -1
private const val BD_CLOSED = -2

// Defensive bound on records drained from one pump. Correct code exits via BD_NO_DATA; this only
// stops a pathological spin from allocating without end (it OOM-killed the box once — never again).
private const val MAX_RECORDS_PER_PUMP = 1024

// BoringSSL protocol-version constants (ssl.h) for the negotiated-version readout.
private const val DTLS1_2_VERSION = 0xfefd
private const val DTLS1_3_VERSION = 0xfefc

// One native staging buffer per engine bridges the FFI edge: BoringSSL's memory BIOs read/write raw
// pointers, while the datagrams that flow through the stack are pooled heap buffers from the injected
// factory. 64 KiB comfortably holds any single DTLS flight (a self-signed P-256 cert is small).
private const val SCRATCH_SIZE = 1 shl 16

/**
 * Kotlin/Native BoringSSL DTLS backend (W4). Owns one `SSL` + memory-BIO pair through the `bd_*`
 * inline-C wrappers; caller-clocked via the injected `current_time_cb` (see boringsslssl.def). No
 * coroutine, no I/O, no wall-clock here — the driver supplies inbound records + a virtual `nowMicros`.
 */
@OptIn(ExperimentalForeignApi::class)
public actual class DtlsEngine actual constructor(
    role: DtlsRole,
    private val config: DtlsConfig,
) {
    private val engine =
        bd_new(if (role == DtlsRole.Client) 1 else 0, if (config.enableDtls13) 1 else 0)
            ?: throw DtlsException(
                DtlsFailureReason.Internal("bd_new failed — BoringSSL SSL_CTX/cert init"),
            )

    // Native FFI staging buffer (freed in close()), used ONLY as a fallback when a datagram is a
    // GC-heap buffer with no stable native address. Native buffers (a pooled native factory — the
    // production hot path, directive #6) pass their own address straight to BoringSSL, no staging.
    private val scratch = NativeBuffer.allocate(SCRATCH_SIZE, ByteOrder.BIG_ENDIAN)
    private val scratchPtr: CPointer<UByteVar> = scratch.nativeAddress.toCPointer()!!

    private var closed = false
    private var handshakeDone = false
    private var terminal: DtlsState? = null
    private var establishedState: DtlsState.Established? = null

    public actual val localFingerprint: CertificateFingerprint = memScoped {
        val out = allocArray<UByteVar>(32)
        val n = bd_local_fingerprint(engine, out)
        if (n != 32) throw DtlsException(DtlsFailureReason.Internal("local fingerprint digest failed"))
        CertificateFingerprint(hex(out, 32))
    }

    public actual fun start(nowMicros: Long): DtlsStep = pump(nowMicros)

    public actual fun onDatagram(
        record: ReadBuffer,
        nowMicros: Long,
    ): DtlsStep {
        terminal?.let { return DtlsStep(emptyList(), emptyList(), it) }
        feed(record)
        return pump(nowMicros)
    }

    public actual fun onTimeout(nowMicros: Long): DtlsStep {
        terminal?.let { return DtlsStep(emptyList(), emptyList(), it) }
        bd_handle_timeout(engine, nowMicros)
        return pump(nowMicros)
    }

    public actual fun send(
        applicationData: ReadBuffer,
        nowMicros: Long,
    ): DtlsStep {
        terminal?.let { return DtlsStep(emptyList(), emptyList(), it) }
        val len = applicationData.limit() - applicationData.position()
        if (len <= 0) return DtlsStep(collectRecords(), emptyList(), stateNow())
        val r = bd_write_app(engine, inputPointer(applicationData), len, nowMicros)
        if (r < 0) return failWith(DtlsFailureReason.RecordLayerError)
        return DtlsStep(collectRecords(), emptyList(), stateNow())
    }

    public actual fun beginClose(nowMicros: Long): DtlsStep {
        if (closed || terminal is DtlsState.Closed) {
            return DtlsStep(emptyList(), emptyList(), DtlsState.Closed)
        }
        bd_shutdown(engine, nowMicros)
        val records = collectRecords()
        terminal = DtlsState.Closed
        return DtlsStep(records, emptyList(), DtlsState.Closed)
    }

    public actual fun nextTimeoutMicros(nowMicros: Long): Long? {
        if (terminal != null) return null
        val us = bd_timeout_us(engine, nowMicros)
        return if (us < 0) null else nowMicros + us
    }

    public actual fun close() {
        if (closed) return
        closed = true
        bd_free(engine)
        scratch.close()
    }

    // ── internals ────────────────────────────────────────────────────────────────────────────────

    /** Advance the handshake / drain application data, then collect outbound records + current state. */
    private fun pump(nowMicros: Long): DtlsStep {
        terminal?.let { return DtlsStep(emptyList(), emptyList(), it) }
        var appData: MutableList<ReadBuffer>? = null

        if (!handshakeDone) {
            when (bd_do_handshake(engine, nowMicros)) {
                BD_OK -> handshakeDone = true
                BD_FATAL -> return failWith(DtlsFailureReason.HandshakeFailure)
                else -> Unit // BD_WANT_READ: still handshaking
            }
        }

        if (handshakeDone) {
            var drained = 0
            while (drained++ < MAX_RECORDS_PER_PUMP) {
                // Probe into the scratch first: SSL_read needs a destination to report availability,
                // and allocating a pooled buffer per probe would churn one away on every empty poll.
                val n = bd_read_app(engine, scratchPtr, config.maxDatagramSize, nowMicros)
                if (n == BD_NO_DATA) break // nothing buffered — the common exit
                if (n == BD_CLOSED) {
                    terminal = DtlsState.Closed
                    return DtlsStep(collectRecords(), appData ?: emptyList(), DtlsState.Closed)
                }
                if (n < 0) break // BD_FATAL on the read path — surface via the record layer below
                (appData ?: mutableListOf<ReadBuffer>().also { appData = it }).add(copyOutOfScratch(n))
            }
        }

        return DtlsStep(collectRecords(), appData ?: emptyList(), stateNow())
    }

    private fun stateNow(): DtlsState {
        terminal?.let { return it }
        if (!handshakeDone) return DtlsState.Handshaking
        establishedState?.let { return it }
        val fp = readPeerFingerprint() ?: return failReasonState(DtlsFailureReason.PeerCertificateMissing)
        val version =
            when (bd_version_negotiated(engine)) {
                DTLS1_2_VERSION -> DtlsVersion.Dtls12
                DTLS1_3_VERSION -> DtlsVersion.Dtls13
                else -> DtlsVersion.Unknown
            }
        return DtlsState.Established(fp, version).also { establishedState = it }
    }

    private fun failWith(reason: DtlsFailureReason): DtlsStep =
        DtlsStep(emptyList(), emptyList(), failReasonState(reason))

    private fun failReasonState(reason: DtlsFailureReason): DtlsState.Failed =
        DtlsState.Failed(reason).also { terminal = it }

    private fun feed(record: ReadBuffer) {
        val len = record.limit() - record.position()
        if (len > 0) bd_feed(engine, inputPointer(record), len)
    }

    /**
     * A native pointer to [buf]'s readable region. Fast path: a native-backed buffer (e.g. a pooled
     * native factory) hands BoringSSL its own address directly — no copy. Slow path: a GC-heap buffer
     * (managed/Default) has no stable native address, so its bytes are staged into [scratch] first.
     */
    private fun inputPointer(buf: ReadBuffer): CPointer<UByteVar> {
        val access = buf.nativeMemoryAccess
        if (access != null) return (access.nativeAddress + buf.position()).toCPointer()!!
        val save = buf.position()
        scratch.resetForWrite()
        scratch.write(buf)
        buf.position(save) // don't disturb the caller's buffer
        return scratchPtr
    }

    /** Copy [n] bytes sitting in [scratch] out into a fresh buffer from the injected factory. */
    private fun copyOutOfScratch(n: Int): ReadBuffer = finish(config.bufferFactory.allocate(n), native = false, n = n)

    /**
     * Finalize an output buffer just filled with [n] bytes. Fast path (buffer is native): the bytes
     * were read straight into it — just frame [0, n). Slow path (heap): copy them out of [scratch].
     */
    private fun finish(
        out: PlatformBuffer,
        native: Boolean,
        n: Int,
    ): ReadBuffer {
        if (native) {
            out.position(0)
            out.setLimit(n)
        } else {
            scratch.position(0)
            scratch.setLimit(n)
            out.write(scratch)
            out.resetForRead()
        }
        return out
    }

    private fun collectRecords(): List<ReadBuffer> {
        var records: MutableList<ReadBuffer>? = null
        var drained = 0
        while (drained++ < MAX_RECORDS_PER_PUMP) {
            val pending = bd_pending(engine)
            if (pending <= 0) break
            val size = minOf(pending, SCRATCH_SIZE)
            val out = config.bufferFactory.allocate(size)
            val native = out.nativeMemoryAccess
            val n =
                if (native != null) {
                    bd_take(engine, native.nativeAddress.toCPointer()!!, size)
                } else {
                    bd_take(engine, scratchPtr, size)
                }
            if (n <= 0) break
            (records ?: mutableListOf<ReadBuffer>().also { records = it }).add(finish(out, native != null, n))
        }
        return records ?: emptyList()
    }

    private fun readPeerFingerprint(): CertificateFingerprint? =
        memScoped {
            val out = allocArray<UByteVar>(32)
            if (bd_peer_fingerprint(engine, out) != 32) return@memScoped null
            CertificateFingerprint(hex(out, 32))
        }
}

@OptIn(ExperimentalForeignApi::class)
private fun hex(
    bytes: CArrayPointer<UByteVar>,
    len: Int,
): String {
    val sb = StringBuilder(len * 2)
    val digits = "0123456789abcdef"
    for (i in 0 until len) {
        val b = bytes[i].toInt() and 0xFF
        sb.append(digits[b ushr 4])
        sb.append(digits[b and 0x0F])
    }
    return sb.toString()
}

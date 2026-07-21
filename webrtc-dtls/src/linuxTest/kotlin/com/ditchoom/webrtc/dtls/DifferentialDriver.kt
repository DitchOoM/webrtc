@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import kotlin.time.Duration.Companion.microseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The seam that lets one conductor drive our pure-Kotlin [DtlsEngine] and the BoringSSL oracle
 * ([BoringSslDtlsEngine]) interchangeably — the two classes present the same sans-io surface but are
 * unrelated types, so the differential tests talk to both through this common shape.
 */
internal interface DtlsEndpoint {
    val localFingerprint: CertificateFingerprint

    fun start(
        role: DtlsRole,
        now: Instant,
    ): DtlsStep

    fun onDatagram(
        record: ReadBuffer,
        now: Instant,
    ): DtlsStep

    fun onTimeout(now: Instant): DtlsStep

    fun send(
        data: ReadBuffer,
        now: Instant,
    ): DtlsStep

    fun nextDeadline(now: Instant): Instant?

    fun close()
}

/** Our production engine as an endpoint. */
internal fun DtlsEngine.endpoint(): DtlsEndpoint =
    object : DtlsEndpoint {
        override val localFingerprint get() = this@endpoint.localFingerprint

        override fun start(
            role: DtlsRole,
            now: Instant,
        ) = this@endpoint.start(role, now)

        override fun onDatagram(
            record: ReadBuffer,
            now: Instant,
        ) = this@endpoint.onDatagram(record, now)

        override fun onTimeout(now: Instant) = this@endpoint.onTimeout(now)

        override fun send(
            data: ReadBuffer,
            now: Instant,
        ) = this@endpoint.send(data, now)

        override fun nextDeadline(now: Instant) = this@endpoint.nextDeadline(now)

        override fun close() = this@endpoint.close()
    }

/** The BoringSSL oracle as an endpoint. */
internal fun BoringSslDtlsEngine.endpoint(): DtlsEndpoint =
    object : DtlsEndpoint {
        override val localFingerprint get() = this@endpoint.localFingerprint

        override fun start(
            role: DtlsRole,
            now: Instant,
        ) = this@endpoint.start(role, now)

        override fun onDatagram(
            record: ReadBuffer,
            now: Instant,
        ) = this@endpoint.onDatagram(record, now)

        override fun onTimeout(now: Instant) = this@endpoint.onTimeout(now)

        override fun send(
            data: ReadBuffer,
            now: Instant,
        ) = this@endpoint.send(data, now)

        override fun nextDeadline(now: Instant) = this@endpoint.nextDeadline(now)

        override fun close() = this@endpoint.close()
    }

/**
 * A deterministic synchronous two-endpoint conductor over a virtual clock — the same shuttle the
 * self-loopback used, but endpoint-typed so either side can be our engine or the oracle. It hands each
 * outbound datagram to the other side, and when both stall mid-handshake it advances virtual time to
 * the nearest armed DTLS timer and fires it — so a lost flight and its backoff recovery replay at zero
 * wall-clock. [now] is public so a test can seed junk / drop a flight and resume.
 */
internal class DtlsConductor {
    var now: Instant = Instant.fromEpochSeconds(0)

    /**
     * Shuttle records between [client] and [server] until both settle. [seed], if non-null, is fed to
     * the server as the opening flight (used by the retransmission test to inject a re-sent ClientHello)
     * instead of calling [start] on both; [junk] prepends a bogus datagram to each side's first flight
     * to prove malformed records are dropped, never wedge the handshake.
     */
    fun drive(
        client: DtlsEndpoint,
        server: DtlsEndpoint,
        seed: List<ReadBuffer>? = null,
        junk: Boolean = false,
    ): Pair<DtlsState, DtlsState> {
        val toServer = ArrayDeque<ReadBuffer>()
        val toClient = ArrayDeque<ReadBuffer>()

        var cState: DtlsState = DtlsState.Handshaking
        var sState: DtlsState = DtlsState.Handshaking
        if (seed != null) {
            toServer.addAll(seed)
        } else {
            cState = client.start(DtlsRole.Client, now).also { toServer.addAll(it.records) }.state
            sState = server.start(DtlsRole.Server, now).also { toClient.addAll(it.records) }.state
        }
        if (junk) {
            toServer.addFirst(junkDatagram())
            toClient.addFirst(junkDatagram())
        }

        var guard = 0
        while (guard++ < 500) {
            if (cState is DtlsState.Established && sState is DtlsState.Established) break
            if (cState is DtlsState.Failed || sState is DtlsState.Failed) break

            if (toServer.isNotEmpty()) {
                server.onDatagram(toServer.removeFirst(), now).let {
                    sState = it.state
                    toClient.addAll(it.records)
                }
            } else if (toClient.isNotEmpty()) {
                client.onDatagram(toClient.removeFirst(), now).let {
                    cState = it.state
                    toServer.addAll(it.records)
                }
            } else {
                val deadlines = listOfNotNull(client.nextDeadline(now), server.nextDeadline(now))
                if (deadlines.isEmpty()) break
                now = maxOf(now + 1.microseconds, deadlines.min())
                client.onTimeout(now).let {
                    cState = it.state
                    toServer.addAll(it.records)
                }
                server.onTimeout(now).let {
                    sState = it.state
                    toClient.addAll(it.records)
                }
            }
        }
        return cState to sState
    }

    private fun junkDatagram(): ReadBuffer = bytesOf(0xFF, 0xFE, 0xFD, 0x00, 0x01, 0x02, 0x03)
}

/** A managed (GC-heap) datagram of the given bytes. */
internal fun bytesOf(vararg values: Int): ReadBuffer {
    val buf = BufferFactory.managed().allocate(values.size, ByteOrder.BIG_ENDIAN)
    values.forEach { buf.writeByte(it.toByte()) }
    buf.resetForRead()
    return buf
}

/** Lowercase hex of a buffer's readable region (leaves the position where it started). */
internal fun hexOf(buf: ReadBuffer): String {
    val p = buf.position()
    val sb = StringBuilder()
    while (buf.remaining() > 0) {
        val b = buf.readByte().toInt() and 0xFF
        sb.append("0123456789abcdef"[b ushr 4])
        sb.append("0123456789abcdef"[b and 0x0F])
    }
    buf.position(p)
    return sb.toString()
}

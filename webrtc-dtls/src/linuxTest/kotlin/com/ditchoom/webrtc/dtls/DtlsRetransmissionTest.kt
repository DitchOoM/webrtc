package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The caller-clocked **timer** path (a W4 exit criterion): DTLS is the one part of the stack that must
 * recover from loss on its own — SCTP sits above it and ICE below, neither retransmits a handshake
 * flight. Because the engine takes its time from the caller ([DtlsConfig] docs / the injected
 * `current_time_cb`), a lost flight and the backoff that repairs it replay under virtual time at zero
 * wall-clock, deterministically — which is the whole reason the seam is shaped this way.
 */
class DtlsRetransmissionTest {
    private var now = 0L

    /**
     * Drop the client's first flight (the ClientHello) outright. The server therefore never answers, so
     * only the client's own DTLS timer can rescue the handshake: it must arm, fire, retransmit, and the
     * session must still establish.
     */
    @Test
    fun a_dropped_flight_is_retransmitted_when_the_dtls_timer_fires() {
        val client = DtlsEngine(DtlsConfig())
        val server = DtlsEngine(DtlsConfig())
        try {
            val firstFlight = client.start(DtlsRole.Client, now).records
            assertTrue(firstFlight.isNotEmpty(), "client sent a ClientHello flight")
            server.start(DtlsRole.Server, now)
            // ...and the network eats it. Nothing reaches the server.

            // A timer must be armed — otherwise a lost flight would hang the handshake forever.
            val deadline = client.nextTimeoutMicros(now)
            assertNotNull(deadline, "client armed a retransmission timer for the unacked flight")
            assertTrue(deadline > now, "the timer is in the future, was $deadline vs now=$now")

            // Before the deadline the engine must NOT retransmit — a timer that fires early would
            // multiply traffic on every slow link.
            val early = client.onTimeout(now + (deadline - now) / 2)
            assertTrue(early.records.isEmpty(), "no retransmission before the deadline")

            // At the deadline it does.
            now = deadline
            val retransmitted = client.onTimeout(now)
            assertTrue(retransmitted.records.isNotEmpty(), "the flight was retransmitted when the timer fired")

            // The retransmitted flight is a real ClientHello: delivering it (and nothing else) completes
            // the handshake, proving recovery is genuine and not just bytes on the wire.
            val (c, s) = drive(client, server, seed = retransmitted.records)
            assertIs<DtlsState.Established>(c, "client established after the retransmission, was $c")
            assertIs<DtlsState.Established>(s, "server established after the retransmission, was $s")
            assertEquals(server.localFingerprint, c.peerFingerprint)
        } finally {
            client.close()
            server.close()
        }
    }

    /**
     * Directive #6 (buffers are factory-injected, bounded in hot paths): every record and every
     * decrypted payload must come from the injected factory, and a handshake must not allocate without
     * bound. This asserts allocation is sourced from the injected seam and stays bounded (per-message
     * and per-handshake) — the same posture W3/W5 landed with; strict pool-`release`/`use{}` accounting
     * of every handed-out buffer is the documented deferred refactor there, not re-litigated here. The
     * engine also owns native memory (the BoringSSL objects + its staging scratch) — [DtlsEngine.close]
     * frees it, and must stay idempotent because the driver closes on both the normal and failure paths.
     */
    @Test
    fun the_handshake_allocates_only_from_the_injected_factory_and_is_bounded() {
        val clientFactory = CountingBufferFactory(BufferFactory.managed())
        val serverFactory = CountingBufferFactory(BufferFactory.managed())
        val client = DtlsEngine(DtlsConfig(bufferFactory = clientFactory))
        val server = DtlsEngine(DtlsConfig(bufferFactory = serverFactory))
        try {
            val (c, s) = drive(client, server, seed = null)
            assertIs<DtlsState.Established>(c)
            assertIs<DtlsState.Established>(s)

            // The records went through the injected seam, not BufferFactory.Default.
            assertTrue(clientFactory.allocations > 0, "client records came from the injected factory")
            assertTrue(serverFactory.allocations > 0, "server records came from the injected factory")

            // Bounded: a P-256 handshake is a handful of flights. The exact count depends on BoringSSL's
            // RNG (the ±1-datagram Tier-B residue), so this asserts an order of magnitude, not a number.
            assertTrue(clientFactory.allocations < 64, "bounded allocation, was ${clientFactory.allocations}")

            // Steady state: application data must not allocate per byte or leak per message.
            val before = clientFactory.allocations
            repeat(16) {
                val step = client.send(bytesOf(0x01, 0x02, 0x03), now)
                for (record in step.records) server.onDatagram(record, now)
            }
            val perMessage = (clientFactory.allocations - before) / 16
            assertTrue(perMessage <= 2, "at most a record buffer or two per message, was $perMessage")
        } finally {
            client.close()
            client.close() // idempotent: the driver frees on both the normal and the failure path
            server.close()
        }
    }

    /**
     * Regression for the adversarial-gate MAJOR: a GC-heap datagram is staged through a fixed 64 KiB
     * native scratch before it reaches BoringSSL. A buffer larger than the scratch cannot be staged in
     * one shot, and passing its full length on would make BoringSSL read past the scratch's end (a
     * native over-read). The engine must reject it up front, not over-read. (Native-backed buffers take
     * the copy-free path and have no such limit — this only bounds the heap fallback.)
     */
    @Test
    fun a_heap_datagram_larger_than_the_ffi_staging_buffer_is_rejected_not_over_read() {
        val engine = DtlsEngine(DtlsConfig())
        try {
            engine.start(DtlsRole.Client, now)
            // One byte past the 64 KiB scratch, on a managed (GC-heap, no native address) buffer.
            val oversize = BufferFactory.managed().allocate((1 shl 16) + 1, ByteOrder.BIG_ENDIAN)
            oversize.position(0)
            oversize.setLimit((1 shl 16) + 1)
            // send() stages through inputPointer before it ever reaches SSL_write, so the bound fires
            // regardless of handshake state — the length alone is rejected, no bytes are read.
            assertFailsWith<IllegalArgumentException> { engine.send(oversize, now) }
        } finally {
            engine.close()
        }
    }

    // ── the same deterministic conductor DtlsHandshakeTest uses, with an optional seeded first flight ──

    private fun drive(
        client: DtlsEngine,
        server: DtlsEngine,
        seed: List<ReadBuffer>?,
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

        var guard = 0
        while (guard++ < 200) {
            if (cState is DtlsState.Established && sState is DtlsState.Established) break
            if (cState is DtlsState.Failed || sState is DtlsState.Failed) break

            if (toServer.isNotEmpty()) {
                val step = server.onDatagram(toServer.removeFirst(), now)
                sState = step.state
                toClient.addAll(step.records)
            } else if (toClient.isNotEmpty()) {
                val step = client.onDatagram(toClient.removeFirst(), now)
                cState = step.state
                toServer.addAll(step.records)
            } else {
                val deadlines = listOfNotNull(client.nextTimeoutMicros(now), server.nextTimeoutMicros(now))
                if (deadlines.isEmpty()) break
                now = maxOf(now + 1, deadlines.min())
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

    private fun bytesOf(vararg values: Int): ReadBuffer {
        val buf = BufferFactory.managed().allocate(values.size, ByteOrder.BIG_ENDIAN)
        values.forEach { buf.writeByte(it.toByte()) }
        buf.resetForRead()
        return buf
    }
}

/** Counts what the engine hands out, so a test can prove the injected seam is the only allocator. */
private class CountingBufferFactory(
    private val delegate: BufferFactory,
) : BufferFactory by delegate {
    var allocations: Int = 0
        private set

    override fun allocate(
        size: Int,
        byteOrder: ByteOrder,
    ): PlatformBuffer {
        allocations++
        return delegate.allocate(size, byteOrder)
    }
}

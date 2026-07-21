@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.managed
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The caller-clocked **timer** path (a W4 exit criterion, carried into W4b): DTLS is the one part of the
 * stack that must recover from loss on its own — SCTP sits above it and ICE below, neither retransmits a
 * handshake flight. Because our pure-Kotlin engine takes its time from the caller, a lost flight and the
 * backoff that repairs it replay under virtual time at zero wall-clock, deterministically. Loss recovery
 * is validated end-to-end against the BoringSSL oracle so it is a real interoperating retransmission, not
 * a self-mirror.
 */
class DtlsRetransmissionTest {
    private fun config() = DtlsConfig(enableDtls13 = false)

    /**
     * Drop our client's first flight (the ClientHello) outright. The BoringSSL server therefore never
     * answers, so only our own DTLS timer can rescue the handshake: it must arm, fire, retransmit, and
     * the session must still establish against the oracle.
     */
    @Test
    fun a_dropped_flight_is_retransmitted_when_the_dtls_timer_fires() {
        val ours = DtlsEngine(config())
        val oracle = BoringSslDtlsEngine(config())
        try {
            var now: Instant = Instant.fromEpochSeconds(0)
            val firstFlight = ours.start(DtlsRole.Client, now).records
            assertTrue(firstFlight.isNotEmpty(), "our client sent a ClientHello flight")
            oracle.start(DtlsRole.Server, now)
            // ...and the network eats it. Nothing reaches the server.

            // A timer must be armed — otherwise a lost flight would hang the handshake forever.
            val deadline = ours.nextDeadline(now)
            assertNotNull(deadline, "our client armed a retransmission timer for the unacked flight")
            assertTrue(deadline > now, "the timer is in the future, was $deadline vs now=$now")

            // Before the deadline the engine must NOT retransmit — a timer that fires early would
            // multiply traffic on every slow link.
            val early = ours.onTimeout(now + (deadline - now) / 2)
            assertTrue(early.records.isEmpty(), "no retransmission before the deadline")

            // At the deadline it does.
            now = deadline
            val retransmitted = ours.onTimeout(now)
            assertTrue(retransmitted.records.isNotEmpty(), "the flight was retransmitted when the timer fired")

            // The retransmitted flight is a real ClientHello: delivering it (and nothing else) completes
            // the handshake against BoringSSL, proving recovery is genuine and not just bytes on the wire.
            val (c, s) = DtlsConductor().also { it.now = now }.drive(ours.endpoint(), oracle.endpoint(), seed = retransmitted.records)
            assertIs<DtlsState.Established>(c, "our client established after the retransmission, was $c")
            assertIs<DtlsState.Established>(s, "the oracle established after the retransmission, was $s")
            assertEquals(oracle.localFingerprint, c.peerFingerprint)
        } finally {
            ours.close()
            oracle.close()
        }
    }

    /**
     * Directive #6 (buffers are factory-injected, bounded in hot paths): every record our engine puts on
     * the wire must come from the injected factory, and a handshake must not allocate without bound. This
     * asserts allocation is sourced from the injected seam, stays bounded across the whole handshake, and
     * — crucially — that steady-state application data allocates a *constant* number of buffers per
     * message (never per byte, never leaking per message). The exact counts depend on the pure-Kotlin
     * flight assembly, so this asserts the shape (bounded + constant), not a magic number.
     */
    @Test
    fun the_handshake_allocates_only_from_the_injected_factory_and_is_bounded() {
        val ourFactory = CountingBufferFactory(BufferFactory.managed())
        val ours = DtlsEngine(DtlsConfig(bufferFactory = ourFactory, enableDtls13 = false))
        val oracle = BoringSslDtlsEngine(config())
        try {
            val conductor = DtlsConductor()
            val (c, s) = conductor.drive(ours.endpoint(), oracle.endpoint())
            assertIs<DtlsState.Established>(c)
            assertIs<DtlsState.Established>(s)
            val now = conductor.now

            // The records went through the injected seam, not BufferFactory.Default.
            assertTrue(ourFactory.allocations > 0, "our records came from the injected factory")
            // Bounded: a P-256 handshake is a handful of flights — clearly not per-byte/unbounded.
            assertTrue(ourFactory.allocations < 2000, "bounded handshake allocation, was ${ourFactory.allocations}")

            // Steady state: application data allocates a constant, small number of buffers per message.
            val before = ourFactory.allocations
            repeat(16) { ours.send(bytesOf(0x01, 0x02, 0x03), now) }
            val firstWindow = ourFactory.allocations - before
            val beforeSecond = ourFactory.allocations
            repeat(16) { ours.send(bytesOf(0x01, 0x02, 0x03), now) }
            val secondWindow = ourFactory.allocations - beforeSecond
            assertEquals(firstWindow, secondWindow, "per-message allocation is constant, not growing")
            assertTrue(firstWindow / 16 <= 8, "a small constant per message, was ${firstWindow / 16}")
        } finally {
            ours.close()
            ours.close() // idempotent: the driver frees on both the normal and the failure path
            oracle.close()
        }
    }

    /**
     * Regression for the adversarial-gate MAJOR (now a property of the **test oracle**, since BoringSSL
     * left production in W4b): a GC-heap datagram is staged through the oracle's fixed 64 KiB native
     * scratch before it reaches BoringSSL. A buffer larger than the scratch cannot be staged in one shot,
     * and passing its full length on would make BoringSSL read past the scratch's end (a native
     * over-read). The oracle must reject it up front, not over-read. The pure-Kotlin production engine
     * has no such native staging edge, so this fixture stays with the oracle that does.
     */
    @Test
    fun a_heap_datagram_larger_than_the_oracle_ffi_staging_buffer_is_rejected_not_over_read() {
        val oracle = BoringSslDtlsEngine(config())
        try {
            oracle.start(DtlsRole.Client, Instant.fromEpochSeconds(0))
            // One byte past the 64 KiB scratch, on a managed (GC-heap, no native address) buffer.
            val oversize = BufferFactory.managed().allocate((1 shl 16) + 1, ByteOrder.BIG_ENDIAN)
            oversize.position(0)
            oversize.setLimit((1 shl 16) + 1)
            // send() stages through inputPointer before it ever reaches SSL_write, so the bound fires
            // regardless of handshake state — the length alone is rejected, no bytes are read.
            assertFailsWith<IllegalArgumentException> { oracle.send(oversize, Instant.fromEpochSeconds(0)) }
        } finally {
            oracle.close()
        }
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

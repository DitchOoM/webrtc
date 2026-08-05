package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.pool.BufferPool
import kotlin.test.assertEquals
import kotlin.test.fail

/**
 * **Leak tracking that can see the free side**, for the `webrtc` module's own fixtures.
 *
 * A deliberate twin of `webrtc-ice`'s `LeakTrackingFactory`, which is `internal` to *that* module's test
 * source set and therefore invisible here. The duplication is the lesser evil — the alternative is
 * publishing a test artifact solely to share forty lines — and it is the same trade `webrtc-dtls`'
 * `networkBuffer()` already makes against `webrtc-ice`'s copy. Keep the two in step.
 *
 * ## Why it asks each buffer instead of doing arithmetic on the pool's counters
 *
 * `BufferFactory` is `allocate`/`wrap` only: there is no free hook, which is why every *counting* factory
 * in this repo counts allocations and stops. A pool can see the other half, because a `PooledBuffer`
 * refuses every read, write and slice once released. The obvious arithmetic metric
 * (`totalAllocations - poolHits - currentPoolSize`) is wrong in **both** directions and must not be
 * resurrected; asking each buffer agrees with reality instead.
 *
 * ## Where to point it
 *
 * At **one** seam, and never at a seam shared with scenery. [TestNet]'s copy-on-receive factory is the
 * receive side of both peers — both production code, no harness servers on that link — which is what
 * makes it a valid target here. A `DtlsConfig.bufferFactory` is the DTLS record seam of one peer.
 * Pointing a single tracker at both would conflate them and make a number that cannot be attributed.
 *
 * It **records without decorating** — the pool's own buffer is handed back unchanged — so the
 * `nativeMemoryAccess` resolution a real io_uring send depends on is untouched.
 */
internal class LeakTrackingFactory(
    private val pool: BufferPool =
        BufferPool(
            maxPoolSize = MAX_TRACKED_POOL,
            defaultBufferSize = TRACKED_BUFFER_SIZE,
            factory = BufferFactory.Default,
        ),
) : BufferFactory {
    private val handedOut = mutableListOf<PlatformBuffer>()

    override fun allocate(
        size: Int,
        byteOrder: ByteOrder,
    ): PlatformBuffer = pool.allocate(size, byteOrder).also { handedOut += it }

    override fun wrap(
        array: ByteArray,
        byteOrder: ByteOrder,
    ): PlatformBuffer = pool.wrap(array, byteOrder).also { handedOut += it }

    /** How many buffers this factory has handed out — the denominator an assertion should report. */
    val allocations: Int get() = handedOut.size

    /** How many are still live. Exposed so a fixture can report the *before* number it is fixing. */
    val live: Int get() = handedOut.count { !it.isReleased() }

    /**
     * The invariant directive 6 has always claimed: every buffer a run allocated came back. [what] names
     * the run, since a count alone says nothing about where.
     */
    fun assertNoLeaks(what: String) {
        val leaked = live
        if (leaked != 0) {
            fail("$what leaked $leaked of $allocations buffer(s): they were never released back to the pool")
        }
        // Not just `leaked == 0`: a run that allocated nothing would satisfy that vacuously, and these
        // fixtures exist to watch a session that definitely allocates.
        assertEquals(true, allocations > 0, "$what allocated nothing — the fixture cannot have exercised anything")
    }

    // A pooled buffer refuses every operation once released, which is the only free-side signal buffer
    // exposes. `slice()` takes a reference on a live one; harmless, since this runs at the end of a run.
    private fun PlatformBuffer.isReleased(): Boolean =
        try {
            slice()
            false
        } catch (_: IllegalStateException) {
            true
        }
}

// 8 KiB: comfortably above a DTLS record or an SCTP packet, and far below the pool's own 64 KiB file-I/O
// default, which would make every fixture allocate in 64 KiB steps for a 100-byte message.
private const val TRACKED_BUFFER_SIZE = 8 * 1024
private const val MAX_TRACKED_POOL = 4096

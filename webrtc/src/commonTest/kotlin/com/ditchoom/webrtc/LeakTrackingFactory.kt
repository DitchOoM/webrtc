package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.deterministic
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
 * ## Two probes, and they answer different questions — use both
 *
 * `BufferFactory` is `allocate`/`wrap` only: there is no free hook, which is why every *counting* factory
 * in this repo counts allocations and stops. A pool can see the other half, and it can see it two ways:
 *
 * - [assertNoLeaks] asks each buffer whether it was released, because a `PooledBuffer` refuses every
 *   read, write and slice once freed. That catches a **missing free**.
 * - [assertPoolDrained] compares the pool's own counters, because the buffer-level probe is *blind* to a
 *   refcount that never reached zero — `freed` is set by the first `freeNativeMemory()` whatever the
 *   refcount does. That catches an **unreleased slice**, which is the socket#277 class and the one the
 *   decode paths in `webrtc-stun`/`webrtc-sctp` produce.
 *
 * Neither subsumes the other. `PoolDrainedProbeTest` injects both conditions and pins both verdicts.
 *
 * The one metric that is **not** used is `totalAllocations - poolHits - currentPoolSize`: CLAUDE.md
 * records it as wrong in *both* directions at once, and it must not be resurrected.
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
            // Native-backed on purpose, not `BufferFactory.Default`. `deterministic()` is the factory
            // production actually uses on Kotlin/Native Linux (a raw malloc that must be closed), so a
            // fixture on it is testing the configuration the leak is real in rather than a GC-managed
            // stand-in that would reclaim the mistake for us. Pooled *and* native is also exactly the
            // `BufferPool(factory = BufferFactory.deterministic())` shape CLAUDE.md recommends to
            // consumers, so the harness now exercises the recommendation.
            factory = BufferFactory.deterministic(),
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
     * **The assertion that can see a refcount which never reached zero** — the one [assertNoLeaks]
     * structurally cannot make.
     *
     * ## Why the other one is blind
     *
     * [assertNoLeaks] asks each buffer "are you released?" by probing `slice()`. But `PooledBuffer` sets
     * its `freed` flag on the *first* `freeNativeMemory()` and `checkNotFreed()` throws from then on —
     * **regardless of the refcount**. So a chunk with outstanding references from decode-side slices
     * reads as "released" while its memory has not come back. That is the socket#277 failure class, and
     * CLAUDE.md already says only pool stats discriminate it. This is that check.
     *
     * ## The invariant, and why it is this one
     *
     * `acquire()` counts a `poolMiss` exactly when it calls `factory.allocate` — so **`poolMisses` is the
     * number of distinct chunks the pool ever created**. `release()` pushes a chunk back onto the
     * freelist, which is what `currentPoolSize` counts. Therefore every chunk came home iff
     * `currentPoolSize == poolMisses`.
     *
     * Deliberately **not** `totalAllocations - poolHits - currentPoolSize`. That metric is recorded in
     * CLAUDE.md as having been wrong in *both* directions at once — blind to a real leak on the
     * byte-order-mismatch path, and inventing 150 phantom leaks for a session where all 601 buffers were
     * freed. It must not be resurrected.
     *
     * The [MAX_TRACKED_POOL] guard is load-bearing: `release()` drops a chunk instead of pooling it once
     * `pooledCount` hits `maxPoolSize`, which would make `currentPoolSize` under-report through no fault
     * of the code under test.
     */
    fun assertPoolDrained(what: String) {
        val stats = pool.stats()
        assertEquals(
            true,
            stats.peakPoolSize < MAX_TRACKED_POOL,
            "$what filled the tracking pool (peak ${stats.peakPoolSize} of $MAX_TRACKED_POOL) — " +
                "release() starts dropping chunks at the cap, so currentPoolSize can no longer be trusted",
        )
        assertEquals(
            stats.poolMisses.toInt(),
            stats.currentPoolSize,
            "$what did not return every chunk to the pool: the pool created ${stats.poolMisses} chunk(s) " +
                "and only ${stats.currentPoolSize} came back, so ${stats.poolMisses - stats.currentPoolSize} " +
                "still has an outstanding reference (a slice nobody released, not a missing free)",
        )
        // Anti-vacuity: a run that never made the pool allocate proves nothing.
        assertEquals(true, stats.poolMisses > 0, "$what never allocated a chunk — the fixture exercised nothing")
    }

    /**
     * The invariant directive 6 has always claimed: every buffer a run allocated came back. [what] names
     * the run, since a count alone says nothing about where.
     *
     * **Weaker than [assertPoolDrained]** — see that KDoc. This one proves `freeNativeMemory()` was
     * *called* on each buffer; it cannot prove the memory came back.
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

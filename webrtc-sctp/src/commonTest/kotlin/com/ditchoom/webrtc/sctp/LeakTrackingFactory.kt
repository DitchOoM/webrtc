package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.deterministic
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.pool.BufferPool
import kotlin.test.assertEquals
import kotlin.test.fail

/**
 * Counts the chunks a [BufferPool] actually creates, by sitting **underneath** it.
 *
 * This is the ground truth, and it exists because three earlier probes tried to derive the same number
 * from `PoolStats` and every one of them was wrong:
 *
 * - `totalAllocations - poolHits - currentPoolSize` — recorded in CLAUDE.md as wrong in *both* directions.
 * - `currentPoolSize == poolMisses` — reports a false failure; the pool legitimately creates buffers that
 *   never reach its freelist (`allocate()` acquires, and on a byte-order mismatch releases that chunk and
 *   hands back an unpooled one).
 * - `currentPoolSize == peakPoolSize` — cannot see a run where nothing was *ever* returned, because the
 *   peak is then zero too.
 *
 * `BufferPool` calls its backing factory exactly once per chunk it allocates, so [created] needs no model
 * of buckets, size classes, hits, or that byte-order path. Measure the thing; do not infer it.
 */
internal class CountingBackingFactory(
    private val delegate: BufferFactory = BufferFactory.deterministic(),
) : BufferFactory {
    var created: Int = 0
        private set

    override fun allocate(
        size: Int,
        byteOrder: ByteOrder,
    ): PlatformBuffer = delegate.allocate(size, byteOrder).also { created++ }

    override fun wrap(
        array: ByteArray,
        byteOrder: ByteOrder,
    ): PlatformBuffer = delegate.wrap(array, byteOrder).also { created++ }
}

/**
 * **Leak tracking that can see the free side**, for `webrtc-sctp`'s own fixtures.
 *
 * The third deliberate twin of this class (`webrtc-ice` and `webrtc` each hold one), because each is
 * `internal` to its own module's test source set. The duplication is the lesser evil — the alternative is
 * publishing a test artifact solely to share a hundred lines — and it buys the thing that matters here:
 * a tracker on `SctpConfig.bufferFactory` **with no DTLS or ICE underneath it**, so a number it reports
 * belongs to the SCTP send seam and to nothing else. Keep the three in step.
 *
 * ## Two probes, answering different questions — use both
 *
 * - [assertNoLeaks] asks each buffer whether it was released, because a `PooledBuffer` refuses every
 *   read, write and slice once freed. That catches a **missing free**.
 * - [assertPoolDrained] compares chunks created against chunks idle, because the buffer-level probe is
 *   *blind* to a refcount that never reached zero — `freed` is set by the first `freeNativeMemory()`
 *   whatever the refcount does. That catches an **unreleased slice**: on a pooled buffer `slice()` is
 *   `addRef()`, so a borrow nobody released keeps the memory out of the pool however diligently its owner
 *   freed it. Every retransmission of a DATA chunk takes exactly one such borrow.
 *
 * Neither subsumes the other. `assertPoolDrained` is the stronger of the two; [assertNoLeaks] earns its
 * keep by naming *which* buffer.
 *
 * ## Why the pool is native-backed
 *
 * `deterministic()` is the factory production actually uses on Kotlin/Native Linux — a raw malloc that
 * must be closed — so fixtures run against the configuration the leak is real in rather than a GC-managed
 * stand-in that reclaims our mistakes for us. Pooled *and* native is also exactly the
 * `BufferPool(factory = BufferFactory.deterministic())` shape CLAUDE.md recommends to consumers.
 *
 * It **records without decorating** — the pool's own buffer is handed back unchanged. An earlier version
 * elsewhere in this repo that *did* decorate (to count slices) perturbed the very balance it was
 * measuring, because its own [assertNoLeaks] probe took a slice that nothing counted.
 */
internal class LeakTrackingFactory(
    private val backing: CountingBackingFactory = CountingBackingFactory(),
    private val pool: BufferPool =
        BufferPool(
            maxPoolSize = MAX_TRACKED_POOL,
            defaultBufferSize = TRACKED_BUFFER_SIZE,
            factory = backing,
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

    /** Chunks the pool created but has not got back — 0 when every reference has been returned. */
    val outstandingChunks: Int get() = backing.created - pool.stats().currentPoolSize

    /**
     * **Every chunk the pool created is back in it.** The probe [assertNoLeaks] structurally cannot make.
     *
     * The [MAX_TRACKED_POOL] guard is load-bearing: `release()` starts *dropping* chunks once
     * `pooledCount` reaches `maxPoolSize`, which would make this under-report through no fault of the
     * code under test.
     */
    fun assertPoolDrained(what: String) {
        val stats = pool.stats()
        assertEquals(
            true,
            stats.peakPoolSize < MAX_TRACKED_POOL,
            "$what filled the tracking pool (peak ${stats.peakPoolSize} of $MAX_TRACKED_POOL) — " +
                "release() drops chunks at the cap, so this measurement can no longer be trusted",
        )
        assertEquals(
            0,
            outstandingChunks,
            "$what did not return every chunk: the pool created ${backing.created} and only " +
                "${stats.currentPoolSize} are idle, so $outstandingChunks still has a reference nobody " +
                "released (a slice, not a missing free)",
        )
        // Anti-vacuity: a run that never made the pool allocate proves nothing.
        assertEquals(true, backing.created > 0, "$what never allocated a chunk — the fixture exercised nothing")
    }

    /**
     * The invariant directive 6 has always claimed: every buffer a run allocated came back. [what] names
     * the run, since a count alone says nothing about where.
     *
     * **Weaker than [assertPoolDrained]** — this proves `freeNativeMemory()` was *called* on each buffer;
     * it cannot prove the memory came back.
     */
    fun assertNoLeaks(what: String) {
        val leaked = handedOut.count { !it.isReleased() }
        if (leaked != 0) {
            fail("$what leaked $leaked of $allocations buffer(s): they were never released back to the pool")
        }
        // Not just `leaked == 0`: a run that allocated nothing would satisfy that vacuously.
        assertEquals(true, allocations > 0, "$what allocated nothing — the fixture cannot have exercised anything")
    }

    // A pooled buffer refuses every operation once released, which is the only free-side signal buffer
    // exposes. The probe slice is released immediately: `slice()` also takes a REFERENCE, so a probe that
    // kept one would pin the very chunk [assertPoolDrained] is asking about. The measurement must not
    // perturb the thing measured.
    private fun PlatformBuffer.isReleased(): Boolean =
        try {
            slice().freeIfNeeded()
            false
        } catch (_: IllegalStateException) {
            true
        }
}

// 8 KiB: comfortably above an SCTP packet, and far below the pool's own 64 KiB file-I/O default, which
// would make every fixture allocate in 64 KiB steps for a 100-byte message.
private const val TRACKED_BUFFER_SIZE = 8 * 1024
private const val MAX_TRACKED_POOL = 4096

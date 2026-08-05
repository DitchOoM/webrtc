package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.pool.BufferPool
import kotlin.test.assertEquals
import kotlin.test.fail

/**
 * **Leak tracking that can actually see the free side** — the thing `CountingBufferFactory` cannot do.
 *
 * `BufferFactory` is `allocate`/`wrap` only: there is no free hook on it, which is why every counting
 * factory in this repo counts allocations and stops there. A *pool* can see the other half, because a
 * pooled buffer knows whether it has been released: `PooledBuffer` refuses every read, write and slice
 * once freed. So [assertNoLeaks] asks each buffer directly rather than inferring anything.
 *
 * ## Why it asks each buffer instead of doing arithmetic on the pool's counters
 *
 * The obvious metric is `totalAllocations - poolHits - currentPoolSize`, and it is **wrong**. It reads 0
 * for a buffer that is genuinely leaked in the byte-order-mismatch path (where the pool releases the
 * chunk it acquired and hands back an unpooled one), and it reported a stable 150 for an ICE session in
 * which every single one of 601 buffers had in fact been freed. Both directions of error at once, which
 * is the worst thing a leak metric can do. Probing each buffer agrees with reality in both directions —
 * verified by deliberately leaking three and finding exactly three.
 *
 * ## Why this does not wrap the buffer
 *
 * [LeakTrackingFactory] hands back the pool's own buffer, unchanged, and merely keeps a reference to it.
 * A *decorating* tracker would risk breaking `nativeMemoryAccess` resolution for io_uring sends — the
 * hazard buffer's own `TrackedSlice` KDoc documents — which is what previously argued against tracking
 * this way at all. Recording is not decorating, so that objection does not apply and this stays usable
 * on the real socket path.
 */
internal fun trackingPool(
    maxPoolSize: Int = MAX_TRACKED_POOL,
    defaultBufferSize: Int = TRACKED_BUFFER_SIZE,
    factory: BufferFactory = BufferFactory.Default,
): BufferPool = BufferPool(maxPoolSize = maxPoolSize, defaultBufferSize = defaultBufferSize, factory = factory)

/**
 * Counts the chunks a [BufferPool] actually creates, by sitting **underneath** it — the ground truth
 * [LeakTrackingFactory.assertPoolDrained] compares against.
 *
 * It exists because every attempt to derive the same number from `PoolStats` was wrong, in both
 * directions: `totalAllocations - poolHits - currentPoolSize` (see the note above);
 * `currentPoolSize == poolMisses`, which the byte-order path falsifies; `currentPoolSize == peakPoolSize`,
 * blind when nothing was ever returned. `BufferPool` calls its backing factory exactly once per chunk it
 * creates, so [created] needs no model of buckets, size classes or hits. Measure it; do not infer it.
 */
internal class CountingBackingFactory(
    private val delegate: BufferFactory = BufferFactory.Default,
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
 * A [BufferFactory] over [pool] that remembers every buffer it handed out, so [assertNoLeaks] can ask
 * each one whether it came back. Point it at the thing under test — `IceConfig(bufferFactory = ...)` —
 * and **not** at the vnet: the vnet's copy-on-receive allocates from the same seam, and one factory
 * serving both would attribute the harness's buffers to production code.
 */
internal class LeakTrackingFactory(
    private val backing: CountingBackingFactory = CountingBackingFactory(),
    private val pool: BufferPool = trackingPool(factory = backing),
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
     * The invariant directive 6 has always claimed and nothing has ever enforced: every buffer a run
     * allocated came back. [what] names the run, since a count alone says nothing about where.
     *
     * **Weaker than [assertPoolDrained]** — this proves `freeNativeMemory()` was *called* on each buffer;
     * it cannot prove the memory came back. Assert it first anyway: it is the one that names *which*.
     */
    fun assertNoLeaks(what: String) {
        val live = handedOut.count { !it.isReleased() }
        if (live != 0) {
            fail("$what leaked $live of $allocations buffer(s): they were never released back to the pool")
        }
        // Not just `live == 0`: a run that allocated nothing would satisfy that vacuously, and this
        // fixture exists to watch a session that definitely allocates.
        assertEquals(true, allocations > 0, "$what allocated nothing — the fixture cannot have exercised anything")
    }

    /**
     * **Every chunk the pool created is back in it** — the claim [assertNoLeaks] structurally cannot make,
     * because `freed` is set by the first `freeNativeMemory()` whatever the refcount does. An unreleased
     * `slice()` is invisible to one and visible to the other; on a pooled buffer `slice()` is `addRef()`.
     *
     * The [MAX_TRACKED_POOL] guard is load-bearing: `release()` starts *dropping* chunks once `pooledCount`
     * reaches `maxPoolSize`, which would make this under-report through no fault of the code under test.
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
        assertEquals(true, backing.created > 0, "$what never allocated a chunk — the fixture exercised nothing")
    }

    // A pooled buffer refuses every operation once released, which is the only free-side signal buffer
    // exposes. The probe slice is released immediately: `slice()` also takes a REFERENCE, so a probe that
    // kept one would pin the very chunk [assertPoolDrained] is asking about — the measurement must not
    // perturb the thing measured.
    private fun PlatformBuffer.isReleased(): Boolean =
        try {
            slice().freeIfNeeded()
            false
        } catch (_: IllegalStateException) {
            true
        }
}

// 8 KiB: comfortably above a STUN check or an SCTP chunk, and far below the pool's own 64 KiB
// file-I/O default, which would make every fixture allocate in 64 KiB steps for a 100-byte message.
private const val TRACKED_BUFFER_SIZE = 8 * 1024
private const val MAX_TRACKED_POOL = 4096

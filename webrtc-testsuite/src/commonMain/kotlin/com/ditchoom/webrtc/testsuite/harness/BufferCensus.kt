package com.ditchoom.webrtc.testsuite.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.pool.BufferPool

/**
 * What a finished scenario did with its buffers — the standing no-leak invariant (TESTING.md §4.1,
 * directive #6) as a value a **consumer** can assert on, via [WebRtcHarnessScope.assertNoBufferLeaks]
 * or [WebRtcHarnessScope.bufferCensus].
 *
 * There are two separate claims here, and the weaker one is the one people reach for:
 *
 * - [unreleasedBuffers] is `freeNativeMemory()` **called or not**, per buffer the scenario was handed.
 *   It names *how many*, which is what a failure message needs — but it is structurally blind to an
 *   unreleased `slice()`, because the freed flag is set by the first free whatever the refcount does.
 *   On a pooled buffer `slice()` is an `addRef`, so a borrow nobody hands back reads as fully released.
 * - [outstandingChunks] is **every chunk the pool created, minus every chunk idle in it**. That is the
 *   real gate: it sees the unreleased borrow the first one cannot, and it is measured at the pool's
 *   backing factory rather than derived from `PoolStats` — every formula tried over those counters has
 *   been wrong, in both directions at once.
 *
 * [saturated] is not a detail to skip. A pool starts *dropping* returned chunks once it is full, which
 * makes [outstandingChunks] under-report through no fault of the code under test; a saturated census
 * cannot be trusted in the passing direction and [assertNoBufferLeaks] fails on it rather than
 * reporting a green it did not measure.
 */
public class BufferCensus internal constructor(
    /** Buffers the scenario was handed — the denominator, and the anti-vacuity guard on the whole census. */
    public val allocations: Int,
    /** Buffers whose `freeNativeMemory()` was never called. See the class doc for what this cannot see. */
    public val unreleasedBuffers: Int,
    /** Chunks the pool asked its backing factory for — measured underneath the pool, never inferred. */
    public val chunksCreated: Int,
    /** Chunks sitting idle in the pool, i.e. every reference to them released. */
    public val chunksIdle: Int,
    /** The most chunks ever idle at once — against [poolCapacity], this is what [saturated] reads. */
    public val peakPoolSize: Int,
    /** How many chunks the pool will hold before it starts dropping returned ones. */
    public val poolCapacity: Int,
) {
    /** Chunks created and not back — 0 when every reference the scenario took has been released. */
    public val outstandingChunks: Int get() = chunksCreated - chunksIdle

    /** The pool filled, so [outstandingChunks] under-reports and this census proves nothing. */
    public val saturated: Boolean get() = peakPoolSize >= poolCapacity

    /** Every chunk came back, the scenario actually allocated, and the measurement is trustworthy. */
    public val isDrained: Boolean get() = !saturated && chunksCreated > 0 && outstandingChunks == 0

    override fun toString(): String =
        "BufferCensus(allocations=$allocations, unreleasedBuffers=$unreleasedBuffers, " +
            "chunksCreated=$chunksCreated, chunksIdle=$chunksIdle, outstandingChunks=$outstandingChunks, " +
            "peakPoolSize=$peakPoolSize/$poolCapacity)"
}

/**
 * The [BufferFactory] the harness hands to the vnet and to both peers: a [BufferPool] with a counter
 * **underneath** it, plus a record of every buffer it handed out.
 *
 * Pooled on purpose. A pool is the only thing in `buffer` that can see the free side at all — a
 * `BufferFactory` is `allocate`/`wrap` and has no free hook, which is why a counting decorator can only
 * ever report allocations. It is also the shape a consumer is meant to run in production
 * (`BufferPool(factory = BufferFactory.deterministic())`), so the harness asserting on it is asserting
 * on the configuration that matters.
 *
 * The counter sits under the pool rather than over it because `BufferPool` calls its backing factory
 * exactly once per chunk it creates — so [BufferCensus.chunksCreated] needs no model of buckets, size
 * classes or hits. This does **not** decorate the buffers it hands back: it returns the pool's own
 * buffer unchanged and merely keeps a reference, so nothing here perturbs `nativeMemoryAccess`
 * resolution on a real socket send path.
 */
internal class TrackingBufferFactory(
    delegate: BufferFactory,
    private val poolCapacity: Int = HARNESS_POOL_CAPACITY,
    defaultBufferSize: Int = HARNESS_BUFFER_SIZE,
) : BufferFactory {
    private val backing = CountingBackingFactory(delegate)
    private val pool: BufferPool = BufferPool(maxPoolSize = poolCapacity, defaultBufferSize = defaultBufferSize, factory = backing)
    private val handedOut = mutableListOf<PlatformBuffer>()

    override fun allocate(
        size: Int,
        byteOrder: ByteOrder,
    ): PlatformBuffer = pool.allocate(size, byteOrder).also { handedOut += it }

    override fun wrap(
        // Overriding `wrap` is the only way to be a BufferFactory at all, and nothing here reads or
        // copies the array — it is handed straight to the pool.
        @Suppress("NoByteArrayInProd") array: ByteArray,
        byteOrder: ByteOrder,
    ): PlatformBuffer = pool.wrap(array, byteOrder).also { handedOut += it }

    val allocationCount: Long get() = handedOut.size.toLong()

    fun census(): BufferCensus {
        val stats = pool.stats()
        return BufferCensus(
            allocations = handedOut.size,
            unreleasedBuffers = handedOut.count { !it.isReleased() },
            chunksCreated = backing.created,
            chunksIdle = stats.currentPoolSize,
            peakPoolSize = stats.peakPoolSize,
            poolCapacity = poolCapacity,
        )
    }

    // A pooled buffer refuses every operation once released, which is the only free-side signal buffer
    // exposes. The probe slice is handed straight back: `slice()` also takes a REFERENCE, so a probe that
    // kept one would pin the very chunk the census is asking about.
    private fun PlatformBuffer.isReleased(): Boolean =
        try {
            slice().freeIfNeeded()
            false
        } catch (_: IllegalStateException) {
            true
        }
}

/** Counts the chunks a [BufferPool] actually creates, by sitting underneath it. Measured, not inferred. */
private class CountingBackingFactory(
    private val delegate: BufferFactory,
) : BufferFactory {
    var created: Int = 0
        private set

    override fun allocate(
        size: Int,
        byteOrder: ByteOrder,
    ): PlatformBuffer = delegate.allocate(size, byteOrder).also { created++ }

    override fun wrap(
        // BufferFactory.wrap's own signature; see TrackingBufferFactory.wrap.
        @Suppress("NoByteArrayInProd") array: ByteArray,
        byteOrder: ByteOrder,
    ): PlatformBuffer = delegate.wrap(array, byteOrder).also { created++ }
}

/**
 * Big enough that no harness scenario reaches it — at the cap a pool drops returned chunks and the
 * census stops meaning anything, which [BufferCensus.saturated] reports rather than hides.
 */
private const val HARNESS_POOL_CAPACITY = 4096

/** Comfortably above a STUN check or an SCTP chunk, and far below the pool's 64 KiB file-I/O default. */
private const val HARNESS_BUFFER_SIZE = 8 * 1024

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
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
 * A [BufferFactory] over [pool] that remembers every buffer it handed out, so [assertNoLeaks] can ask
 * each one whether it came back. Point it at the thing under test — `IceConfig(bufferFactory = ...)` —
 * and **not** at the vnet: the vnet's copy-on-receive allocates from the same seam, and one factory
 * serving both would attribute the harness's buffers to production code.
 */
internal class LeakTrackingFactory(
    private val pool: BufferPool = trackingPool(),
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

    /**
     * The invariant directive 6 has always claimed and nothing has ever enforced: every buffer a run
     * allocated came back. [what] names the run, since a count alone says nothing about where.
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

    // A pooled buffer refuses every operation once released, which is the only free-side signal buffer
    // exposes. `slice()` takes a reference on a live one; harmless, since this runs at the end of a run.
    private fun PlatformBuffer.isReleased(): Boolean =
        try {
            slice()
            false
        } catch (e: IllegalStateException) {
            true
        }
}

// 8 KiB: comfortably above a STUN check or an SCTP chunk, and far below the pool's own 64 KiB
// file-I/O default, which would make every fixture allocate in 64 KiB steps for a 100-byte message.
private const val TRACKED_BUFFER_SIZE = 8 * 1024
private const val MAX_TRACKED_POOL = 4096

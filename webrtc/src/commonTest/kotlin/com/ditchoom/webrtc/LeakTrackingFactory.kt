package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.deterministic
import com.ditchoom.buffer.freeIfNeeded
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
    private var slicesTaken = 0
    private var slicesReleased = 0

    // Where each still-live slice was taken. A count alone says "something pins the datagram"; this says
    // which line, which is the difference between a fix and a hunt.
    //
    // Keyed on the WRAPPER, which is unique per slice — not on the raw buffer. Two earlier attempts got
    // this wrong and reported no sites while the count said 21: a map keyed by the raw buffer collapsed
    // entries because buffer's types compare by CONTENT, and a list keyed by raw identity still collided
    // because the pool REUSES chunks, so the same object is sliced again later and the removal took out a
    // still-live entry. The wrapper is created once per slice and never recycled.
    private val liveSliceSites = mutableListOf<Counting>()

    /** How many slices this run took — for a fixture that wants to assert it exercised zero-copy decode. */
    val slices: Int get() = slicesTaken

    override fun allocate(
        size: Int,
        byteOrder: ByteOrder,
    ): PlatformBuffer = Counting(pool.allocate(size, byteOrder), isSlice = false).also { handedOut += it }

    override fun wrap(
        array: ByteArray,
        byteOrder: ByteOrder,
    ): PlatformBuffer = Counting(pool.wrap(array, byteOrder), isSlice = false).also { handedOut += it }

    /**
     * Counts `slice()` against its release, transitively.
     *
     * This one *does* decorate, unlike the rest of this factory, and that is a deliberate exception with
     * a bounded blast radius: decorating risks breaking `nativeMemoryAccess` resolution for io_uring
     * sends, so it must never be pointed at a real socket. Every fixture using it runs on the in-memory
     * vnet, where there is no such path. Nested slices are wrapped too — `slice()` on a slice takes
     * another reference on the same root chunk, so an untracked inner view would hide exactly the pin
     * this is looking for.
     */
    private inner class Counting(
        private val inner: PlatformBuffer,
        // Only a SLICE's release balances a `slice()`. The root buffer is freed by its owner under the
        // last-reader rule and was never counted as taken, so counting its free would hide one missing
        // slice release per datagram.
        private val isSlice: Boolean,
        val site: String? = null,
    ) : PlatformBuffer by inner {
        private var released = false

        override fun slice(byteOrder: ByteOrder): PlatformBuffer {
            slicesTaken++
            val sliced = inner.slice(byteOrder)
            return Counting(sliced, isSlice = true, site = Throwable().stackTraceToString())
                .also { liveSliceSites += it }
        }

        override fun freeNativeMemory() {
            // Guarded: `freeNativeMemory()` is idempotent on the real types, so a double release must not
            // be counted twice or a genuine imbalance could be masked by one.
            if (!released) {
                released = true
                if (isSlice) {
                    slicesReleased++
                    val at = liveSliceSites.indexOfFirst { it === this@Counting }
                    if (at >= 0) liveSliceSites.removeAt(at)
                }
            }
            inner.freeNativeMemory()
        }
    }

    /** How many buffers this factory has handed out — the denominator an assertion should report. */
    val allocations: Int get() = handedOut.size

    /** How many are still live. Exposed so a fixture can report the *before* number it is fixing. */
    val live: Int get() = handedOut.count { !it.isReleased() }

    /**
     * **The assertion that can see a reference that never came back** — the one [assertNoLeaks]
     * structurally cannot make.
     *
     * ## Why the other one is blind
     *
     * [assertNoLeaks] asks each buffer "are you released?" by probing `slice()`. But `PooledBuffer` sets
     * its `freed` flag on the *first* `freeNativeMemory()` and `checkNotFreed()` throws from then on —
     * **regardless of the refcount**. A chunk with outstanding decode-side slices therefore reads as
     * "released" while its memory has not come back. That is the socket#277 failure class.
     *
     * ## Why this counts slices rather than doing arithmetic on the pool's counters
     *
     * The obvious probe is a formula over `PoolStats`, and **every such formula tried here has been
     * wrong**. `totalAllocations - poolHits - currentPoolSize` is recorded in CLAUDE.md as wrong in both
     * directions at once. `currentPoolSize == poolMisses` (tried next) reports a false failure, because
     * the pool legitimately creates chunks that never reach its freelist. `currentPoolSize ==
     * peakPoolSize` cannot see a run where nothing was *ever* returned, since the peak is then zero too.
     * The counters do not model what we actually want to know.
     *
     * So this measures the thing itself. `slice()` on a pooled parent is `addRef()`, and the only way the
     * refcount reaches zero is a matching release on every slice. Counting the two and comparing is exact,
     * needs no model of the pool's internals, and points at a *number of missing releases* rather than a
     * derived quantity — which is also why it survives a pool implementation change.
     */
    fun assertSlicesBalanced(what: String) {
        val outstanding = slicesTaken - slicesReleased
        assertEquals(
            0,
            outstanding,
            "$what left $outstanding of $slicesTaken slice(s) unreleased. On a pooled buffer each is a " +
                "reference the chunk never got back, so its memory stays out of the pool however " +
                "diligently the owner called freeNativeMemory().\n  taken at:\n" + liveSiteSummary(),
        )
    }

    // The distinct call sites still holding a slice, most frequent first — trimmed to the frames that are
    // ours, since the buffer/coroutine frames above and below them are never the answer.
    private fun liveSiteSummary(): String =
        liveSliceSites
            .map { entry ->
                (entry.site ?: "")
                    .lines()
                    .filter { it.contains(".kt:") && !it.contains("LeakTrackingFactory") }
                    .take(2)
                    .joinToString(" <- ") { it.trim().removePrefix("at ") }
            }.groupingBy { it }
            .eachCount()
            .entries
            .sortedByDescending { it.value }
            .take(6)
            .joinToString("\n") { "    ${it.value}x  ${it.key}" }

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
            // Released immediately: `slice()` is the only free-side signal buffer exposes, but it also
            // takes a reference — and since this factory now COUNTS slices, a probe that kept one would
            // corrupt the very balance [assertSlicesBalanced] measures. The measurement must not perturb
            // the thing measured.
            slice().freeIfNeeded()
            false
        } catch (_: IllegalStateException) {
            true
        }
}

// 8 KiB: comfortably above a DTLS record or an SCTP packet, and far below the pool's own 64 KiB file-I/O
// default, which would make every fixture allocate in 64 KiB steps for a 100-byte message.
private const val TRACKED_BUFFER_SIZE = 8 * 1024
private const val MAX_TRACKED_POOL = 4096

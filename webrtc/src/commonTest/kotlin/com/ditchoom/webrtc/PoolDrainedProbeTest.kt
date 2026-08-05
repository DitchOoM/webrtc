package com.ditchoom.webrtc

import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.freeIfNeeded
import kotlin.test.Test
import kotlin.test.assertFailsWith

/**
 * **The anti-vacuity check for [LeakTrackingFactory.assertPoolDrained].**
 *
 * A diagnostic needs its own proof that it detects the thing it claims to — this repo has a standing
 * lesson about that: a previous leak metric was concluded correct from a test that could not have
 * discriminated either way, and the wrong conclusion reached a commit message. So each case below
 * *injects* the condition and asserts the probe's verdict, rather than reasoning about it.
 *
 * The third case is the one that matters, and the reason `assertPoolDrained` exists at all:
 * an unreleased **slice** is invisible to [LeakTrackingFactory.assertNoLeaks] — `PooledBuffer` sets its
 * `freed` flag on the first `freeNativeMemory()` and refuses `slice()` from then on regardless of
 * refcount, so the buffer reads as "released" while its chunk has not come back. That is exactly the
 * shape of DitchOoM/socket#277 and of the decode-side pinning in `webrtc-stun`/`webrtc-sctp`.
 */
class PoolDrainedProbeTest {
    @Test
    fun a_run_that_releases_everything_passes() {
        val factory = LeakTrackingFactory()
        repeat(4) { factory.allocate(64, ByteOrder.BIG_ENDIAN).freeIfNeeded() }
        factory.assertPoolDrained("a fully-released run")
    }

    /** A missing free is [LeakTrackingFactory.assertNoLeaks]'s job — the two probes divide the work. */
    @Test
    fun a_plainly_leaked_buffer_is_caught_by_the_leak_probe() {
        val factory = LeakTrackingFactory()
        val buffer = factory.allocate(64, ByteOrder.BIG_ENDIAN)
        buffer.slice(ByteOrder.BIG_ENDIAN).freeIfNeeded() // slices balance…
        // …but the buffer itself is never freed.
        val e = assertFailsWith<AssertionError> { factory.assertNoLeaks("a run with one leak") }
        assertContains(e.message, "leaked 1 of")
        // The chunk probe catches it too — a buffer nobody freed is also a chunk that never came back.
        // `assertPoolDrained` is the STRICTLY STRONGER of the two; `assertNoLeaks` earns its keep by
        // naming *which* buffer, which a chunk count cannot.
        val stronger = assertFailsWith<AssertionError> { factory.assertPoolDrained("a run with one leak") }
        assertContains(stronger.message, "reference nobody")
    }

    /**
     * The discriminating case. The buffer IS freed — so `assertNoLeaks` is satisfied — but a slice taken
     * from it was never released, so the chunk never returns to the pool. Only the slice probe sees it.
     */
    @Test
    fun a_buffer_freed_while_a_slice_still_holds_a_reference_is_caught_only_by_the_slice_probe() {
        val factory = LeakTrackingFactory()
        val buffer = factory.allocate(64, ByteOrder.BIG_ENDIAN)
        buffer.slice(ByteOrder.BIG_ENDIAN) // +1 ref, dropped on the floor exactly as decode does
        buffer.freeIfNeeded() // the owner does its part; the refcount still never reaches zero

        // The weaker probe is satisfied — this is the blind spot, asserted rather than described.
        factory.assertNoLeaks("a freed buffer with a live slice")

        val e = assertFailsWith<AssertionError> { factory.assertPoolDrained("a freed buffer with a live slice") }
        assertContains(e.message, "reference nobody")
    }

    /**
     * **Buffer already has the fix, and it is not a new primitive — it is releasing the slice.**
     *
     * `TrackedSlice`'s own contract says so: "once the slice is released (`releaseToPool` /
     * `freeNativeMemory`) **and** the parent chunk's refcount reaches zero, the raw buffer is returned to
     * the pool's freelist". So N decode-side slices need N releases, and the arithmetic closes.
     *
     * This matters because it settles what the remaining work actually is. Closing
     * [PooledReceiveChunkTest] does **not** require a non-refcounting view upstream in `buffer` — it
     * requires the decode paths in `webrtc-stun`/`webrtc-sctp` to own the slices they take. Proven here
     * rather than assumed, on the same shape the codecs produce: slice repeatedly, release each, and the
     * chunk comes home.
     */
    @Test
    fun releasing_every_slice_returns_the_chunk_even_with_many_outstanding_views() {
        val factory = LeakTrackingFactory()
        val buffer = factory.allocate(256, ByteOrder.BIG_ENDIAN)
        // Ten sub-views, exactly as decoding ten attributes off one datagram would take.
        val slices = List(10) { buffer.slice(ByteOrder.BIG_ENDIAN) }
        slices.forEach { it.freeIfNeeded() }
        buffer.freeIfNeeded()
        factory.assertPoolDrained("a chunk whose every slice was released")
    }

    private fun assertContains(
        actual: String?,
        expected: String,
    ) {
        kotlin.test.assertEquals(
            true,
            actual?.contains(expected) == true,
            "expected the failure message to mention \"$expected\", but it was: $actual",
        )
    }
}

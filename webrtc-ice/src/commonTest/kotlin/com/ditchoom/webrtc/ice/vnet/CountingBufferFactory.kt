package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer

/**
 * A [BufferFactory] decorator that counts allocations — the seed of the directive-#6 no-leak harness.
 *
 * Every test harness threads a factory it can inspect (`TrackingBufferFactory` in the standing
 * directives). This first cut counts `allocate`/`wrap` calls so a test can assert the vnet's
 * copy-on-send accounting (exactly one allocation per delivered datagram). Full free-tracking
 * (`assertNoLeaks()`) arrives with the ICE fixtures, where deterministic/native buffers are used under
 * `use {}` and an unbalanced free is a real bug; GC-managed buffers (the default here) have no explicit
 * free to balance, so counting allocations is the meaningful invariant at this layer.
 */
internal class CountingBufferFactory(
    private val delegate: BufferFactory,
) : BufferFactory by delegate {
    var allocations: Int = 0
        private set

    var wraps: Int = 0
        private set

    /** Total buffers this factory has handed out (allocations + wraps). */
    val handedOut: Int get() = allocations + wraps

    override fun allocate(
        size: Int,
        byteOrder: ByteOrder,
    ): PlatformBuffer {
        allocations++
        return delegate.allocate(size, byteOrder)
    }

    override fun wrap(
        array: ByteArray,
        byteOrder: ByteOrder,
    ): PlatformBuffer {
        wraps++
        return delegate.wrap(array, byteOrder)
    }
}

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer

/**
 * A [BufferFactory] decorator that counts allocations — the directive-#6 accounting seam for the SCTP
 * association (mirrors the ICE `CountingBufferFactory`). Injected through [SctpConfig.bufferFactory], it
 * proves the factory is actually threaded through the hot paths (packet encode, reassembly copies, send
 * copies) and that allocation is *bounded* — proportional to real work (packets), not to the number of
 * timer ticks. GC-managed buffers have no explicit free to balance, so bounded-allocation is the
 * meaningful invariant at this layer until a published `TrackingBufferFactory` lands (W1/W3 precedent).
 */
internal class CountingBufferFactory(
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

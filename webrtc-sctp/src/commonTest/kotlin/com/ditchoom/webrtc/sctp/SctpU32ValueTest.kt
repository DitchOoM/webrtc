package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.managed
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * **`ofU32` must put the same bytes on the wire as the scratch-buffer round trip it replaced.**
 *
 * The parameters and causes whose whole value is a 32-bit word used to be built by allocating a scratch,
 * writing the word into it, handing it to `ofValue` to be copied into a *second* padded buffer, and
 * releasing the scratch — two allocations and a copy to move four bytes, and the release was the step
 * two builders here forgot. `ofU32` writes straight into the buffer that survives.
 *
 * Nothing about that may change the encoding, so every case is asserted **against the old path**
 * (`ofValue` over a scratch) rather than against a hand-written expectation, which would only assert that
 * the new code agrees with the test author. The boundary values matter because the word is written
 * unsigned and read back through `u32`: `0xFFFFFFFF` is the one that catches a signed round trip.
 */
class SctpU32ValueTest {
    private fun viaScratch(value: UInt): SctpParameter {
        val scratch = BufferFactory.managed().allocate(U32_BYTES, ByteOrder.BIG_ENDIAN)
        scratch.writeUInt(value)
        scratch.resetForRead()
        scratch.setLimit(U32_BYTES)
        return SctpParameter.ofValue(ParameterType.ZeroChecksumAcceptable, scratch)
    }

    private fun values() = listOf(0u, 1u, 0x0000_0100u, 0x8000_0000u, 0xFFFF_FFFFu, 0x1234_5678u)

    @Test
    fun ofU32MatchesTheScratchRoundTripItReplaced() {
        for (v in values()) {
            val direct = SctpParameter.ofU32(ParameterType.ZeroChecksumAcceptable, v)
            val old = viaScratch(v)
            assertEquals(old.length, direct.length, "declared length for $v")
            assertTrue(old.value.contentEquals(direct.value), "value bytes for $v")
            assertEquals(old, direct, "the parameters must be indistinguishable for $v")
        }
    }

    @Test
    fun ofU32IsBigEndianAndReadsBackThroughU32() {
        for (v in values()) {
            val p = SctpParameter.ofU32(ParameterType.HeartbeatInfo, v)
            val view = p.paddedValue
            assertEquals(v, view.u32(view.position()), "the decode is the exact inverse of the encode")
        }
    }

    /** RFC 9653 §4's decoder must accept what `zeroChecksumAcceptable` now builds without a scratch. */
    @Test
    fun zeroChecksumAcceptableStillDecodes() {
        val method = ErrorDetectionMethodId.ZeroChecksum
        val decoded = SctpParameter.zeroChecksumAcceptable(method).asZeroChecksumAcceptable()
        assertEquals(ZeroChecksumParameterDecode.Advertised(method), decoded)
    }

    /** The Invalid Stream Identifier cause is the id in the high half and two reserved zero bytes. */
    @Test
    fun invalidStreamIdentifierCauseLaysTheIdInTheHighHalf() {
        val id = 0xBEEFu
        val cause = SctpErrorCause.ofU32(ErrorCauseCode.InvalidStreamIdentifier, id shl Short.SIZE_BITS)
        val view = cause.paddedValue
        val base = view.position()
        assertEquals(U32_BYTES, cause.length)
        assertEquals(0xBEu, view.u8(base).toUInt(), "id high byte")
        assertEquals(0xEFu, view.u8(base + 1).toUInt(), "id low byte")
        assertEquals(0u, view.u8(base + 2).toUInt(), "reserved")
        assertEquals(0u, view.u8(base + 3).toUInt(), "reserved")
    }

    /** Supported Extensions is written into its padded buffer directly; the decoder must still read it. */
    @Test
    fun supportedExtensionsStillDecodes() {
        val types = listOf(SctpChunkType.ForwardTsn, SctpChunkType.ReConfig)
        val p = SctpParameter.supportedExtensions(types)
        assertEquals(types.size, p.length, "declared length is the type count, not the padded size")
        assertEquals(types, p.asSupportedExtensions())
    }
}

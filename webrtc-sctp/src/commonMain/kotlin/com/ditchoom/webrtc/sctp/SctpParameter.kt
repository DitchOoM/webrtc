package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import kotlin.jvm.JvmInline

/**
 * An INIT / INIT-ACK parameter type (RFC 4960 §3.2.1) — a 16-bit registry point wrapped so it is
 * never a bare `UShort`. Like a chunk type, the two high bits carry the [unrecognizedAction] a
 * receiver applies when it does not recognize the parameter.
 */
@JvmInline
public value class ParameterType(
    public val value: UShort,
) {
    /** RFC 4960 §3.2.1 policy for an unrecognized parameter, from the two high bits. */
    public val unrecognizedAction: UnrecognizedAction
        get() = UnrecognizedAction.ofHighBits(value.toInt() ushr PARAM_HIGH_BITS_SHIFT)

    public companion object {
        private const val PARAM_HIGH_BITS_SHIFT = 14

        public val HeartbeatInfo: ParameterType = ParameterType(1u)
        public val Ipv4Address: ParameterType = ParameterType(5u)
        public val Ipv6Address: ParameterType = ParameterType(6u)
        public val StateCookie: ParameterType = ParameterType(7u)
        public val UnrecognizedParameter: ParameterType = ParameterType(8u)
        public val CookiePreservative: ParameterType = ParameterType(9u)
        public val SupportedAddressTypes: ParameterType = ParameterType(12u)

        /** Supported Extensions (RFC 5061 §4.2.7) — the chunk types this endpoint understands. */
        public val SupportedExtensions: ParameterType = ParameterType(0x8008u)

        /** Forward-TSN-Supported (RFC 3758 §3.1) — a zero-length flag advertising PR-SCTP. */
        public val ForwardTsnSupported: ParameterType = ParameterType(0xC000u)
    }
}

/**
 * One INIT/INIT-ACK parameter as a **type + zero-copy value view** (RFC 4960 §3.2.1). The TLV framing
 * (2-byte type, 2-byte length, value, pad to a 4-byte boundary) is owned by the chunk decoder.
 *
 * Like STUN's `RawAttribute`, the construction stores [paddedValue] — the value including its trailing
 * pad to the 4-byte boundary (bounded to the chunk's declared region, so a final unpadded parameter
 * keeps only its real bytes) — so decode→encode reproduces the chunk byte-for-byte. [value] is the
 * declared-length view the typed interpreters read; [length] excludes padding. On decode both are
 * slices over the datagram (never an array — RFC §6), so a parameter must not outlive that buffer's
 * scope; the companion builders produce caller-owned buffers with zero padding.
 */
public class SctpParameter internal constructor(
    public val type: ParameterType,
    public val length: Int,
    internal val paddedValue: ReadBuffer,
) {
    /** The declared-length value view (padding excluded) — what the typed interpreters read. */
    public val value: ReadBuffer = paddedValue.sliceOf(0, minOf(length, paddedValue.remaining()))

    override fun equals(other: Any?): Boolean =
        this === other ||
            (other is SctpParameter && type == other.type && length == other.length && value.contentEquals(other.value))

    override fun hashCode(): Int = HASH_SEED * type.value.hashCode() + length

    override fun toString(): String = "SctpParameter(type=0x${type.value.toString(HEX)}, length=$length)"

    public companion object {
        private const val HASH_SEED = 31
        private const val HEX = 16

        /** Wraps a caller-built, exactly-[declared]-remaining-byte value, zero-padding to a 4-byte boundary. */
        public fun ofValue(
            type: ParameterType,
            declared: ReadBuffer,
        ): SctpParameter {
            val len = declared.remaining()
            val padded = BufferFactory.managed().allocate(paddedLength(len), ByteOrder.BIG_ENDIAN)
            val dp = declared.position()
            padded.write(declared)
            declared.position(dp)
            repeat(paddedLength(len) - len) { padded.writeByte(0) }
            padded.resetForRead()
            return SctpParameter(type, len, padded)
        }

        /** Wraps a decoded on-wire span: [paddedView] is the padding-inclusive slice, [length] the declared value length. */
        internal fun ofWire(
            type: ParameterType,
            length: Int,
            paddedView: ReadBuffer,
        ): SctpParameter = SctpParameter(type, length, paddedView)

        /** Forward-TSN-Supported (RFC 3758 §3.1) — a zero-length parameter. */
        public fun forwardTsnSupported(): SctpParameter = SctpParameter(ParameterType.ForwardTsnSupported, 0, ReadBuffer.EMPTY_BUFFER)

        /** Supported Extensions (RFC 5061 §4.2.7) — one chunk-type byte per supported extension. */
        public fun supportedExtensions(types: List<SctpChunkType>): SctpParameter {
            val buf = BufferFactory.managed().allocate(maxOf(1, types.size), ByteOrder.BIG_ENDIAN)
            for (t in types) buf.writeByte(t.value.toByte())
            buf.resetForRead()
            buf.setLimit(types.size)
            return ofValue(ParameterType.SupportedExtensions, buf)
        }
    }
}

/**
 * The chunk types listed by a Supported Extensions parameter (RFC 5061 §4.2.7), or `null` if this is
 * not that parameter. Each byte is one [SctpChunkType]; a total read (never throws on hostile length).
 */
public fun SctpParameter.asSupportedExtensions(): List<SctpChunkType>? {
    if (type != ParameterType.SupportedExtensions) return null
    val v = value
    val n = minOf(length, v.remaining())
    val out = ArrayList<SctpChunkType>(n)
    for (i in 0 until n) out += SctpChunkType(v.get(i).toUByte())
    return out
}

package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import kotlin.jvm.JvmInline

/**
 * An SCTP error-cause code (RFC 4960 §3.3.10) — a 16-bit registry point wrapped so it is never a bare
 * `UShort`. Carried by ERROR (RFC 4960 §3.3.10) and optionally by ABORT (§3.3.7). Like the other SCTP
 * registry identifiers ([SctpChunkType], [ParameterType]) it is a value class rather than an enum: the
 * wire carries an open 16-bit space, so decode stays total and byte-exact for codes we don't model
 * (the exhaustive `when` in this stack lives at the sealed [SctpChunk] layer, which drives behavior).
 */
@JvmInline
public value class ErrorCauseCode(
    public val value: UShort,
) {
    public companion object {
        public val InvalidStreamIdentifier: ErrorCauseCode = ErrorCauseCode(1u)
        public val MissingMandatoryParameter: ErrorCauseCode = ErrorCauseCode(2u)
        public val StaleCookie: ErrorCauseCode = ErrorCauseCode(3u)
        public val OutOfResource: ErrorCauseCode = ErrorCauseCode(4u)
        public val UnresolvableAddress: ErrorCauseCode = ErrorCauseCode(5u)
        public val UnrecognizedChunkType: ErrorCauseCode = ErrorCauseCode(6u)
        public val InvalidMandatoryParameter: ErrorCauseCode = ErrorCauseCode(7u)
        public val UnrecognizedParameters: ErrorCauseCode = ErrorCauseCode(8u)
        public val NoUserData: ErrorCauseCode = ErrorCauseCode(9u)
        public val CookieReceivedWhileShuttingDown: ErrorCauseCode = ErrorCauseCode(10u)
        public val RestartWithNewAddresses: ErrorCauseCode = ErrorCauseCode(11u)
        public val UserInitiatedAbort: ErrorCauseCode = ErrorCauseCode(12u)
        public val ProtocolViolation: ErrorCauseCode = ErrorCauseCode(13u)
    }
}

/**
 * One error cause as a **code + zero-copy value view** (RFC 4960 §3.3.10). The TLV framing (2-byte
 * code, 2-byte length, cause-specific info, pad to a 4-byte boundary) is owned by the chunk decoder.
 *
 * Stores [paddedValue] (padding-inclusive, bounded to the chunk region) so decode→encode is byte-exact
 * — the same discipline as [SctpParameter] / STUN's `RawAttribute`. [value] is the declared-length
 * view; [length] excludes padding. On decode both are slices over the datagram (never an array —
 * RFC §6), so a cause must not outlive that buffer's scope.
 */
public class SctpErrorCause internal constructor(
    public val code: ErrorCauseCode,
    public val length: Int,
    internal val paddedValue: ReadBuffer,
) {
    /** The declared-length value view (padding excluded). */
    public val value: ReadBuffer = paddedValue.sliceOf(0, minOf(length, paddedValue.remaining()))

    override fun equals(other: Any?): Boolean =
        this === other ||
            (other is SctpErrorCause && code == other.code && length == other.length && value.contentEquals(other.value))

    override fun hashCode(): Int = HASH_SEED * code.value.hashCode() + length

    override fun toString(): String = "SctpErrorCause(code=0x${code.value.toString(HEX)}, length=$length)"

    public companion object {
        private const val HASH_SEED = 31
        private const val HEX = 16

        /** Wraps a caller-built, exactly-[declared]-remaining-byte cause value, zero-padding to a 4-byte boundary. */
        public fun ofValue(
            code: ErrorCauseCode,
            declared: ReadBuffer,
        ): SctpErrorCause {
            val len = declared.remaining()
            val padded = BufferFactory.managed().allocate(paddedLength(len), ByteOrder.BIG_ENDIAN)
            val dp = declared.position()
            padded.write(declared)
            declared.position(dp)
            repeat(paddedLength(len) - len) { padded.writeByte(0) }
            padded.resetForRead()
            return SctpErrorCause(code, len, padded)
        }

        /** A cause with no cause-specific information (e.g. User-Initiated-Abort with no upper-layer text). */
        public fun empty(code: ErrorCauseCode): SctpErrorCause = SctpErrorCause(code, 0, ReadBuffer.EMPTY_BUFFER)

        /** Wraps a decoded on-wire span: [paddedView] is the padding-inclusive slice, [length] the declared value length. */
        internal fun ofWire(
            code: ErrorCauseCode,
            length: Int,
            paddedView: ReadBuffer,
        ): SctpErrorCause = SctpErrorCause(code, length, paddedView)
    }
}

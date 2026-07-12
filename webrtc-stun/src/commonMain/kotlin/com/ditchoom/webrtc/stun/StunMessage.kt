package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import com.ditchoom.buffer.codec.DecodeContext
import com.ditchoom.buffer.codec.EncodeContext
import com.ditchoom.buffer.crc32
import com.ditchoom.buffer.crypto.HMAC_SHA1_BYTES
import com.ditchoom.buffer.crypto.HmacSha1Mac
import com.ditchoom.buffer.crypto.constantTimeEquals
import com.ditchoom.webrtc.stun.StunDecodeResult.Reject
import com.ditchoom.webrtc.stun.StunDecodeResult.Success

/**
 * A decoded or hand-built STUN message (RFC 8489 §5): a [StunHeader] and its ordered [attributes].
 * The TLV attribute layer is hand-written — STUN's 4-byte value padding and the MESSAGE-INTEGRITY /
 * FINGERPRINT computations (which cover byte ranges with a rewritten length field) are outside what
 * the declarative codec expresses — while the 20-byte header rides the KSP-generated [StunHeaderCodec].
 *
 * Decoding is zero-copy: every attribute [value][RawAttribute.value] is a slice over [source], so a
 * decoded message must not outlive that datagram's scope. [verifyMessageIntegrity] / [verifyFingerprint]
 * read those same bytes in place. Build outgoing messages with [StunMessageBuilder].
 */
public class StunMessage internal constructor(
    public val header: StunHeader,
    public val attributes: List<RawAttribute>,
    private val source: ReadBuffer?,
    private val sourceStart: Int,
    private val messageIntegrityOffset: Int?,
    private val fingerprintOffset: Int?,
) {
    public val messageType: StunMessageType get() = header.messageType
    public val transactionId: TransactionId get() = header.transactionId

    /** The first attribute of [type], or null if absent. */
    public fun firstOrNull(type: StunAttributeType): RawAttribute? = attributes.firstOrNull { it.type == type }

    /**
     * The comprehension-required attribute types present that are not in [recognized] (RFC 8489 §6.3):
     * a receiver that hits any of these must reply 420 with UNKNOWN-ATTRIBUTES listing them. Drives
     * that response at the ICE/TURN layer (W3).
     */
    public fun unknownComprehensionRequired(recognized: Set<StunAttributeType>): List<StunAttributeType> =
        attributes
            .asSequence()
            .map { it.type }
            .filter { it.isComprehensionRequired && it !in recognized }
            .distinct()
            .toList()

    /**
     * Recomputes FINGERPRINT (RFC 8489 §14.7) over the decoded bytes and compares it to the value on
     * the wire. Returns false if there is no FINGERPRINT attribute or this message was not decoded
     * from a buffer. CRC-32 of the message up to the attribute, XOR 0x5354554E.
     */
    public fun verifyFingerprint(): Boolean {
        val src = source ?: return false
        val fpAt = fingerprintOffset ?: return false
        // A conforming FINGERPRINT value is exactly 4 bytes; a malformed short length would make the
        // fixed-size read below run off the datagram (Jazzer regression). Reject rather than throw.
        if (src.u16be(fpAt + TYPE_FIELD_BYTES) != UINT_BYTES) return false
        val computed = src.crc32(sourceStart, fpAt - sourceStart) xor FINGERPRINT_XOR
        return computed == src.u32be(fpAt + TLV_HEADER_BYTES)
    }

    /**
     * Recomputes MESSAGE-INTEGRITY (RFC 8489 §14.5) with [key] and compares it to the value on the
     * wire. Returns false if there is no MESSAGE-INTEGRITY attribute or this message was not decoded.
     *
     * HMAC-SHA1 over the message up to (excluding) the attribute, but with the header length field
     * **rewritten** to cover through the MESSAGE-INTEGRITY attribute (so a trailing FINGERPRINT does
     * not perturb it). Fed to the MAC in three slices — no mutation of the datagram, no full copy.
     */
    public fun verifyMessageIntegrity(key: ReadBuffer): Boolean {
        val src = source ?: return false
        val miAt = messageIntegrityOffset ?: return false
        // A conforming MESSAGE-INTEGRITY value is exactly 20 bytes (HMAC-SHA1); a malformed short
        // length would make the 20-byte compare below run off the datagram (Jazzer regression).
        if (src.u16be(miAt + TYPE_FIELD_BYTES) != HMAC_SHA1_BYTES) return false
        val patchedLength = (miAt - (sourceStart + StunHeader.SIZE_BYTES)) + MESSAGE_INTEGRITY_TLV_BYTES
        val patched = BufferFactory.Default.allocate(LENGTH_FIELD_BYTES, ByteOrder.BIG_ENDIAN)
        patched.writeUShort(patchedLength.toUShort())
        patched.resetForRead()

        val out = BufferFactory.Default.allocate(HMAC_SHA1_BYTES, ByteOrder.BIG_ENDIAN)
        HmacSha1Mac(key)
            .update(src.sliceOf(sourceStart, sourceStart + TYPE_FIELD_BYTES)) // message type
            .update(patched) // rewritten length
            .update(src.sliceOf(sourceStart + TYPE_FIELD_BYTES + LENGTH_FIELD_BYTES, miAt)) // cookie‖txid‖attrs
            .doFinalInto(out)
        out.resetForRead()
        // Constant-time compare: a short-circuiting compare of a secret-derived MAC against an
        // attacker-supplied value is a timing oracle enabling byte-by-byte forgery.
        val onWire = src.sliceOf(miAt + TLV_HEADER_BYTES, miAt + TLV_HEADER_BYTES + HMAC_SHA1_BYTES)
        return out.constantTimeEquals(onWire)
    }

    /**
     * Serializes this message (header + attributes, each value padded to a 4-byte boundary) into a
     * freshly allocated read-ready buffer. The header length is derived from the attributes, so a
     * decoded message re-encodes byte-for-byte.
     */
    public fun encode(factory: BufferFactory = BufferFactory.Default): PlatformBuffer {
        val attrBytes = attributes.sumOf { TLV_HEADER_BYTES + paddedLength(it.length) }
        val dest = factory.allocate(StunHeader.SIZE_BYTES + attrBytes, ByteOrder.BIG_ENDIAN)
        writeInto(dest, header.copy(messageLength = attrBytes.toUShort()), attributes)
        dest.resetForRead()
        return dest
    }

    public companion object {
        /** FINGERPRINT XOR constant (RFC 8489 §14.7). */
        public const val FINGERPRINT_XOR: UInt = 0x5354554Eu

        internal const val TLV_HEADER_BYTES = 4 // attribute type(2) + length(2)
        private const val TYPE_FIELD_BYTES = 2
        private const val LENGTH_FIELD_BYTES = 2
        private const val ALIGNMENT = 4
        private const val UINT_BYTES = 4 // the FINGERPRINT value is a single u32 CRC (RFC 8489 §14.7)
        private const val MESSAGE_INTEGRITY_TLV_BYTES = TLV_HEADER_BYTES + HMAC_SHA1_BYTES // 24

        /** Padded on-wire length of a [len]-byte value (RFC 8489 §14: pad to a 4-byte boundary). */
        internal fun paddedLength(len: Int): Int = len + ((ALIGNMENT - (len % ALIGNMENT)) % ALIGNMENT)

        /**
         * Parses one STUN message from [source] (starting at its current position). Never throws on a
         * malformed datagram — every failure is a typed [Reject]. On success the attribute values are
         * zero-copy slices over [source].
         */
        public fun decode(source: ReadBuffer): StunDecodeResult {
            val start = source.position()
            if (source.limit() - start < StunHeader.SIZE_BYTES) return Reject(StunRejectReason.ShorterThanHeader)

            val header =
                try {
                    StunHeaderCodec.decode(source, DecodeContext.Empty)
                } catch (_: IllegalArgumentException) {
                    // The only guarded construction on the header path is StunMessageType's
                    // leading-bits invariant → not a STUN message.
                    return Reject(StunRejectReason.NotStunMethod)
                }
            if (header.magicCookie != Stun.MAGIC_COOKIE) {
                return Reject(StunRejectReason.BadMagicCookie(header.magicCookie))
            }
            val attrLen = header.messageLength.toInt()
            if (attrLen % ALIGNMENT != 0) return Reject(StunRejectReason.LengthNotAligned(attrLen))

            val attrStart = start + StunHeader.SIZE_BYTES
            val attrEnd = attrStart + attrLen
            if (attrEnd > source.limit()) {
                return Reject(StunRejectReason.Truncated(needed = attrEnd - start, available = source.limit() - start))
            }

            val attributes = mutableListOf<RawAttribute>()
            var miOffset: Int? = null
            var fpOffset: Int? = null
            var pos = attrStart
            while (pos < attrEnd) {
                if (pos + TLV_HEADER_BYTES > attrEnd) return Reject(StunRejectReason.MalformedAttribute(pos))
                val type = StunAttributeType(source.u16be(pos).toUShort())
                val len = source.u16be(pos + TYPE_FIELD_BYTES)
                val valueStart = pos + TLV_HEADER_BYTES
                val paddedEnd = valueStart + paddedLength(len)
                if (paddedEnd > attrEnd) return Reject(StunRejectReason.MalformedAttribute(pos))
                attributes += RawAttribute.ofWire(type, len, source.sliceOf(valueStart, paddedEnd))
                if (type == StunAttributeType.MessageIntegrity && miOffset == null) miOffset = pos
                if (type == StunAttributeType.Fingerprint && fpOffset == null) fpOffset = pos
                pos = paddedEnd
            }
            if (pos != attrEnd) return Reject(StunRejectReason.MalformedAttribute(pos))

            return Success(StunMessage(header, attributes, source, start, miOffset, fpOffset))
        }

        /** Writes [header] then each attribute (type, length, value, zero-padding). */
        internal fun writeInto(
            dest: WriteBuffer,
            header: StunHeader,
            attributes: List<RawAttribute>,
        ) {
            StunHeaderCodec.encode(dest, header, EncodeContext.Empty)
            for (attr in attributes) {
                dest.writeUShort(attr.type.value)
                dest.writeUShort(attr.length.toUShort())
                // paddedValue already carries the 4-byte-boundary padding (real bytes for a decoded
                // attribute, zeros for a built one), so MESSAGE-INTEGRITY over it stays valid.
                val pv = attr.paddedValue
                val p = pv.position()
                dest.write(pv)
                pv.position(p)
            }
        }
    }
}

/** Big-endian absolute 16-bit read — byte-order-independent, for the TLV walk. */
internal fun ReadBuffer.u16be(index: Int): Int = ((get(index).toInt() and 0xFF) shl Byte.SIZE_BITS) or (get(index + 1).toInt() and 0xFF)

/** Big-endian absolute 32-bit read. */
internal fun ReadBuffer.u32be(index: Int): UInt = ((u16be(index).toLong() shl Short.SIZE_BITS) or u16be(index + 2).toLong()).toUInt()

/**
 * A zero-copy big-endian slice view of `[start, endExclusive)` that does **not** disturb this
 * buffer's position/limit. The slice shares storage (the slice-lifetime contract applies).
 */
internal fun ReadBuffer.sliceOf(
    start: Int,
    endExclusive: Int,
): ReadBuffer {
    val savedPos = position()
    val savedLimit = limit()
    position(0)
    setLimit(endExclusive)
    position(start)
    val view = slice(ByteOrder.BIG_ENDIAN)
    position(0)
    setLimit(savedLimit)
    position(savedPos)
    return view
}

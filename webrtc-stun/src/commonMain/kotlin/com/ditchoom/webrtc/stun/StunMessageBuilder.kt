package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.crc32
import com.ditchoom.buffer.crypto.HMAC_SHA1_BYTES
import com.ditchoom.buffer.crypto.HMAC_SHA256_BYTES
import com.ditchoom.buffer.crypto.hmacSha1
import com.ditchoom.buffer.crypto.hmacSha256

/**
 * Assembles an outgoing STUN message (RFC 8489). Add attributes in wire order, then optionally
 * [addMessageIntegrity] and [addFingerprint] **last, in that order** — each is computed over the
 * message as serialized so far with the header length rewritten to cover the attribute being added
 * (RFC 8489 §14.5, §14.7), which is exactly what makes them verify on the far side.
 */
public class StunMessageBuilder(
    private val messageType: StunMessageType,
    private val transactionId: TransactionId,
) {
    private val attributes = mutableListOf<RawAttribute>()

    public fun add(attribute: RawAttribute): StunMessageBuilder {
        attributes += attribute
        return this
    }

    /** Appends MESSAGE-INTEGRITY (HMAC-SHA1 under [key]) over everything added so far. */
    public fun addMessageIntegrity(key: ReadBuffer): StunMessageBuilder {
        requireNoFingerprintYet("MESSAGE-INTEGRITY")
        val prefix = serializePrefix(lengthAddend = MESSAGE_INTEGRITY_TLV_BYTES)
        attributes += RawAttribute.ofValue(StunAttributeType.MessageIntegrity, hmacSha1(key, prefix, BufferFactory.Default))
        return this
    }

    /**
     * Appends MESSAGE-INTEGRITY-SHA256 (HMAC-SHA256 under [key], RFC 8489 §14.6) over everything added
     * so far. [tagLengthBytes] defaults to the full 32-byte tag; a STUN Usage that negotiated
     * truncation may pass a smaller multiple of 4 in 16..32. Add after [addMessageIntegrity] when both
     * are present, and before [addFingerprint].
     */
    public fun addMessageIntegritySha256(
        key: ReadBuffer,
        tagLengthBytes: Int = HMAC_SHA256_BYTES,
    ): StunMessageBuilder {
        require(tagLengthBytes in MIN_SHA256_MI_BYTES..HMAC_SHA256_BYTES && tagLengthBytes % ALIGNMENT == 0) {
            "MESSAGE-INTEGRITY-SHA256 tag must be a multiple of 4 in $MIN_SHA256_MI_BYTES..$HMAC_SHA256_BYTES, got $tagLengthBytes"
        }
        requireNoFingerprintYet("MESSAGE-INTEGRITY-SHA256")
        val prefix = serializePrefix(lengthAddend = StunMessage.TLV_HEADER_BYTES + tagLengthBytes)
        val full = hmacSha256(key, prefix, BufferFactory.Default)
        val tag = if (tagLengthBytes == HMAC_SHA256_BYTES) full else full.sliceOf(0, tagLengthBytes)
        attributes += RawAttribute.ofValue(StunAttributeType.MessageIntegritySha256, tag)
        return this
    }

    // FINGERPRINT must be the last attribute (RFC 8489 §14.7) and MESSAGE-INTEGRITY* must precede it,
    // else the far side's checks silently fail to verify. Make the misuse a typed error, not a mystery.
    private fun requireNoFingerprintYet(what: String) {
        require(attributes.none { it.type == StunAttributeType.Fingerprint }) {
            "$what must be added before FINGERPRINT (FINGERPRINT must be the last attribute)"
        }
    }

    /** Appends FINGERPRINT (CRC-32 XOR 0x5354554E) over everything added so far. */
    public fun addFingerprint(): StunMessageBuilder {
        val prefix = serializePrefix(lengthAddend = FINGERPRINT_TLV_BYTES)
        val crc = prefix.crc32() xor StunMessage.FINGERPRINT_XOR
        val value = BufferFactory.Default.allocate(UINT_BYTES, ByteOrder.BIG_ENDIAN)
        value.writeUInt(crc)
        value.resetForRead()
        attributes += RawAttribute.ofValue(StunAttributeType.Fingerprint, value)
        return this
    }

    /** The finished message (source-less; serialize it with [StunMessage.encode]). */
    public fun build(): StunMessage {
        val attrBytes = attributes.sumOf { StunMessage.TLV_HEADER_BYTES + StunMessage.paddedLength(it.length) }
        val header = StunHeader(messageType, attrBytes.toUShort(), Stun.MAGIC_COOKIE, transactionId)
        return StunMessage(header, attributes.toList(), source = null, sourceStart = 0, null, null, null)
    }

    /** Convenience: build then [StunMessage.encode]. */
    public fun encode(factory: BufferFactory = BufferFactory.Default): com.ditchoom.buffer.PlatformBuffer = build().encode(factory)

    // Serializes header + current attributes into a read-ready buffer, with the header length field
    // set to (current attribute bytes + the about-to-be-added attribute's wire size) — the length the
    // integrity computation must see (RFC 8489 §14.5/§14.7).
    private fun serializePrefix(lengthAddend: Int): ReadBuffer {
        val attrBytes = attributes.sumOf { StunMessage.TLV_HEADER_BYTES + StunMessage.paddedLength(it.length) }
        val header = StunHeader(messageType, (attrBytes + lengthAddend).toUShort(), Stun.MAGIC_COOKIE, transactionId)
        val scratch = BufferFactory.Default.allocate(StunHeader.SIZE_BYTES + attrBytes, ByteOrder.BIG_ENDIAN)
        StunMessage.writeInto(scratch, header, attributes)
        scratch.resetForRead()
        return scratch
    }

    public companion object {
        private const val UINT_BYTES = 4
        private const val FINGERPRINT_TLV_BYTES = StunMessage.TLV_HEADER_BYTES + UINT_BYTES // 8
        private const val MESSAGE_INTEGRITY_TLV_BYTES = StunMessage.TLV_HEADER_BYTES + HMAC_SHA1_BYTES // 24
        private const val ALIGNMENT = 4 // STUN attribute 4-byte boundary (RFC 8489 §14)
        private const val MIN_SHA256_MI_BYTES = 16 // smallest negotiable MI-SHA256 tag (RFC 8489 §14.6)

        /** Starts a builder for `(stunClass, method)` with the given transaction id. */
        public fun of(
            stunClass: StunClass,
            method: StunMethod,
            transactionId: TransactionId,
        ): StunMessageBuilder = StunMessageBuilder(StunMessageType.of(stunClass, method), transactionId)
    }
}

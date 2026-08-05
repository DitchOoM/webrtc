package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
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
    /**
     * Allocator for every scratch buffer this builder makes — the integrity/fingerprint prefixes and
     * attribute values. A constructor-injected seam with a production default (directive #2): a caller
     * that hands the stack a pooled or tracking factory gets it used HERE too, rather than silently
     * bypassed by a hardwired `BufferFactory.Default`.
     */
    private val factory: BufferFactory = BufferFactory.Default,
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
        val tag = hmacSha1(key, prefix, factory)
        // The prefix exists only to be hashed. Nothing downstream holds it — the tag is a fresh buffer,
        // not a view — so it is released here rather than left for a GC that a native factory does not
        // have. One of these per check, forever, is a measurable share of a session's allocations.
        prefix.freeNativeMemory()
        attributes += RawAttribute.ofValue(StunAttributeType.MessageIntegrity, tag, factory)
        tag.releaseIfOwnable() // ofValue COPIED it; nothing refers to the raw tag any more
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
        val full = hmacSha256(key, prefix, factory)
        // As in [addMessageIntegrity]: the hashed prefix is scratch and is released here. `full` is NOT
        // — a truncated tag is a *slice* of it, so freeing it would hand the attribute a view of memory
        // the allocator has taken back.
        prefix.freeNativeMemory()
        val tag = if (tagLengthBytes == HMAC_SHA256_BYTES) full else full.sliceOf(0, tagLengthBytes)
        attributes += RawAttribute.ofValue(StunAttributeType.MessageIntegritySha256, tag, factory)
        // Free `full`, not `tag`: a truncated tag is a slice OF full, so full is the allocation and it
        // is unreferenced only now, after ofValue copied the bytes out of it.
        full.releaseIfOwnable()
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
        prefix.freeNativeMemory() // scratch, hashed and done with — see [addMessageIntegrity]
        val value = factory.allocate(UINT_BYTES, ByteOrder.BIG_ENDIAN)
        value.writeUInt(crc)
        value.resetForRead()
        attributes += RawAttribute.ofValue(StunAttributeType.Fingerprint, value, factory)
        value.freeNativeMemory() // as above: copied, not retained
        return this
    }

    /** The finished message (source-less; serialize it with [StunMessage.encode]). */
    public fun build(): StunMessage {
        val attrBytes = attributes.sumOf { StunMessage.TLV_HEADER_BYTES + StunMessage.paddedLength(it.length) }
        val header = StunHeader(messageType, attrBytes.toUShort(), Stun.MAGIC_COOKIE, transactionId)
        return StunMessage(header, attributes.toList(), source = null, sourceStart = 0, null, null, null)
    }

    /**
     * Convenience: [build] then [StunMessage.encode] — and **the terminal operation on this builder**,
     * which is what makes it the right place to release the attribute values it allocated.
     *
     * Every attribute the companion builders produced holds a buffer whose only purpose was to be
     * serialized into the message this returns. Once those bytes are written, nothing refers to it: the
     * returned buffer is a fresh allocation, not a view. Decoded attributes are untouched — they are
     * slices over someone else's datagram, and [RawAttribute.owned] is how the two are told apart.
     *
     * Do not reuse a builder after this. `build()` alone still hands ownership to the caller.
     */
    public fun encode(factory: BufferFactory = this.factory): PlatformBuffer {
        val encoded = build().encode(factory)
        for (attribute in attributes) attribute.releaseViews()
        return encoded
    }

    // Serializes header + current attributes into a read-ready buffer, with the header length field
    // set to (current attribute bytes + the about-to-be-added attribute's wire size) — the length the
    // integrity computation must see (RFC 8489 §14.5/§14.7).
    private fun serializePrefix(lengthAddend: Int): PlatformBuffer {
        val attrBytes = attributes.sumOf { StunMessage.TLV_HEADER_BYTES + StunMessage.paddedLength(it.length) }
        val header = StunHeader(messageType, (attrBytes + lengthAddend).toUShort(), Stun.MAGIC_COOKIE, transactionId)
        val scratch = factory.allocate(StunHeader.SIZE_BYTES + attrBytes, ByteOrder.BIG_ENDIAN)
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
            factory: BufferFactory = BufferFactory.Default,
        ): StunMessageBuilder = StunMessageBuilder(StunMessageType.of(stunClass, method), transactionId, factory)
    }
}

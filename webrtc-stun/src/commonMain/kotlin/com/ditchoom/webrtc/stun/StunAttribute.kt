package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer

/**
 * One STUN attribute as a **type + zero-copy value view** (RFC 8489 §14). The TLV framing (2-byte
 * type, 2-byte length, value, pad to a 4-byte boundary) is owned by [StunMessage].
 *
 * The construction stores [paddedValue] — the value rounded up to the 4-byte boundary — because
 * MESSAGE-INTEGRITY / FINGERPRINT are computed over the padding bytes too (RFC 8489 §14.5): a
 * received signed message must re-emit its exact padding or its integrity breaks. [value] is the
 * declared-length view the typed interpreters read; [length] excludes padding. On decode both are
 * slices over the datagram (ARCHITECTURE §6 — never an array), so a `RawAttribute` must not outlive that
 * buffer's scope; the [companion] builders produce caller-owned buffers with zero padding.
 */
public class RawAttribute internal constructor(
    public val type: StunAttributeType,
    public val length: Int,
    internal val paddedValue: ReadBuffer,
    /**
     * Whether [paddedValue] is **ours to free**, which is the whole built-vs-parsed distinction the
     * class KDoc describes, made explicit so a release path cannot get it wrong.
     *
     * A built attribute owns a buffer the companion allocated for it, and nothing else refers to that
     * buffer once the message is serialized. A **decoded** one is a slice over the received datagram,
     * shared with every other attribute in the message and with the datagram itself — freeing that
     * would hand the rest of the parse a view of reclaimed memory. Hence `false` by default: the
     * dangerous direction is the one you get by forgetting.
     */
    internal val owned: Boolean = false,
) {
    /** The declared-length value view (padding excluded) — what the typed interpreters read. */
    public val value: ReadBuffer = paddedValue.sliceOf(0, length)

    /**
     * Give back **every** buffer reference this attribute took — both the [value] view and, when this
     * attribute owns it, [paddedValue] itself. Idempotent-by-construction: called once, from
     * [StunMessageBuilder.encode] for a built attribute and from [StunMessage.release] for a decoded one.
     *
     * ## Why [value] is released in both cases, and why it used to be released in neither
     *
     * [value] is a sub-view this class creates in its **constructor**, so it exists for every attribute
     * whether or not anyone reads it. On a pooled buffer `slice()` is `addRef()`, and `TrackedSlice`
     * re-parents to the *root* chunk — so the reference is against the datagram (decoded) or against
     * [paddedValue] (built), and in both cases it is ours and nobody else's to return. Releasing only
     * [paddedValue], which is what this method used to do, left that second reference outstanding
     * forever: a built attribute went 2 → 1 and a decoded one left the datagram pinned.
     *
     * ## Why releasing a decoded [paddedValue] is safe — the `owned = false` KDoc still holds
     *
     * That flag says "not ours to **free**", and it is still right: a decoded [paddedValue] is a slice
     * over a datagram shared with every other attribute, so *freeing the datagram* here would hand the
     * rest of the parse reclaimed memory. Releasing the **slice** is a different act — it returns the one
     * reference this attribute took and nothing else. On a pooled parent it decrements; on a plain
     * native buffer `NativeBufferSlice.freeNativeMemory()` is a documented no-op, so it costs nothing.
     * The datagram is still freed exactly once, by its own owner, under the last-reader rule.
     */
    internal fun releaseViews() {
        value.releaseIfOwnable()
        paddedValue.releaseIfOwnable()
    }

    override fun equals(other: Any?): Boolean =
        this === other ||
            (other is RawAttribute && type == other.type && length == other.length && value.contentEquals(other.value))

    override fun hashCode(): Int = HASH_SEED * type.hashCode() + length

    override fun toString(): String = "RawAttribute(type=0x${type.value.toString(HEX)}, length=$length)"

    public companion object {
        private const val HASH_SEED = 31
        private const val HEX = 16
        private const val ADDR_HEADER_BYTES = 4 // reserved(1) + family(1) + port(2)
        private const val PORT_XOR: Int = 0x2112 // magic cookie high half (RFC 8489 §14.2)
        private const val ERROR_CLASS_DIVISOR = 100
        private const val UINT_BITS = 32

        /**
         * Wraps a caller-built [value] as an attribute of [type], padding to the 4-byte boundary — the
         * public escape hatch for attributes that have no typed builder here. ICE (RFC 8445 §7.1) adds
         * PRIORITY, USE-CANDIDATE, and ICE-CONTROLLED/ICE-CONTROLLING in the `webrtc-ice` module without
         * webrtc-stun having to know their shapes; the [StunAttributeType] ctor is already public, so a
         * caller supplies `StunAttributeType(0x0024u)` and the value bytes. The value is copied, so the
         * result is caller-owned and outlives any source buffer.
         */
        public fun ofRaw(
            type: StunAttributeType,
            value: ReadBuffer,
        ): RawAttribute = ofValue(type, value)

        /**
         * An attribute of [type] carrying the XOR-MAPPED-ADDRESS wire form (RFC 8489 §14.2) of
         * [address]. TURN's XOR-PEER-ADDRESS and XOR-RELAYED-ADDRESS (RFC 8656 §14.3/§14.5) reuse that
         * exact encoding, so this one builder serves all three; decode any of them with
         * [asXorMappedAddress], which reads the value regardless of the declared type.
         */
        public fun ofXorAddress(
            type: StunAttributeType,
            address: TransportAddress,
            transactionId: TransactionId,
            factory: BufferFactory = BufferFactory.Default,
        ): RawAttribute = ofScratch(type, encodeAddress(address, xorWith = transactionId, factory = factory), factory)

        /** Wraps a caller-built, exactly-[length]-byte value, padding it to a 4-byte boundary with zeros. */
        internal fun ofValue(
            type: StunAttributeType,
            declared: ReadBuffer,
            factory: BufferFactory = BufferFactory.Default,
        ): RawAttribute {
            val len = declared.remaining()
            val padded = factory.allocate(StunMessage.paddedLength(len), ByteOrder.BIG_ENDIAN)
            val dp = declared.position()
            padded.write(declared)
            declared.position(dp)
            repeat(StunMessage.paddedLength(len) - len) { padded.writeByte(0) }
            padded.resetForRead()
            // `declared` is COPIED here, never retained — which is what lets each internal caller below
            // free the scratch it built to feed this, and what stops `ofRaw` from consuming a buffer its
            // public caller still owns.
            return RawAttribute(type, len, padded, owned = true)
        }

        /**
         * [ofValue], plus the release of the scratch buffer that was built only to feed it.
         *
         * Every typed builder below has the same shape: allocate a buffer, lay the wire form into it,
         * hand it to [ofValue] — which **copies** — and then hold no further reference to it. Doing that
         * release at each site is what made an attribute cost two live allocations instead of one, so it
         * is done here once. Not used by [ofRaw]: that value belongs to a public caller.
         */
        internal fun ofScratch(
            type: StunAttributeType,
            scratch: ReadBuffer,
            factory: BufferFactory,
        ): RawAttribute = ofValue(type, scratch, factory).also { scratch.releaseIfOwnable() }

        /** Wraps a decoded on-wire span: [paddedView] is the padding-inclusive slice, [length] the declared value length. */
        internal fun ofWire(
            type: StunAttributeType,
            length: Int,
            paddedView: ReadBuffer,
        ): RawAttribute = RawAttribute(type, length, paddedView)

        /** UTF-8 text attribute (USERNAME/REALM/NONCE/SOFTWARE), value = the string's bytes. */
        public fun ofText(
            type: StunAttributeType,
            text: String,
            factory: BufferFactory = BufferFactory.Default,
        ): RawAttribute {
            val bytes = factory.allocate(utf8Size(text), ByteOrder.BIG_ENDIAN)
            bytes.writeString(text, Charset.UTF8)
            bytes.resetForRead()
            return ofScratch(type, bytes, factory)
        }

        /** MAPPED-ADDRESS (RFC 8489 §14.1) — plaintext family/port/address. */
        public fun ofMappedAddress(
            address: TransportAddress,
            factory: BufferFactory = BufferFactory.Default,
        ): RawAttribute = ofScratch(StunAttributeType.MappedAddress, encodeAddress(address, xorWith = null, factory = factory), factory)

        /**
         * XOR-MAPPED-ADDRESS (RFC 8489 §14.2) — port XOR'd with the cookie's high half, address
         * XOR'd with the cookie (IPv4) or cookie‖transaction-id (IPv6).
         */
        public fun ofXorMappedAddress(
            address: TransportAddress,
            transactionId: TransactionId,
            factory: BufferFactory = BufferFactory.Default,
        ): RawAttribute =
            ofScratch(
                StunAttributeType.XorMappedAddress,
                encodeAddress(address, xorWith = transactionId, factory = factory),
                factory,
            )

        /** ERROR-CODE (RFC 8489 §14.8). */
        public fun ofErrorCode(
            error: StunErrorCode,
            factory: BufferFactory = BufferFactory.Default,
        ): RawAttribute {
            val reason = error.reason
            val body = factory.allocate(ADDR_HEADER_BYTES + utf8Size(reason), ByteOrder.BIG_ENDIAN)
            body.writeShort(0) // 2 reserved bytes
            body.writeByte((error.code / ERROR_CLASS_DIVISOR).toByte()) // class (3..6)
            body.writeByte((error.code % ERROR_CLASS_DIVISOR).toByte()) // number (0..99)
            body.writeString(reason, Charset.UTF8)
            body.resetForRead()
            return ofScratch(StunAttributeType.ErrorCode, body, factory)
        }

        internal fun ipv6XorKey(transactionId: TransactionId?): Pair<ULong, ULong> {
            if (transactionId == null) return 0uL to 0uL
            val khi = (Stun.MAGIC_COOKIE.toULong() shl UINT_BITS) or transactionId.w0.toULong()
            val klo = (transactionId.w1.toULong() shl UINT_BITS) or transactionId.w2.toULong()
            return khi to klo
        }

        private fun encodeAddress(
            address: TransportAddress,
            xorWith: TransactionId?,
            factory: BufferFactory = BufferFactory.Default,
        ): ReadBuffer {
            val ip = address.ip
            val buf = factory.allocate(ADDR_HEADER_BYTES + ipSize(ip), ByteOrder.BIG_ENDIAN)
            buf.writeByte(0) // reserved
            buf.writeUByte(ip.family)
            val portMask = if (xorWith != null) PORT_XOR else 0
            buf.writeUShort((address.port.toInt() xor portMask).toUShort())
            when (ip) {
                is IpAddress.V4 -> buf.writeUInt(ip.bits xor if (xorWith != null) Stun.MAGIC_COOKIE else 0u)
                is IpAddress.V6 -> {
                    val (khi, klo) = ipv6XorKey(xorWith)
                    buf.writeULong(ip.hi xor khi)
                    buf.writeULong(ip.lo xor klo)
                }
            }
            buf.resetForRead()
            return buf
        }

        private fun ipSize(ip: IpAddress): Int =
            when (ip) {
                is IpAddress.V4 -> IpAddress.V4.SIZE_BYTES
                is IpAddress.V6 -> IpAddress.V6.SIZE_BYTES
            }

        // UTF-8 byte length without allocating (STUN text attributes are OpaqueString/qdtext).
        private fun utf8Size(text: String): Int {
            var n = 0
            for (c in text) {
                val cp = c.code
                n +=
                    when {
                        cp < 0x80 -> 1
                        cp < 0x800 -> 2
                        else -> 3
                    }
            }
            return n
        }
    }
}

/**
 * A parsed ERROR-CODE (RFC 8489 §14.8): [code] is the composed value (class×100 + number, e.g. 401),
 * [reason] the UTF-8 phrase.
 */
public data class StunErrorCode(
    public val code: Int,
    public val reason: String,
)

/**
 * Return this buffer's memory to whatever allocated it, if it is memory we can return at all.
 *
 * buffer's crypto and slice APIs answer the read-only [ReadBuffer]; only a [PlatformBuffer] carries
 * `freeNativeMemory()`. Every buffer this module allocates *is* a `PlatformBuffer`, so the check costs
 * nothing on the paths that matter and makes the call a no-op on a view that was never ours — which is
 * the safe direction to fail in.
 */
internal fun ReadBuffer.releaseIfOwnable() {
    if (this is PlatformBuffer) freeNativeMemory()
}

package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer

/**
 * One STUN attribute as a **type + zero-copy value view** (RFC 8489 §14). The TLV framing (2-byte
 * type, 2-byte length, value, pad to a 4-byte boundary) is owned by [StunMessage].
 *
 * The construction stores [paddedValue] — the value rounded up to the 4-byte boundary — because
 * MESSAGE-INTEGRITY / FINGERPRINT are computed over the padding bytes too (RFC 8489 §14.5): a
 * received signed message must re-emit its exact padding or its integrity breaks. [value] is the
 * declared-length view the typed interpreters read; [length] excludes padding. On decode both are
 * slices over the datagram (RFC §6 — never an array), so a `RawAttribute` must not outlive that
 * buffer's scope; the [companion] builders produce caller-owned buffers with zero padding.
 */
public class RawAttribute internal constructor(
    public val type: StunAttributeType,
    public val length: Int,
    internal val paddedValue: ReadBuffer,
) {
    /** The declared-length value view (padding excluded) — what the typed interpreters read. */
    public val value: ReadBuffer = paddedValue.sliceOf(0, length)

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
        ): RawAttribute = ofValue(type, encodeAddress(address, xorWith = transactionId))

        /** Wraps a caller-built, exactly-[length]-byte value, padding it to a 4-byte boundary with zeros. */
        internal fun ofValue(
            type: StunAttributeType,
            declared: ReadBuffer,
        ): RawAttribute {
            val len = declared.remaining()
            val padded = BufferFactory.Default.allocate(StunMessage.paddedLength(len), ByteOrder.BIG_ENDIAN)
            val dp = declared.position()
            padded.write(declared)
            declared.position(dp)
            repeat(StunMessage.paddedLength(len) - len) { padded.writeByte(0) }
            padded.resetForRead()
            return RawAttribute(type, len, padded)
        }

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
        ): RawAttribute {
            val bytes = BufferFactory.Default.allocate(utf8Size(text), ByteOrder.BIG_ENDIAN)
            bytes.writeString(text, Charset.UTF8)
            bytes.resetForRead()
            return ofValue(type, bytes)
        }

        /** MAPPED-ADDRESS (RFC 8489 §14.1) — plaintext family/port/address. */
        public fun ofMappedAddress(address: TransportAddress): RawAttribute =
            ofValue(StunAttributeType.MappedAddress, encodeAddress(address, xorWith = null))

        /**
         * XOR-MAPPED-ADDRESS (RFC 8489 §14.2) — port XOR'd with the cookie's high half, address
         * XOR'd with the cookie (IPv4) or cookie‖transaction-id (IPv6).
         */
        public fun ofXorMappedAddress(
            address: TransportAddress,
            transactionId: TransactionId,
        ): RawAttribute = ofValue(StunAttributeType.XorMappedAddress, encodeAddress(address, xorWith = transactionId))

        /** ERROR-CODE (RFC 8489 §14.8). */
        public fun ofErrorCode(error: StunErrorCode): RawAttribute {
            val reason = error.reason
            val body = BufferFactory.Default.allocate(ADDR_HEADER_BYTES + utf8Size(reason), ByteOrder.BIG_ENDIAN)
            body.writeShort(0) // 2 reserved bytes
            body.writeByte((error.code / ERROR_CLASS_DIVISOR).toByte()) // class (3..6)
            body.writeByte((error.code % ERROR_CLASS_DIVISOR).toByte()) // number (0..99)
            body.writeString(reason, Charset.UTF8)
            body.resetForRead()
            return ofValue(StunAttributeType.ErrorCode, body)
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
        ): ReadBuffer {
            val ip = address.ip
            val buf = BufferFactory.Default.allocate(ADDR_HEADER_BYTES + ipSize(ip), ByteOrder.BIG_ENDIAN)
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

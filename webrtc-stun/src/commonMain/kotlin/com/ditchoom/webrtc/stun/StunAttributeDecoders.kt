package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.ReadBuffer

/**
 * Typed interpreters for a [RawAttribute]'s zero-copy value view (RFC 8489 §14). Each returns `null`
 * when the view does not match the shape it expects — a genuinely-absent typed reading, never a
 * throw (T0: malformed content is a typed miss, not a crash). They assume the value is network byte
 * order, which [StunMessage] guarantees for decoded attributes.
 */

private const val FAMILY_OFFSET = 1
private const val PORT_OFFSET = 2
private const val ADDRESS_OFFSET = 4
private const val ERROR_HEADER_BYTES = 4
private const val PORT_XOR = 0x2112 // magic cookie high half (RFC 8489 §14.2)
private const val ERROR_CLASS_MULTIPLIER = 100
private const val ERROR_CLASS_MASK = 0x07
private const val BYTE_MASK = 0xFF

/** MAPPED-ADDRESS (RFC 8489 §14.1) — plaintext family/port/address. */
public fun RawAttribute.asTransportAddress(): TransportAddress? = decodeAddress(xorWith = null)

/**
 * XOR-MAPPED-ADDRESS (RFC 8489 §14.2) — un-XORs the port with the cookie's high half and the address
 * with the cookie (IPv4) or cookie‖[transactionId] (IPv6).
 */
public fun RawAttribute.asXorMappedAddress(transactionId: TransactionId): TransportAddress? = decodeAddress(xorWith = transactionId)

private fun RawAttribute.decodeAddress(xorWith: TransactionId?): TransportAddress? {
    val v = value
    if (length < ADDRESS_OFFSET) return null
    val portMask = if (xorWith != null) PORT_XOR else 0
    val port = (v.getUnsignedShort(PORT_OFFSET).toInt() xor portMask).toUShort()
    return when (v.get(FAMILY_OFFSET).toUByte()) {
        IpAddress.V4.FAMILY -> {
            if (length < ADDRESS_OFFSET + IpAddress.V4.SIZE_BYTES) return null
            val mask = if (xorWith != null) Stun.MAGIC_COOKIE else 0u
            TransportAddress(IpAddress.V4(v.getUnsignedInt(ADDRESS_OFFSET) xor mask), port)
        }
        IpAddress.V6.FAMILY -> {
            if (length < ADDRESS_OFFSET + IpAddress.V6.SIZE_BYTES) return null
            val (khi, klo) = RawAttribute.ipv6XorKey(xorWith)
            val hi = v.getUnsignedLong(ADDRESS_OFFSET) xor khi
            val lo = v.getUnsignedLong(ADDRESS_OFFSET + Long.SIZE_BYTES) xor klo
            TransportAddress(IpAddress.V6(hi, lo), port)
        }
        else -> null
    }
}

/** ERROR-CODE (RFC 8489 §14.8) → composed code (class×100 + number) and the UTF-8 reason. */
public fun RawAttribute.asErrorCode(): StunErrorCode? {
    if (type != StunAttributeType.ErrorCode || length < ERROR_HEADER_BYTES) return null
    val v = value
    val classDigit = v.get(PORT_OFFSET).toInt() and ERROR_CLASS_MASK
    val number = v.get(ADDRESS_OFFSET - 1).toInt() and BYTE_MASK
    return StunErrorCode(classDigit * ERROR_CLASS_MULTIPLIER + number, readUtf8OrNull(v, ERROR_HEADER_BYTES, length) ?: "")
}

/**
 * UTF-8 text (USERNAME/REALM/NONCE/SOFTWARE) — the whole value as a string, or `null` if the bytes
 * are not valid UTF-8. Total by contract (T0): a hostile peer's malformed text is a typed miss, never
 * a throw. Found by the Jazzer lane; regression fixture in `StunMalformedCorpusTest`.
 */
public fun RawAttribute.asText(): String? = readUtf8OrNull(value, 0, length)

private fun readUtf8OrNull(
    v: ReadBuffer,
    start: Int,
    end: Int,
): String? {
    if (end <= start) return ""
    val savedPos = v.position()
    return try {
        v.position(start)
        v.readString(end - start, Charset.UTF8)
    } catch (_: Throwable) {
        // Not decodable as UTF-8: a typed absence, not a crash. Must be Throwable, not Exception —
        // on Kotlin/JS the platform TextDecoder throws a raw JS error that is not a Kotlin Exception,
        // so only a Throwable catch is portable. The one place a broad catch is right (bytes→text edge).
        null
    } finally {
        v.position(savedPos)
    }
}

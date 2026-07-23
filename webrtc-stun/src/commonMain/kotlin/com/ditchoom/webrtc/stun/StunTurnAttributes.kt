package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default

/**
 * Codec-only typed builders/interpreters for the fixed-shape TURN attributes (RFC 8656) and the core
 * STUN UNKNOWN-ATTRIBUTES (RFC 8489 §14.9). W1 ships the wire codec for these; the TURN client state
 * machine is W3. XOR-PEER-ADDRESS / XOR-RELAYED-ADDRESS share XOR-MAPPED-ADDRESS's wire form, so
 * [RawAttribute.asXorMappedAddress] / [RawAttribute.ofXorMappedAddress] already cover them.
 */

private const val REQUESTED_TRANSPORT_BYTES = 4 // protocol(1) + RFFU(3)
private const val REQUESTED_ADDRESS_FAMILY_BYTES = 4 // family(1) + RFFU(3)
private const val CHANNEL_NUMBER_BYTES = 4 // channel(2) + RFFU(2)
private const val U32_BYTES = 4
private const val U16_BYTES = 2

/** IANA protocol number for UDP, the only REQUESTED-TRANSPORT value TURN defines (RFC 8656 §18.6). */
public const val TURN_TRANSPORT_UDP: UByte = 17u

/** REQUESTED-ADDRESS-FAMILY family octets (RFC 8656 §18.9): the relay address family an Allocate asks for. */
public const val TURN_FAMILY_IPV4: UByte = 0x01u
public const val TURN_FAMILY_IPV6: UByte = 0x02u

/**
 * REQUESTED-ADDRESS-FAMILY (RFC 8656 §18.9): a 1-byte address family then 3 reserved bytes. An Allocate
 * MUST carry this to obtain an **IPv6** relay — absent it, the server allocates an IPv4 relay (RFC 8656
 * §7.2's default), which against a v6-only TURN server has no usable address (it falls back to loopback,
 * yielding a relay candidate no peer can reach → ICE `AllPairsFailed`).
 */
public fun RawAttribute.Companion.ofRequestedAddressFamily(family: UByte): RawAttribute {
    val v = BufferFactory.Default.allocate(REQUESTED_ADDRESS_FAMILY_BYTES, ByteOrder.BIG_ENDIAN)
    v.writeUByte(family)
    v.writeByte(0)
    v.writeShort(0)
    v.resetForRead()
    return ofValue(StunAttributeType.RequestedAddressFamily, v)
}

/** REQUESTED-ADDRESS-FAMILY family octet, or null if the value is malformed. */
public fun RawAttribute.asRequestedAddressFamily(): UByte? = if (length == REQUESTED_ADDRESS_FAMILY_BYTES) value.get(0).toUByte() else null

/** LIFETIME (RFC 8656 §18.4): a u32 duration in seconds (Allocate/Refresh). */
public fun RawAttribute.Companion.ofLifetime(seconds: UInt): RawAttribute {
    val v = BufferFactory.Default.allocate(U32_BYTES, ByteOrder.BIG_ENDIAN)
    v.writeUInt(seconds)
    v.resetForRead()
    return ofValue(StunAttributeType.Lifetime, v)
}

/** LIFETIME seconds, or null if the value is not a u32. */
public fun RawAttribute.asLifetimeSeconds(): UInt? = if (length == U32_BYTES) value.getUnsignedInt(0) else null

/** REQUESTED-TRANSPORT (RFC 8656 §18.6): a 1-byte protocol number then 3 reserved bytes. */
public fun RawAttribute.Companion.ofRequestedTransport(protocol: UByte = TURN_TRANSPORT_UDP): RawAttribute {
    val v = BufferFactory.Default.allocate(REQUESTED_TRANSPORT_BYTES, ByteOrder.BIG_ENDIAN)
    v.writeUByte(protocol)
    v.writeByte(0)
    v.writeShort(0)
    v.resetForRead()
    return ofValue(StunAttributeType.RequestedTransport, v)
}

/** REQUESTED-TRANSPORT protocol number, or null if the value is malformed. */
public fun RawAttribute.asRequestedTransport(): UByte? = if (length == REQUESTED_TRANSPORT_BYTES) value.get(0).toUByte() else null

/** CHANNEL-NUMBER (RFC 8656 §18.1): a u16 channel then 2 reserved bytes. */
public fun RawAttribute.Companion.ofChannelNumber(channel: UShort): RawAttribute {
    val v = BufferFactory.Default.allocate(CHANNEL_NUMBER_BYTES, ByteOrder.BIG_ENDIAN)
    v.writeUShort(channel)
    v.writeShort(0)
    v.resetForRead()
    return ofValue(StunAttributeType.ChannelNumber, v)
}

/** CHANNEL-NUMBER value, or null if the value is malformed. */
public fun RawAttribute.asChannelNumber(): UShort? = if (length == CHANNEL_NUMBER_BYTES) value.getUnsignedShort(0) else null

/**
 * UNKNOWN-ATTRIBUTES (RFC 8489 §14.9): the list of attribute types a 420 error response reports as
 * not-understood — a packed sequence of u16 types.
 */
public fun RawAttribute.Companion.ofUnknownAttributes(types: List<StunAttributeType>): RawAttribute {
    val v = BufferFactory.Default.allocate((types.size * U16_BYTES).coerceAtLeast(1), ByteOrder.BIG_ENDIAN)
    for (t in types) v.writeUShort(t.value)
    v.resetForRead()
    v.setLimit(types.size * U16_BYTES)
    return ofValue(StunAttributeType.UnknownAttributes, v)
}

/** The u16 attribute types carried by UNKNOWN-ATTRIBUTES, or null if the length isn't a u16 multiple. */
public fun RawAttribute.asUnknownAttributes(): List<StunAttributeType>? {
    if (type != StunAttributeType.UnknownAttributes || length % U16_BYTES != 0) return null
    val out = ArrayList<StunAttributeType>(length / U16_BYTES)
    var i = 0
    while (i < length) {
        out += StunAttributeType(value.getUnsignedShort(i))
        i += U16_BYTES
    }
    return out
}

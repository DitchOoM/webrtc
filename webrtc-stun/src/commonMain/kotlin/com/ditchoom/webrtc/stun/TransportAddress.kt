package com.ditchoom.webrtc.stun

/**
 * An IP address as a value, held **without a `ByteArray`** (standing directive #1): IPv4 packs into
 * a `UInt`, IPv6 into two `ULong`s. Value equality + a hash for free, and it can outlive the
 * datagram (an ICE candidate keeps it) with no retained slice. The STUN address family byte
 * (RFC 8489 §14.1) is the sealed discriminant, so an "IPv4 with 16 bytes" state is unrepresentable.
 */
public sealed interface IpAddress {
    /** RFC 8489 §14.1 family byte: 0x01 (IPv4) or 0x02 (IPv6). */
    public val family: UByte

    /** IPv4, big-endian in [bits] (bits 31..24 are the first dotted octet). */
    public data class V4(
        public val bits: UInt,
    ) : IpAddress {
        override val family: UByte get() = FAMILY

        override fun toString(): String {
            val b = bits
            return "${(b shr 24) and 0xFFu}.${(b shr 16) and 0xFFu}.${(b shr 8) and 0xFFu}.${b and 0xFFu}"
        }

        public companion object {
            public const val FAMILY: UByte = 0x01u
            public const val SIZE_BYTES: Int = 4
        }
    }

    /** IPv6, [hi] the first 8 bytes (network order), [lo] the last 8. */
    public data class V6(
        public val hi: ULong,
        public val lo: ULong,
    ) : IpAddress {
        override val family: UByte get() = FAMILY

        public companion object {
            public const val FAMILY: UByte = 0x02u
            public const val SIZE_BYTES: Int = 16
        }
    }
}

/**
 * A transport address: an [IpAddress] and a 16-bit [port]. The parsed form of MAPPED-ADDRESS and
 * (after un-XOR) XOR-MAPPED-ADDRESS / the TURN peer & relayed addresses.
 */
public data class TransportAddress(
    public val ip: IpAddress,
    public val port: UShort,
)

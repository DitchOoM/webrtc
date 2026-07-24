package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.stun.IpAddress

/**
 * The one-shot mDNS query/response **wire codec** (RFC 6762 over the RFC 1035 DNS message format) — pure,
 * sans-io, `commonMain`, so it is exercised deterministically on every target under `runTest`, while the
 * multicast socket that carries these bytes is a platform actual ([MulticastMdnsResolver], non-browser
 * targets only). A browser advertises an `<uuid>.local` host candidate to hide its private IP (RFC 8828);
 * to send a connectivity check to it we resolve the name to an address with a single QM/QU query.
 *
 * Encodes a query for one name + record type; decodes a response by walking the answer section for the
 * first matching A / AAAA record. Truncation or a malformed message is a **typed reject** (`null`), never a
 * throw (T0 discipline) — a hostile or corrupt datagram on the multicast group must not crash the resolver.
 */
internal object MdnsMessage {
    /** RFC 1035 §3.2.2 TYPE values we support — an A (IPv4) or AAAA (IPv6) address record. */
    const val TYPE_A: Int = 1
    const val TYPE_AAAA: Int = 28

    private const val HEADER_BYTES = 12
    private const val QUESTION_TAIL_BYTES = 4 // QTYPE(u16) + QCLASS(u16)
    private const val CLASS_IN = 0x0001
    private const val QU_BIT = 0x8000 // RFC 6762 §5.4 unicast-response ("QU") bit in the question's QCLASS
    private const val COMPRESSION_MASK = 0xC0 // RFC 1035 §4.1.4: a label length byte with the top 2 bits set is a pointer
    private const val LABEL_MAX = 0x3F
    private const val V4_RDLENGTH = 4
    private const val V6_RDLENGTH = 16

    /**
     * Encode a one-shot mDNS query for [name] (`<uuid>.local`) asking for [qType] (A or AAAA). The
     * transaction id is 0 (RFC 6762 §18.1: responders ignore it for multicast queries) and the QCLASS
     * carries the QU bit so a responder MAY unicast the reply straight back to our source port. Returns a
     * read-positioned [ReadBuffer] ready to hand to `DatagramChannel.send`.
     */
    fun encodeQuery(
        name: String,
        qType: Int,
        bufferFactory: BufferFactory,
    ): ReadBuffer {
        val labels = name.trimEnd('.').split('.').filter { it.isNotEmpty() }
        val nameBytes = labels.sumOf { 1 + it.length } + 1 // each label: len(u8)+bytes; then a 0 root terminator
        val buffer = bufferFactory.allocate(HEADER_BYTES + nameBytes + QUESTION_TAIL_BYTES, ByteOrder.BIG_ENDIAN)
        buffer.writeUShort(0u) // ID — 0 (ignored on multicast, RFC 6762 §18.1)
        buffer.writeUShort(0u) // flags — QR=0 (query), opcode 0, RD=0
        buffer.writeUShort(1u) // QDCOUNT
        buffer.writeUShort(0u) // ANCOUNT
        buffer.writeUShort(0u) // NSCOUNT
        buffer.writeUShort(0u) // ARCOUNT
        for (label in labels) {
            buffer.writeByte(label.length.toByte())
            for (c in label) buffer.writeByte(c.code.toByte()) // `.local` names are ASCII
        }
        buffer.writeByte(0) // root label — terminates the QNAME
        buffer.writeUShort(qType.toUShort())
        buffer.writeUShort((CLASS_IN or QU_BIT).toUShort())
        buffer.resetForRead()
        return buffer
    }

    /**
     * Walk a response [payload] and return the first address record of [wantType] (A→[IpAddress.V4],
     * AAAA→[IpAddress.V6]), or null if there is none or the datagram is truncated/malformed. The question
     * section is skipped; answer NAMEs are skipped (including RFC 1035 compression pointers) — in a one-shot
     * exchange the only responder is answering our exact query, so matching the RR owner name adds nothing.
     */
    fun decodeAddress(
        payload: ReadBuffer,
        wantType: Int,
    ): IpAddress? {
        if (payload.remaining() < HEADER_BYTES) return null
        payload.readUnsignedShort() // ID
        payload.readUnsignedShort() // flags
        val questionCount = payload.readUnsignedShort().toInt()
        val answerCount = payload.readUnsignedShort().toInt()
        payload.readUnsignedShort() // NSCOUNT
        payload.readUnsignedShort() // ARCOUNT

        repeat(questionCount) {
            if (!skipName(payload)) return null
            if (payload.remaining() < QUESTION_TAIL_BYTES) return null
            payload.readUnsignedShort() // QTYPE
            payload.readUnsignedShort() // QCLASS
        }

        repeat(answerCount) {
            if (!skipName(payload)) return null
            if (payload.remaining() < 10) return null // TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2)
            val type = payload.readUnsignedShort().toInt()
            payload.readUnsignedShort() // CLASS (top bit = cache-flush, RFC 6762 §10.2 — irrelevant here)
            payload.readUnsignedInt() // TTL
            val rdLength = payload.readUnsignedShort().toInt()
            if (rdLength < 0 || payload.remaining() < rdLength) return null
            when {
                type == TYPE_A && wantType == TYPE_A && rdLength == V4_RDLENGTH -> return readV4(payload)
                type == TYPE_AAAA && wantType == TYPE_AAAA && rdLength == V6_RDLENGTH -> return readV6(payload)
                else -> skip(payload, rdLength) // a different / unwanted record — step over its RDATA and continue
            }
        }
        return null
    }

    private fun readV4(payload: ReadBuffer): IpAddress.V4 {
        var bits = 0u
        repeat(V4_RDLENGTH) { bits = (bits shl Byte.SIZE_BITS) or payload.readUnsignedByte().toUInt() }
        return IpAddress.V4(bits)
    }

    private fun readV6(payload: ReadBuffer): IpAddress.V6 {
        var hi = 0uL
        repeat(V6_RDLENGTH / 2) { hi = (hi shl Byte.SIZE_BITS) or payload.readUnsignedByte().toULong() }
        var lo = 0uL
        repeat(V6_RDLENGTH / 2) { lo = (lo shl Byte.SIZE_BITS) or payload.readUnsignedByte().toULong() }
        return IpAddress.V6(hi, lo)
    }

    // Advance past a DNS name at the current position: a run of length-prefixed labels ended by a zero byte,
    // or a 2-byte compression pointer (RFC 1035 §4.1.4). Returns false on truncation.
    private fun skipName(payload: ReadBuffer): Boolean {
        while (true) {
            if (payload.remaining() < 1) return false
            val length = payload.readUnsignedByte().toInt()
            when {
                length == 0 -> return true // root label — end of name
                (length and COMPRESSION_MASK) == COMPRESSION_MASK -> {
                    if (payload.remaining() < 1) return false
                    payload.readUnsignedByte() // second half of the pointer; a pointer always ends the name
                    return true
                }
                length <= LABEL_MAX -> {
                    if (payload.remaining() < length) return false
                    skip(payload, length)
                }
                else -> return false // reserved 0b10 top bits — malformed
            }
        }
    }

    private fun skip(
        payload: ReadBuffer,
        count: Int,
    ) {
        payload.position(payload.position() + count)
    }
}

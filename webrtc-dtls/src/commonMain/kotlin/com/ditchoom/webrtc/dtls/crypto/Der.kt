package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer

/**
 * A minimal DER (ASN.1 Distinguished Encoding Rules) writer — only the productions a self-signed
 * WebRTC certificate needs (RFC §11.5's "a bounded ASN.1 DER slice is webrtc's own"). Not a general
 * ASN.1 library: no parsing, no indefinite lengths, no BER. Every element is built innermost-first as a
 * complete `tag ‖ length ‖ value` [ReadBuffer], then composed. Definite lengths use the short form
 * below 128 and the big-endian long form above — the DER-canonical minimal encoding.
 */
internal class Der(
    private val factory: BufferFactory,
) {
    /** Wraps [content] in a `tag ‖ length ‖ content` TLV. */
    fun tlv(
        tag: Int,
        content: ReadBuffer,
    ): ReadBuffer {
        val len = content.remaining()
        val lengthOctets = lengthOctets(len)
        val out = factory.allocate(1 + lengthOctets.size + len, ByteOrder.BIG_ENDIAN)
        out.writeByte((tag and 0xFF).toByte())
        for (o in lengthOctets) out.writeByte(o.toByte())
        writeView(out, content)
        out.resetForRead()
        return out
    }

    /** `SEQUENCE { children… }`. */
    fun sequence(children: List<ReadBuffer>): ReadBuffer = tlv(0x30, concat(children))

    /** `SET { children… }`. */
    fun set(children: List<ReadBuffer>): ReadBuffer = tlv(0x31, concat(children))

    /** `[n] EXPLICIT` context-tagged wrapper (constructed). */
    fun explicit(
        context: Int,
        content: ReadBuffer,
    ): ReadBuffer = tlv(0xA0 or context, content)

    /** `INTEGER` from an already-positive, minimally-encoded magnitude (caller guarantees the form). */
    fun integer(magnitude: ReadBuffer): ReadBuffer = tlv(0x02, magnitude)

    /** `BIT STRING` with zero unused bits — prepends the `00` unused-bits octet before [content]. */
    fun bitString(content: ReadBuffer): ReadBuffer {
        val wrapped = factory.allocate(1 + content.remaining(), ByteOrder.BIG_ENDIAN)
        wrapped.writeByte(0)
        writeView(wrapped, content)
        wrapped.resetForRead()
        return tlv(0x03, wrapped)
    }

    /** `UTCTime` (`YYMMDDHHMMSSZ`). */
    fun utcTime(value: String): ReadBuffer = tlv(0x17, ascii(value))

    /** `PrintableString`. */
    fun printableString(value: String): ReadBuffer = tlv(0x13, ascii(value))

    /** A pre-encoded literal TLV (an OID or full AlgorithmIdentifier), spliced verbatim. */
    fun literal(vararg octets: Int): ReadBuffer {
        val out = factory.allocate(octets.size, ByteOrder.BIG_ENDIAN)
        for (o in octets) out.writeByte((o and 0xFF).toByte())
        out.resetForRead()
        return out
    }

    fun ascii(value: String): ReadBuffer {
        val out = factory.allocate(value.length, ByteOrder.BIG_ENDIAN)
        for (ch in value) out.writeByte((ch.code and 0xFF).toByte())
        out.resetForRead()
        return out
    }

    fun concat(children: List<ReadBuffer>): ReadBuffer {
        val total = children.sumOf { it.remaining() }
        val out = factory.allocate(maxOf(total, 1), ByteOrder.BIG_ENDIAN)
        for (c in children) writeView(out, c)
        out.resetForRead()
        return out
    }

    private fun lengthOctets(len: Int): List<Int> {
        if (len < 0x80) return listOf(len)
        val octets = ArrayDeque<Int>()
        var v = len
        while (v > 0) {
            octets.addFirst(v and 0xFF)
            v = v ushr 8
        }
        return buildList {
            add(0x80 or octets.size)
            addAll(octets)
        }
    }

    private fun writeView(
        dest: WriteBuffer,
        view: ReadBuffer,
    ) {
        val p = view.position()
        dest.write(view)
        view.position(p)
    }
}

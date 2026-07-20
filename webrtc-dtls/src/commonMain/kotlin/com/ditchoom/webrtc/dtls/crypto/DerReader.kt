package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer

/**
 * A minimal DER *reader* — only enough to walk a certificate's SEQUENCE structure and lift out the
 * `subjectPublicKeyInfo`, so the ServerKeyExchange signature can be verified against the peer's identity
 * key (RFC 8422 §5.4). Definite lengths only; never throws (T0 totality — a malformed cert yields null,
 * which the handshake maps to a typed reject). Pairs with the write-only [Der].
 */
internal object DerReader {
    /** One parsed TLV: the byte range of the whole element and of its content, plus where the next starts. */
    class Tlv(
        val tag: Int,
        val elementStart: Int,
        val contentStart: Int,
        val contentEnd: Int,
    ) {
        val next: Int get() = contentEnd
    }

    /** Reads the TLV at [off] within `[off, end)`, or null if its tag/length overrun the region. */
    fun readTlv(
        buf: ReadBuffer,
        off: Int,
        end: Int,
    ): Tlv? {
        if (off + 2 > end) return null
        val tag = u8(buf, off)
        val lenByte = u8(buf, off + 1)
        val contentStart: Int
        val length: Int
        if (lenByte < 0x80) {
            length = lenByte
            contentStart = off + 2
        } else {
            val numLenOctets = lenByte and 0x7F
            if (numLenOctets == 0 || numLenOctets > 4 || off + 2 + numLenOctets > end) return null
            var v = 0
            for (i in 0 until numLenOctets) v = (v shl 8) or u8(buf, off + 2 + i)
            length = v
            contentStart = off + 2 + numLenOctets
        }
        val contentEnd = contentStart + length
        if (contentEnd > end || contentEnd < contentStart) return null
        return Tlv(tag, off, contentStart, contentEnd)
    }

    /** Walks the direct children of a constructed TLV over `[start, end)`, or null on any overrun. */
    fun children(
        buf: ReadBuffer,
        start: Int,
        end: Int,
    ): List<Tlv>? {
        val out = ArrayList<Tlv>(8)
        var pos = start
        while (pos < end) {
            val tlv = readTlv(buf, pos, end) ?: return null
            out += tlv
            pos = tlv.next
        }
        return out
    }

    /**
     * Extracts the `subjectPublicKeyInfo` (a full DER SEQUENCE) from an X.509 [certificateDer]. The
     * TBSCertificate fields are, in order: optional `[0] version`, serialNumber, signature, issuer,
     * validity, subject, **subjectPublicKeyInfo**, then optional extensions — so the SPKI is the field
     * right after `subject`. Returns a freshly-allocated copy (independent of [certificateDer]'s
     * lifetime), or null if the structure doesn't parse. Never throws.
     */
    fun extractSpki(
        certificateDer: ReadBuffer,
        factory: BufferFactory,
    ): ReadBuffer? {
        val end = certificateDer.remaining()
        val certificate = readTlv(certificateDer, 0, end) ?: return null
        if (certificate.tag != 0x30) return null
        val certChildren = children(certificateDer, certificate.contentStart, certificate.contentEnd) ?: return null
        val tbs = certChildren.firstOrNull() ?: return null
        if (tbs.tag != 0x30) return null
        val tbsChildren = children(certificateDer, tbs.contentStart, tbs.contentEnd) ?: return null

        // subjectPublicKeyInfo sits after subject: index 6 when the [0] version is present, else 5.
        val hasVersion = tbsChildren.firstOrNull()?.tag == 0xA0
        val spkiIndex = if (hasVersion) 6 else 5
        val spki = tbsChildren.getOrNull(spkiIndex) ?: return null
        if (spki.tag != 0x30) return null

        val len = spki.contentEnd - spki.elementStart
        val out = factory.allocate(len, ByteOrder.BIG_ENDIAN)
        val save = certificateDer.position()
        certificateDer.position(spki.elementStart)
        var i = 0
        while (i < len) {
            out.writeByte(certificateDer.readByte())
            i++
        }
        certificateDer.position(save)
        out.resetForRead()
        return out
    }

    private fun u8(
        buf: ReadBuffer,
        index: Int,
    ): Int = buf.get(index).toInt() and 0xFF
}

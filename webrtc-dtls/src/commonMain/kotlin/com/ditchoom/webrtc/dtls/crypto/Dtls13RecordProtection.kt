package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import com.ditchoom.buffer.crypto.Aad
import com.ditchoom.buffer.crypto.Aead
import com.ditchoom.buffer.crypto.AesEcb
import com.ditchoom.buffer.crypto.AesEcbKey
import com.ditchoom.buffer.crypto.AesGcmKey
import com.ditchoom.buffer.crypto.CryptoCapabilities
import com.ditchoom.buffer.crypto.SyncCapableAesGcmKey
import com.ditchoom.buffer.crypto.VerificationFailed
import com.ditchoom.buffer.crypto.aesEcb
import com.ditchoom.buffer.crypto.aesGcm

/**
 * DTLS 1.3 AEAD record protection for `TLS_AES_128_GCM_SHA256` (RFC 9147 §4 over RFC 8446 §5.2), matched
 * byte-for-byte against BoringSSL's `dtls_seal_record`. One directional instance protects one epoch: it
 * carries the local write key/IV + record-number key ([sealKey]/[sealIv]/[sealSn]) and the peer's
 * ([openKey]/[openIv]/[openSn]).
 *
 * A sealed record is the DTLS 1.3 **unified header** followed by the AEAD output:
 * ```
 *   unified_hdr = first_byte(0x2c|epoch&3) ‖ uint16 seq ‖ uint16 length
 *   record      = unified_hdr ‖ AEAD(TLSInnerPlaintext)
 * ```
 * where `TLSInnerPlaintext = content ‖ real_content_type` (no padding). Three subtleties are load-bearing:
 * 1. **AAD is the header with the *plaintext* sequence number** (before record-number encryption), and the
 *    16-bit on-wire form. The receiver decrypts the sequence number first, then uses the recovered header.
 * 2. **The AEAD nonce uses the full 48-bit per-epoch sequence number** (`iv XOR left-pad(seq)`), not the
 *    16-bit wire value — so a record past the first 2¹⁶ still gets a unique nonce.
 * 3. **Record-number encryption** (RFC 9147 §4.2.3): `mask = AES-ECB(sn_key, ciphertext[0..15])`, then the
 *    two header sequence bytes are XORed with `mask[0..1]`.
 */
internal class Dtls13RecordProtection private constructor(
    private val sealKey: SyncCapableAesGcmKey,
    private val sealIv: ReadBuffer,
    private val sealSn: AesEcbKey,
    private val openKey: SyncCapableAesGcmKey,
    private val openIv: ReadBuffer,
    private val openSn: AesEcbKey,
    private val factory: BufferFactory,
) : AutoCloseable {
    private val aead =
        (CryptoCapabilities.aesGcm as? Aead.Blocking<AesGcmKey, SyncCapableAesGcmKey>)?.ops
            ?: error("AES-GCM blocking AEAD unavailable on this target (browsers delegate; the engine never runs here)")
    private val ecb =
        (CryptoCapabilities.aesEcb as? AesEcb.Blocking)?.ops
            ?: error("AES-ECB unavailable on this target (browsers delegate; the engine never runs here)")

    // Highest full sequence number successfully opened, for wire-seq reconstruction (RFC 9147 §4.2.2).
    private var highestOpenedSeq = -1L

    /** A decrypted record: the real [contentType] (handshake/app/alert/ack) and its [content]. */
    class Opened(
        val contentType: Int,
        val content: ReadBuffer,
    )

    /**
     * Seals [content] as an epoch-[epoch] record with real content type [realContentType] at the full
     * per-epoch sequence [seq]. Returns the full wire record (unified header + encrypted body).
     */
    fun seal(
        content: ReadBuffer,
        realContentType: Int,
        epoch: Int,
        seq: Long,
    ): ReadBuffer {
        // TLSInnerPlaintext = content ‖ type (no padding).
        val inner = factory.allocate(content.remaining() + 1, ByteOrder.BIG_ENDIAN)
        writeView(inner, content)
        inner.writeByte((realContentType and 0xFF).toByte())
        inner.resetForRead()

        val wireSeq = (seq and 0xFFFF).toInt()
        val ciphertextLen = inner.remaining() + TAG_BYTES
        // AAD = the 5-byte header with the PLAINTEXT sequence number.
        val aad = header(epoch, wireSeq, ciphertextLen)
        val nonce = nonceFor(sealIv, seq)
        val ctTag = aead.sealWithNonceBlocking(sealKey, nonce, inner, Aad.Of(aad), factory)

        val mask = recordNumberMask(sealSn, ctTag)
        val out = factory.allocate(HEADER_BYTES + ctTag.remaining(), ByteOrder.BIG_ENDIAN)
        out.writeByte((FIRST_BYTE_BASE or (epoch and 0x3)).toByte())
        out.writeByte((((wireSeq ushr 8) and 0xFF) xor mask.first).toByte())
        out.writeByte(((wireSeq and 0xFF) xor mask.second).toByte())
        out.writeByte(((ciphertextLen ushr 8) and 0xFF).toByte())
        out.writeByte((ciphertextLen and 0xFF).toByte())
        ctTag.position(0)
        out.write(ctTag)
        out.resetForRead()
        return out
    }

    /**
     * Opens one unified-header record whose bytes span `[start, start+length)` of [datagram] (the caller
     * frames the record boundary). Returns the decrypted [Opened], or null if the header/body is malformed
     * or the tag fails — a decrypt failure is a dropped record in DTLS (RFC 9147), never fatal here.
     */
    fun open(
        datagram: ReadBuffer,
        start: Int,
        endExclusive: Int,
    ): Opened? {
        if (endExclusive - start < HEADER_BYTES + TAG_BYTES) return null
        val ciphertextStart = start + HEADER_BYTES
        val ciphertextLen = endExclusive - ciphertextStart
        if (ciphertextLen < AES_BLOCK) return null

        // Record-number decryption: sample the ciphertext, generate the mask, recover the wire seq bytes.
        val sample = sliceOf(datagram, ciphertextStart, ciphertextStart + AES_BLOCK)
        val mask = recordNumberMask(openSn, sample)
        val encSeqHi = datagram.get(start + 1).toInt() and 0xFF
        val encSeqLo = datagram.get(start + 2).toInt() and 0xFF
        val wireSeq = (((encSeqHi xor mask.first) shl 8) or (encSeqLo xor mask.second)) and 0xFFFF
        val length = ((datagram.get(start + 3).toInt() and 0xFF) shl 8) or (datagram.get(start + 4).toInt() and 0xFF)
        if (length != ciphertextLen) return null

        val fullSeq = reconstructSeq(wireSeq, highestOpenedSeq)
        val epochBits = datagram.get(start).toInt() and 0x3
        val aad = header(epochBits, wireSeq, ciphertextLen)
        val nonce = nonceFor(openIv, fullSeq)
        val ctTag = sliceOf(datagram, ciphertextStart, endExclusive)
        val inner =
            try {
                aead.openWithNonceBlocking(nonce, ctTag, openKey, Aad.Of(aad), factory)
            } catch (_: VerificationFailed) {
                return null
            }
        if (fullSeq > highestOpenedSeq) highestOpenedSeq = fullSeq
        return stripInnerPlaintext(inner)
    }

    override fun close() {
        sealKey.close()
        openKey.close()
        sealSn.close()
        openSn.close()
    }

    // ── helpers ────────────────────────────────────────────────────────────────────────────────────

    /** The 5-byte unified header for [epoch]/[wireSeq]/[ciphertextLen] — used both as AAD and on the wire. */
    private fun header(
        epoch: Int,
        wireSeq: Int,
        ciphertextLen: Int,
    ): ReadBuffer {
        val b = factory.allocate(HEADER_BYTES, ByteOrder.BIG_ENDIAN)
        b.writeByte((FIRST_BYTE_BASE or (epoch and 0x3)).toByte())
        b.writeByte(((wireSeq ushr 8) and 0xFF).toByte())
        b.writeByte((wireSeq and 0xFF).toByte())
        b.writeByte(((ciphertextLen ushr 8) and 0xFF).toByte())
        b.writeByte((ciphertextLen and 0xFF).toByte())
        b.resetForRead()
        return b
    }

    /** `nonce = iv XOR (0…0 ‖ seq_be64)`, seq in the low 8 bytes of the 12-byte IV (RFC 8446 §5.3). */
    private fun nonceFor(
        iv: ReadBuffer,
        seq: Long,
    ): ReadBuffer {
        val n = factory.allocate(Tls13KeySchedule.IV_LEN, ByteOrder.BIG_ENDIAN)
        val base = iv.position()
        for (i in 0 until Tls13KeySchedule.IV_LEN) {
            val ivByte = iv.get(base + i).toInt() and 0xFF
            val shift = (Tls13KeySchedule.IV_LEN - 1 - i) * 8
            val seqByte = if (shift < 64) ((seq ushr shift) and 0xFF).toInt() else 0
            n.writeByte((ivByte xor seqByte).toByte())
        }
        n.resetForRead()
        return n
    }

    /** `mask[0..1]` from `AES-ECB(sn_key, sample[0..15])` (RFC 9147 §4.2.3). */
    private fun recordNumberMask(
        snKey: AesEcbKey,
        sample: ReadBuffer,
    ): Pair<Int, Int> {
        val block = sliceOf(sample, sample.position(), sample.position() + AES_BLOCK)
        val out = factory.allocate(AES_BLOCK, ByteOrder.BIG_ENDIAN)
        ecb.encryptBlock(snKey, block, out)
        out.resetForRead()
        val m0 = out.get(0).toInt() and 0xFF
        val m1 = out.get(1).toInt() and 0xFF
        return m0 to m1
    }

    /** Strips the trailing content-type byte (and any zero padding) from a decrypted TLSInnerPlaintext. */
    private fun stripInnerPlaintext(inner: ReadBuffer): Opened? {
        var end = inner.limit()
        while (end > inner.position() && (inner.get(end - 1).toInt() and 0xFF) == 0) end--
        if (end <= inner.position()) return null // all-zero: no content type — malformed
        val type = inner.get(end - 1).toInt() and 0xFF
        val content = sliceOf(inner, inner.position(), end - 1)
        return Opened(type, content)
    }

    private fun writeView(
        dest: WriteBuffer,
        view: ReadBuffer,
    ) {
        val p = view.position()
        dest.write(view)
        view.position(p)
    }

    private fun sliceOf(
        buf: ReadBuffer,
        start: Int,
        endExclusive: Int,
    ): ReadBuffer {
        val savedPos = buf.position()
        val savedLimit = buf.limit()
        buf.position(0)
        buf.setLimit(endExclusive)
        buf.position(start)
        val view = buf.slice(ByteOrder.BIG_ENDIAN)
        buf.position(0)
        buf.setLimit(savedLimit)
        buf.position(savedPos)
        return view
    }

    companion object {
        const val HEADER_BYTES = 5 // first byte ‖ uint16 seq ‖ uint16 length
        const val TAG_BYTES = 16
        private const val AES_BLOCK = 16
        private const val FIRST_BYTE_BASE = 0x2C // 0b001_0_1_1_00: 001 fixed, C=0, S=1(16-bit seq), L=1(length)

        /** True when [firstByte] is a DTLS 1.3 unified-header (bits 7-5 == 001), vs a legacy plaintext record. */
        fun isUnifiedHeader(firstByte: Int): Boolean = (firstByte and 0xE0) == 0x20

        /**
         * Builds a directional protection instance from the two traffic secrets. [localSecret] seals
         * (our writes), [peerSecret] opens (the peer's writes); each expands into an AES-128-GCM key, a
         * 12-byte IV, and a record-number AES key via [Tls13KeySchedule].
         */
        fun fromTrafficSecrets(
            schedule: Tls13KeySchedule,
            localSecret: ReadBuffer,
            peerSecret: ReadBuffer,
            factory: BufferFactory,
        ): Dtls13RecordProtection {
            val sealKeyBuf = schedule.expandLabel(localSecret, "key", emptyBuf(factory), Tls13KeySchedule.KEY_LEN)
            val sealIv = schedule.expandLabel(localSecret, "iv", emptyBuf(factory), Tls13KeySchedule.IV_LEN)
            val sealSnBuf = schedule.expandLabel(localSecret, "sn", emptyBuf(factory), Tls13KeySchedule.SN_KEY_LEN)
            val openKeyBuf = schedule.expandLabel(peerSecret, "key", emptyBuf(factory), Tls13KeySchedule.KEY_LEN)
            val openIv = schedule.expandLabel(peerSecret, "iv", emptyBuf(factory), Tls13KeySchedule.IV_LEN)
            val openSnBuf = schedule.expandLabel(peerSecret, "sn", emptyBuf(factory), Tls13KeySchedule.SN_KEY_LEN)
            return Dtls13RecordProtection(
                sealKey = AesGcmKey.of(sealKeyBuf),
                sealIv = sealIv,
                sealSn = AesEcbKey.of(sealSnBuf),
                openKey = AesGcmKey.of(openKeyBuf),
                openIv = openIv,
                openSn = AesEcbKey.of(openSnBuf),
                factory = factory,
            )
        }

        private fun emptyBuf(factory: BufferFactory): ReadBuffer {
            val b = factory.allocate(1, ByteOrder.BIG_ENDIAN)
            b.resetForRead()
            b.setLimit(0)
            return b
        }

        /**
         * Reconstructs the full 48-bit sequence number from the 16-bit [wireSeq] given the [highest] full
         * sequence opened so far (RFC 9147 §4.2.2; mirrors BoringSSL `reconstruct_seqnum`, 16-bit mask).
         */
        fun reconstructSeq(
            wireSeq: Int,
            highest: Long,
        ): Long {
            val mask = 0xFFFFL
            val step = mask + 1
            val maxPlusOne = highest + 1
            val diff = ((wireSeq.toLong() - maxPlusOne) and mask)
            var seqnum = maxPlusOne + diff
            if (diff > step / 2 && seqnum >= step) seqnum -= step
            return if (seqnum < 0) wireSeq.toLong() else seqnum
        }
    }
}

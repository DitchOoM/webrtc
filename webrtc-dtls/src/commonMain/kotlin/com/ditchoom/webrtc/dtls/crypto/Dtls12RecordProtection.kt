package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import com.ditchoom.buffer.crypto.Aad
import com.ditchoom.buffer.crypto.Aead
import com.ditchoom.buffer.crypto.AesGcmKey
import com.ditchoom.buffer.crypto.CryptoCapabilities
import com.ditchoom.buffer.crypto.SyncCapableAesGcmKey
import com.ditchoom.buffer.crypto.VerificationFailed
import com.ditchoom.buffer.crypto.aesGcm

/**
 * DTLS 1.2 AEAD record protection for `AES_128_GCM` (RFC 5246 §6.2.3.3, RFC 5288, RFC 6347 §4.1.2). The
 * spike proved buffer-crypto's explicit-nonce AEAD maps 1:1 onto TLS GCM:
 *
 * - **nonce (12 B)** = `write_IV (4)` ‖ `explicit_nonce (8)`, where the explicit nonce is the record's
 *   64-bit `epoch (2) ‖ sequence_number (6)`. The 8-byte explicit part is also prepended to the wire
 *   fragment so the receiver reconstructs the nonce.
 * - **AAD (13 B)** = `epoch (2) ‖ sequence_number (6) ‖ type (1) ‖ version (2) ‖ plaintext_length (2)` —
 *   TLS 1.2's `seq_num ‖ TLSCompressed.type/version/length` with the 8-byte DTLS seq substituted.
 * - **wire fragment** = `explicit_nonce (8) ‖ ciphertext ‖ tag (16)`; buffer-crypto returns the bare
 *   `ciphertext ‖ tag`, so we frame the explicit nonce ourselves.
 *
 * One instance protects one connection: it holds the local write key/IV ([sealKey]/[sealIv]) and the
 * peer's ([openKey]/[openIv]), sliced from the key block by role. [close] frees the AEAD keys.
 */
internal class Dtls12RecordProtection private constructor(
    private val sealKey: SyncCapableAesGcmKey,
    private val sealIv: ReadBuffer,
    private val openKey: SyncCapableAesGcmKey,
    private val openIv: ReadBuffer,
    private val factory: BufferFactory,
) : AutoCloseable {
    private val ops =
        (CryptoCapabilities.aesGcm as? Aead.Blocking<AesGcmKey, SyncCapableAesGcmKey>)?.ops
            ?: error("AES-GCM blocking AEAD unavailable on this target (browsers delegate; the engine never runs here)")

    /** Encrypts [plaintext] into a wire fragment (`explicit_nonce ‖ ciphertext ‖ tag`). */
    fun seal(
        plaintext: ReadBuffer,
        epoch: Int,
        sequenceNumber: Long,
        contentType: Int,
        version: Int,
    ): ReadBuffer {
        val explicit = explicitNonce(epoch, sequenceNumber)
        val nonce = concat(sealIv, explicit)
        val aad = additionalData(epoch, sequenceNumber, contentType, version, plaintext.remaining())
        val ctTag = ops.sealWithNonceBlocking(sealKey, nonce, plaintext, Aad.Of(aad), factory)
        val fragment = factory.allocate(EXPLICIT_NONCE_BYTES + ctTag.remaining(), ByteOrder.BIG_ENDIAN)
        writeView(fragment, explicit)
        ctTag.position(0)
        fragment.write(ctTag)
        fragment.resetForRead()
        return fragment
    }

    /**
     * Decrypts a wire [fragment]; returns the plaintext, or null if the fragment is too short or the tag
     * fails to verify — a decrypt failure is a dropped record in DTLS (RFC 6347), never a fatal fault at
     * this layer.
     */
    fun open(
        fragment: ReadBuffer,
        epoch: Int,
        sequenceNumber: Long,
        contentType: Int,
        version: Int,
    ): ReadBuffer? {
        val total = fragment.remaining()
        if (total < EXPLICIT_NONCE_BYTES + TAG_BYTES) return null
        val base = fragment.position()
        val explicit = sliceOf(fragment, base, base + EXPLICIT_NONCE_BYTES)
        val ctTag = sliceOf(fragment, base + EXPLICIT_NONCE_BYTES, base + total)
        val nonce = concat(openIv, explicit)
        val plaintextLen = ctTag.remaining() - TAG_BYTES
        val aad = additionalData(epoch, sequenceNumber, contentType, version, plaintextLen)
        return try {
            ops.openWithNonceBlocking(nonce, ctTag, openKey, Aad.Of(aad), factory)
        } catch (_: VerificationFailed) {
            null
        }
    }

    override fun close() {
        sealKey.close()
        openKey.close()
    }

    private fun explicitNonce(
        epoch: Int,
        sequenceNumber: Long,
    ): ReadBuffer {
        val b = factory.allocate(EXPLICIT_NONCE_BYTES, ByteOrder.BIG_ENDIAN)
        b.writeByte(((epoch ushr 8) and 0xFF).toByte())
        b.writeByte((epoch and 0xFF).toByte())
        writeU48(b, sequenceNumber)
        b.resetForRead()
        return b
    }

    private fun additionalData(
        epoch: Int,
        sequenceNumber: Long,
        contentType: Int,
        version: Int,
        plaintextLen: Int,
    ): ReadBuffer {
        val b = factory.allocate(AAD_BYTES, ByteOrder.BIG_ENDIAN)
        b.writeByte(((epoch ushr 8) and 0xFF).toByte())
        b.writeByte((epoch and 0xFF).toByte())
        writeU48(b, sequenceNumber)
        b.writeByte((contentType and 0xFF).toByte())
        b.writeByte(((version ushr 8) and 0xFF).toByte())
        b.writeByte((version and 0xFF).toByte())
        b.writeByte(((plaintextLen ushr 8) and 0xFF).toByte())
        b.writeByte((plaintextLen and 0xFF).toByte())
        b.resetForRead()
        return b
    }

    private fun writeU48(
        dest: WriteBuffer,
        value: Long,
    ) {
        dest.writeByte(((value ushr 40) and 0xFF).toByte())
        dest.writeByte(((value ushr 32) and 0xFF).toByte())
        dest.writeByte(((value ushr 24) and 0xFF).toByte())
        dest.writeByte(((value ushr 16) and 0xFF).toByte())
        dest.writeByte(((value ushr 8) and 0xFF).toByte())
        dest.writeByte((value and 0xFF).toByte())
    }

    private fun concat(
        a: ReadBuffer,
        b: ReadBuffer,
    ): ReadBuffer {
        val out = factory.allocate(a.remaining() + b.remaining(), ByteOrder.BIG_ENDIAN)
        writeView(out, a)
        writeView(out, b)
        out.resetForRead()
        return out
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
        const val KEY_BYTES = 16
        const val FIXED_IV_BYTES = 4
        const val EXPLICIT_NONCE_BYTES = 8
        const val TAG_BYTES = 16
        private const val AAD_BYTES = 13

        /** AES-128-GCM key-block layout: `client_write_key(16) ‖ server_write_key(16) ‖ client_IV(4) ‖ server_IV(4)`. */
        const val KEY_BLOCK_BYTES = 2 * KEY_BYTES + 2 * FIXED_IV_BYTES

        /**
         * Slices the [keyBlock] by [role] into a directional record-protection instance. The client
         * seals with the `client_write_*` material and opens with the `server_write_*`; the server is the
         * mirror. The key bytes are copied into wiped AEAD keys, so the key block buffer may be released
         * afterward.
         */
        fun fromKeyBlock(
            keyBlock: ReadBuffer,
            client: Boolean,
            factory: BufferFactory,
        ): Dtls12RecordProtection {
            val base = keyBlock.position()

            fun slice(
                off: Int,
                len: Int,
            ): ReadBuffer = subview(keyBlock, base + off, base + off + len)

            val clientKey = AesGcmKey.of(slice(0, KEY_BYTES))
            val serverKey = AesGcmKey.of(slice(KEY_BYTES, KEY_BYTES))
            val clientIv = slice(2 * KEY_BYTES, FIXED_IV_BYTES)
            val serverIv = slice(2 * KEY_BYTES + FIXED_IV_BYTES, FIXED_IV_BYTES)
            return if (client) {
                Dtls12RecordProtection(clientKey, clientIv, serverKey, serverIv, factory)
            } else {
                Dtls12RecordProtection(serverKey, serverIv, clientKey, clientIv, factory)
            }
        }

        private fun subview(
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
    }
}

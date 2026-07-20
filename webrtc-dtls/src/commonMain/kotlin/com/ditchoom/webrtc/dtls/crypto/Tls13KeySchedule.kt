package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import com.ditchoom.buffer.crypto.Hkdf
import com.ditchoom.buffer.crypto.HmacSha256Mac
import com.ditchoom.buffer.crypto.Info
import com.ditchoom.buffer.crypto.Salt
import com.ditchoom.buffer.crypto.Sha256Digest

/**
 * The DTLS 1.3 key schedule for `TLS_AES_128_GCM_SHA256` (RFC 9147 §5 over RFC 8446 §7.1). The suite's
 * hash is SHA-256, so every secret is 32 bytes and every `HKDF-Expand`/`Extract` runs over buffer-crypto's
 * [Hkdf] (HMAC-SHA256). Pure functions over buffers — no clock, no I/O, no RNG.
 *
 * **The DTLS gotcha (spike- and BoringSSL-confirmed):** `HKDF-Expand-Label`'s label prefix is `"dtls13"`
 * (six bytes, **no** trailing space), concatenated directly with the label — *not* TLS's `"tls13 "`. So the
 * key for the record's AEAD is `HKDF-Expand-Label(secret, "key", "", 16)` with the full label bytes
 * `"dtls13key"`. Getting this wrong yields keys that differ from every real DTLS 1.3 stack.
 *
 * The secret tree (`hs->secret` threads through each step, matching BoringSSL `tls13_enc.cc`):
 * ```
 *   early      = HKDF-Extract(salt=0, ikm=0^32)
 *   derived₁   = Expand-Label(early, "derived", SHA-256(""), 32)
 *   handshake  = HKDF-Extract(salt=derived₁, ikm=ECDHE)
 *   {c,s} hs traffic = Derive-Secret(handshake, "{c,s} hs traffic", TranscriptHash(CH…SH))
 *   derived₂   = Expand-Label(handshake, "derived", SHA-256(""), 32)
 *   master     = HKDF-Extract(salt=derived₂, ikm=0^32)
 *   {c,s} ap traffic = Derive-Secret(master, "{c,s} ap traffic", TranscriptHash(CH…server Finished))
 * ```
 * Traffic keys derive from a traffic secret as `key = Expand-Label(s,"key","",16)`,
 * `iv = Expand-Label(s,"iv","",12)`, `sn = Expand-Label(s,"sn","",16)` (the last is the record-number
 * encryption key, RFC 9147 §4.2.3). The Finished `verify_data` is `HMAC(Expand-Label(base,"finished","",32),
 * TranscriptHash(context))`.
 */
internal class Tls13KeySchedule(
    private val factory: BufferFactory,
) {
    /** `SHA-256("")` — the transcript hash of the empty string, used by every `"derived"` step. */
    val emptyTranscriptHash: ReadBuffer by lazy {
        val digest = Sha256Digest()
        val out = factory.allocate(HASH_LEN, ByteOrder.BIG_ENDIAN)
        digest.digestInto(out)
        digest.close()
        out.resetForRead()
        out
    }

    private val zeros: ReadBuffer by lazy {
        val b = factory.allocate(HASH_LEN, ByteOrder.BIG_ENDIAN)
        repeat(HASH_LEN) { b.writeByte(0) }
        b.resetForRead()
        b
    }

    /**
     * `HKDF-Expand-Label(secret, label, context, length)` with the DTLS 1.3 `"dtls13"` label prefix.
     * `HkdfLabel = uint16(length) ‖ uint8(6+label.len) ‖ "dtls13"‖label ‖ uint8(context.len) ‖ context`.
     */
    fun expandLabel(
        secret: ReadBuffer,
        label: String,
        context: ReadBuffer,
        length: Int,
    ): ReadBuffer {
        val fullLabelLen = LABEL_PREFIX.length + label.length
        val info = factory.allocate(2 + 1 + fullLabelLen + 1 + context.remaining(), ByteOrder.BIG_ENDIAN)
        info.writeByte(((length ushr 8) and 0xFF).toByte())
        info.writeByte((length and 0xFF).toByte())
        info.writeByte((fullLabelLen and 0xFF).toByte())
        for (ch in LABEL_PREFIX) info.writeByte(ch.code.toByte())
        for (ch in label) info.writeByte(ch.code.toByte())
        info.writeByte((context.remaining() and 0xFF).toByte())
        writeView(info, context)
        info.resetForRead()

        val out = factory.allocate(length, ByteOrder.BIG_ENDIAN)
        val prkPos = secret.position()
        Hkdf.expandInto(secret, Info.Of(info), length, out)
        secret.position(prkPos)
        out.resetForRead()
        return out
    }

    /** `Derive-Secret(secret, label, messages) = HKDF-Expand-Label(secret, label, Hash(messages), 32)`. */
    fun deriveSecret(
        secret: ReadBuffer,
        label: String,
        transcriptHash: ReadBuffer,
    ): ReadBuffer = expandLabel(secret, label, transcriptHash, HASH_LEN)

    /** The Early Secret `HKDF-Extract(salt=0, ikm=0^32)` — the root with no PSK (RFC 8446 §7.1). */
    fun earlySecret(): ReadBuffer = extract(null, zeros)

    /** The Handshake Secret `HKDF-Extract(salt=Derive(early,"derived",""), ikm=ECDHE)`. */
    fun handshakeSecret(
        earlySecret: ReadBuffer,
        ecdheSecret: ReadBuffer,
    ): ReadBuffer = extract(derived(earlySecret), ecdheSecret)

    /** The Master Secret `HKDF-Extract(salt=Derive(handshake,"derived",""), ikm=0^32)`. */
    fun masterSecret(handshakeSecret: ReadBuffer): ReadBuffer = extract(derived(handshakeSecret), zeros)

    /** The `"finished"` HMAC key for a Finished / verify_data derived from a sender's traffic secret. */
    fun finishedKey(baseSecret: ReadBuffer): ReadBuffer = expandLabel(baseSecret, "finished", empty, HASH_LEN)

    /**
     * A Finished `verify_data` = `HMAC-SHA256(finished_key(baseSecret), transcriptHash)` (RFC 8446 §4.4.4).
     * [transcriptHash] is the running hash of the handshake context up to (not including) the Finished.
     */
    fun verifyData(
        baseSecret: ReadBuffer,
        transcriptHash: ReadBuffer,
    ): ReadBuffer {
        val key = finishedKey(baseSecret)
        val kp = key.position()
        val mac = HmacSha256Mac(key)
        key.position(kp)
        val tp = transcriptHash.position()
        mac.update(transcriptHash)
        transcriptHash.position(tp)
        val out = factory.allocate(HASH_LEN, ByteOrder.BIG_ENDIAN)
        mac.doFinalInto(out)
        mac.close()
        out.resetForRead()
        return out
    }

    // ── HKDF-Extract + the "derived" bridge ────────────────────────────────────────────────────────

    private fun derived(secret: ReadBuffer): ReadBuffer = expandLabel(secret, "derived", emptyTranscriptHash, HASH_LEN)

    private fun extract(
        salt: ReadBuffer?,
        ikm: ReadBuffer,
    ): ReadBuffer {
        val out = factory.allocate(HASH_LEN, ByteOrder.BIG_ENDIAN)
        val ip = ikm.position()
        if (salt == null) {
            Hkdf.extractInto(Salt.None, ikm, out)
        } else {
            val sp = salt.position()
            Hkdf.extractInto(Salt.Of(salt), ikm, out)
            salt.position(sp)
        }
        ikm.position(ip)
        out.resetForRead()
        return out
    }

    private val empty: ReadBuffer by lazy {
        val b = factory.allocate(1, ByteOrder.BIG_ENDIAN)
        b.resetForRead()
        b.setLimit(0)
        b
    }

    private fun writeView(
        dest: WriteBuffer,
        view: ReadBuffer,
    ) {
        val p = view.position()
        dest.write(view)
        view.position(p)
    }

    companion object {
        const val HASH_LEN = 32 // SHA-256
        const val KEY_LEN = 16 // AES-128
        const val IV_LEN = 12 // AEAD nonce
        const val SN_KEY_LEN = 16 // record-number encryption (AES-128)
        private const val LABEL_PREFIX = "dtls13"

        const val CLIENT_HANDSHAKE_LABEL = "c hs traffic"
        const val SERVER_HANDSHAKE_LABEL = "s hs traffic"
        const val CLIENT_APPLICATION_LABEL = "c ap traffic"
        const val SERVER_APPLICATION_LABEL = "s ap traffic"
    }
}

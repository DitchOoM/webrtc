package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import com.ditchoom.buffer.crypto.HmacSha256Mac
import com.ditchoom.buffer.crypto.secure
import com.ditchoom.buffer.freeIfNeeded

/**
 * The TLS 1.2 PRF and the DTLS 1.2 key schedule for the WebRTC cipher suite
 * `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (RFC 5246 §5, §6.3, §8.1; RFC 7627 for the extended master
 * secret). The suite's hash is SHA-256, so the PRF is `P_SHA256` built on buffer-crypto's
 * [HmacSha256Mac]. Pure functions over buffers — no clock, no I/O, no RNG.
 *
 * ```
 * PRF(secret, label, seed)  = P_SHA256(secret, label ‖ seed)
 * P_hash(secret, seed)      = HMAC(secret, A(1) ‖ seed) ‖ HMAC(secret, A(2) ‖ seed) ‖ …
 *   A(0) = seed ;  A(i) = HMAC(secret, A(i-1))
 * ```
 */
internal class Tls12KeySchedule(
    callerFactory: BufferFactory,
) {
    /**
     * **Every buffer this class allocates is key material or a seed over it, so all of them are wiped on
     * free** — the same reasoning as [Tls13KeySchedule], and load-bearing for the same reason: these are
     * now *released* rather than leaked, and an unwiped master secret handed back to a `BufferPool` is a
     * chunk the next `allocate()` gets. That would trade a leak for key disclosure, which is worse.
     */
    private val factory: BufferFactory = callerFactory.secure()

    /** `PRF(secret, label, seed)` truncated to [outLen] bytes (RFC 5246 §5). */
    fun prf(
        secret: ReadBuffer,
        label: String,
        seed: ReadBuffer,
        outLen: Int,
    ): ReadBuffer {
        val labelSeed = factory.allocate(label.length + seed.remaining(), ByteOrder.BIG_ENDIAN)
        for (ch in label) labelSeed.writeByte(ch.code.toByte())
        writeView(labelSeed, seed)
        labelSeed.resetForRead()
        // `labelSeed` exists for this one expansion — one per derived secret, key block and verify_data,
        // which is what made a 1.2 handshake cost dozens of chunks.
        return try {
            pSha256(secret, labelSeed, outLen)
        } finally {
            labelSeed.freeIfNeeded()
        }
    }

    /**
     * The 48-byte master secret. With [sessionHash] non-null this is the RFC 7627 extended master secret
     * (`PRF(pms, "extended master secret", session_hash)`), which WebRTC always negotiates; the legacy
     * form (`PRF(pms, "master secret", client_random ‖ server_random)`) is kept for a peer that omits the
     * extension.
     */
    fun masterSecret(
        premaster: ReadBuffer,
        clientRandom: ReadBuffer,
        serverRandom: ReadBuffer,
        sessionHash: ReadBuffer?,
    ): ReadBuffer =
        if (sessionHash != null) {
            prf(premaster, "extended master secret", sessionHash, MASTER_SECRET_BYTES)
        } else {
            withSeed(concat(clientRandom, serverRandom)) { prf(premaster, "master secret", it, MASTER_SECRET_BYTES) }
        }

    /**
     * The key block `PRF(master_secret, "key expansion", server_random ‖ client_random)`, sized to
     * [outLen]. For AES-128-GCM the caller slices it as
     * `client_write_key(16) ‖ server_write_key(16) ‖ client_write_IV(4) ‖ server_write_IV(4)`.
     */
    fun keyBlock(
        masterSecret: ReadBuffer,
        serverRandom: ReadBuffer,
        clientRandom: ReadBuffer,
        outLen: Int,
    ): ReadBuffer = withSeed(concat(serverRandom, clientRandom)) { prf(masterSecret, "key expansion", it, outLen) }

    /**
     * The 12-byte Finished `verify_data` = `PRF(master_secret, finished_label, Hash(handshake_messages))`.
     * [finishedLabel] is `"client finished"` or `"server finished"`; [transcriptHash] is the SHA-256 over
     * every handshake message so far (each in its normalized 12-byte-header form — the DTLS gotcha).
     */
    fun verifyData(
        masterSecret: ReadBuffer,
        finishedLabel: String,
        transcriptHash: ReadBuffer,
    ): ReadBuffer = prf(masterSecret, finishedLabel, transcriptHash, VERIFY_DATA_BYTES)

    /**
     * `PRF(master_secret, label, client_random ‖ server_random [‖ uint16(context.len) ‖ context])`
     * truncated to [length] — the RFC 5705 TLS 1.2 exporter, DTLS-SRTP's key derivation (RFC 5764). A null
     * [context] is the DTLS-SRTP case (no context) — the seed is just the two randoms, with no length bytes
     * (RFC 5705 §4 distinguishes "no context" from an empty one). Matches `SSL_export_keying_material`.
     */
    fun exportKeyingMaterial(
        masterSecret: ReadBuffer,
        label: String,
        clientRandom: ReadBuffer,
        serverRandom: ReadBuffer,
        context: ReadBuffer?,
        length: Int,
    ): ReadBuffer {
        val seed =
            if (context == null) {
                concat(clientRandom, serverRandom)
            } else {
                val out =
                    factory.allocate(
                        clientRandom.remaining() + serverRandom.remaining() + 2 + context.remaining(),
                        ByteOrder.BIG_ENDIAN,
                    )
                writeView(out, clientRandom)
                writeView(out, serverRandom)
                out.writeShort(context.remaining().toShort()) // uint16 context length
                writeView(out, context)
                out.resetForRead()
                out
            }
        return withSeed(seed) { prf(masterSecret, label, it, length) }
    }

    /**
     * Run [block] over a seed this class built for exactly one PRF call, and give the seed back after.
     *
     * The three callers all compose their seed from buffers they do **not** own (the two randoms, a
     * caller-supplied context), so the concatenation is the only thing here that could be freed — and it
     * is anonymous at the call site, which is precisely why the release cannot live there.
     */
    private inline fun withSeed(
        seed: ReadBuffer,
        block: (ReadBuffer) -> ReadBuffer,
    ): ReadBuffer =
        try {
            block(seed)
        } finally {
            seed.freeIfNeeded()
        }

    // ── P_SHA256 ─────────────────────────────────────────────────────────────────────────────────

    private fun pSha256(
        secret: ReadBuffer,
        seed: ReadBuffer,
        outLen: Int,
    ): ReadBuffer {
        val out = factory.allocate(outLen, ByteOrder.BIG_ENDIAN)
        var a = hmac(secret, seed) // A(1)
        var written = 0
        while (written < outLen) {
            val block = hmac(secret, a, seed) // HMAC(secret, A(i) ‖ seed)
            val take = minOf(HMAC_BYTES, outLen - written)
            block.setLimit(take)
            block.position(0)
            out.write(block)
            block.freeIfNeeded() // copied into `out`; one of these per 32 bytes of every derived secret
            written += take
            if (written < outLen) {
                // A(i) is superseded here, and **a superseded field is a leak**: the previous A was the
                // only reference to that buffer, so overwriting it without a release drops one chunk per
                // PRF round. Free before reassigning, never after.
                val next = hmac(secret, a) // A(i+1) = HMAC(secret, A(i))
                a.freeIfNeeded()
                a = next
            }
        }
        a.freeIfNeeded() // the last A(i), which no round consumed
        out.resetForRead()
        return out
    }

    /** `HMAC-SHA256(key, m1 [‖ m2])` into a fresh 32-byte read buffer; inputs' positions are preserved. */
    private fun hmac(
        key: ReadBuffer,
        m1: ReadBuffer,
        m2: ReadBuffer? = null,
    ): ReadBuffer {
        val kp = key.position()
        val mac = HmacSha256Mac(key)
        key.position(kp)
        val p1 = m1.position()
        mac.update(m1)
        m1.position(p1)
        if (m2 != null) {
            val p2 = m2.position()
            mac.update(m2)
            m2.position(p2)
        }
        val dest = factory.allocate(HMAC_BYTES, ByteOrder.BIG_ENDIAN)
        mac.doFinalInto(dest)
        mac.close()
        dest.resetForRead()
        return dest
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

    companion object {
        const val MASTER_SECRET_BYTES = 48
        const val VERIFY_DATA_BYTES = 12
        private const val HMAC_BYTES = 32

        const val CLIENT_FINISHED_LABEL = "client finished"
        const val SERVER_FINISHED_LABEL = "server finished"
    }
}

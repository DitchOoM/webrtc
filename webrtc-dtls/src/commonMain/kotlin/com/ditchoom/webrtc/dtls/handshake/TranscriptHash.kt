package com.ditchoom.webrtc.dtls.handshake

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.crypto.Sha256Digest
import com.ditchoom.webrtc.dtls.wire.HandshakeMessage

/**
 * The running handshake transcript for the TLS 1.2 Finished / CertificateVerify / extended-master-secret
 * hashes. Every handshake message contributes in its **normalized 12-byte-DTLS-header** form
 * (`fragment_offset = 0`, `fragment_length = length`) — the spike gotcha; [HandshakeMessage.transcriptInto]
 * emits exactly that. ChangeCipherSpec is a separate content type and is **not** part of the transcript.
 *
 * The bytes are retained (not folded into a streaming digest) because the schedule needs the hash at
 * several points — `session_hash` at ClientKeyExchange time, then again for each Finished — and
 * [Sha256Digest] is one-shot. The transcript is small (a few KB), so re-hashing on demand is cheap. A
 * client that receives a HelloVerifyRequest calls [reset] so the transcript restarts at the second
 * ClientHello (RFC 6347 §4.2.6: the initial ClientHello + HVR are excluded).
 */
internal class TranscriptHash(
    private val factory: BufferFactory,
    // DTLS 1.3 hashes each message in the TLS 1.3 4-byte-header form (msg_type ‖ length ‖ body), omitting
    // the DTLS message_seq/fragment fields (RFC 9147 §5.2); DTLS 1.2 hashes the full normalized 12-byte
    // header. The FSM picks the mode; everything else (session_hash, Finished, CertVerify input) is common.
    private val dtls13: Boolean = false,
) {
    private val messages = mutableListOf<ReadBuffer>()

    /** Appends [message] in its normalized transcript form (12-byte DTLS 1.2 or 4-byte DTLS 1.3 header). */
    fun append(message: HandshakeMessage) {
        val size = if (dtls13) message.transcript13Size else HandshakeMessage.HEADER_BYTES + message.length
        val buf = factory.allocate(size, ByteOrder.BIG_ENDIAN)
        if (dtls13) message.transcript13Into(buf) else message.transcriptInto(buf)
        buf.resetForRead()
        messages += buf
    }

    /** Discards everything appended so far (client received a HelloVerifyRequest). */
    fun reset() {
        messages.clear()
    }

    /**
     * The raw concatenation of every appended message, in order — the `handshake_messages` a TLS 1.2
     * CertificateVerify signs over (RFC 5246 §7.4.8; the signature scheme applies its own hash). Freshly
     * allocated, read-ready.
     */
    fun currentBytes(): ReadBuffer {
        val total = messages.sumOf { it.remaining() }
        val out = factory.allocate(maxOf(total, 1), ByteOrder.BIG_ENDIAN)
        for (m in messages) {
            val p = m.position()
            out.write(m)
            m.position(p)
        }
        out.resetForRead()
        return out
    }

    /** SHA-256 over every appended message, in order — the current transcript hash (32 bytes, read-ready). */
    fun currentSha256(): ReadBuffer {
        val digest = Sha256Digest()
        for (m in messages) {
            val p = m.position()
            digest.update(m)
            m.position(p)
        }
        val out = factory.allocate(32, ByteOrder.BIG_ENDIAN)
        digest.digestInto(out)
        digest.close()
        out.resetForRead()
        return out
    }
}

package com.ditchoom.webrtc.dtls.wire

import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import kotlin.jvm.JvmInline

// Shared wire helpers for the hand-written DTLS layers (records, handshake messages, TLS extensions).
// DTLS is big-endian throughout (RFC 6347/9147). These mirror the SCTP/STUN codec helpers: absolute
// big-endian reads that never disturb the buffer position, plus a zero-copy slice view. No crypto here.

/** Big-endian absolute 8-bit read. */
internal fun ReadBuffer.u8(index: Int): Int = get(index).toInt() and 0xFF

/** Big-endian absolute 16-bit read — byte-order-independent. */
internal fun ReadBuffer.u16(index: Int): Int = (u8(index) shl 8) or u8(index + 1)

/** Big-endian absolute 24-bit read (DTLS handshake `uint24` length / fragment fields). */
internal fun ReadBuffer.u24(index: Int): Int = (u8(index) shl 16) or (u8(index + 1) shl 8) or u8(index + 2)

/** Big-endian absolute 32-bit read. */
internal fun ReadBuffer.u32(index: Int): Long = (u16(index).toLong() shl 16) or u16(index + 2).toLong()

/** Big-endian absolute 48-bit read (the DTLS record `sequence_number`). */
internal fun ReadBuffer.u48(index: Int): Long = (u16(index).toLong() shl 32) or (u16(index + 2).toLong() shl 16) or u16(index + 4).toLong()

/** Writes a big-endian `uint24` (DTLS handshake length / fragment fields). [value] must fit 24 bits. */
internal fun WriteBuffer.writeU24(value: Int) {
    writeByte(((value ushr 16) and 0xFF).toByte())
    writeByte(((value ushr 8) and 0xFF).toByte())
    writeByte((value and 0xFF).toByte())
}

/** Writes a big-endian `uint48` (the DTLS record `sequence_number`). [value] must be non-negative. */
internal fun WriteBuffer.writeU48(value: Long) {
    writeByte(((value ushr 40) and 0xFF).toByte())
    writeByte(((value ushr 32) and 0xFF).toByte())
    writeByte(((value ushr 24) and 0xFF).toByte())
    writeByte(((value ushr 16) and 0xFF).toByte())
    writeByte(((value ushr 8) and 0xFF).toByte())
    writeByte((value and 0xFF).toByte())
}

/**
 * A zero-copy big-endian slice view of `[start, endExclusive)` that does **not** disturb this buffer's
 * position/limit (mirrors the SCTP/STUN `sliceOf`). The slice shares storage — a view must not outlive
 * the datagram's scope.
 */
internal fun ReadBuffer.sliceOf(
    start: Int,
    endExclusive: Int,
): ReadBuffer {
    val savedPos = position()
    val savedLimit = limit()
    position(0)
    setLimit(endExclusive)
    position(start)
    val view = slice(ByteOrder.BIG_ENDIAN)
    position(0)
    setLimit(savedLimit)
    position(savedPos)
    return view
}

/** Writes [view]'s remaining bytes without disturbing its position (decoded views are shared). */
internal fun WriteBuffer.writeView(view: ReadBuffer) {
    val p = view.position()
    write(view)
    view.position(p)
}

/**
 * A DTLS/TLS record content type (RFC 6347 §4.1). Wrapped so a call site never reads a bare `type == 22`;
 * unknown values are preserved for a typed drop rather than a crash (T0 totality).
 */
@JvmInline
internal value class ContentType(
    val value: Int,
) {
    companion object {
        val ChangeCipherSpec = ContentType(20)
        val Alert = ContentType(21)
        val Handshake = ContentType(22)
        val ApplicationData = ContentType(23)

        // DTLS 1.3 unified header records carry the connection-id/epoch bits high; the 0b001xxxxx family
        // is the DTLSCiphertext "unified header" first byte (RFC 9147 §4). The 1.2 record layer only ever
        // sees the four legacy content types above; anything else is dropped by the framing layer.
    }
}

/**
 * A DTLS protocol version on the wire (RFC 6347): DTLS uses the 1's-complement encoding, so DTLS 1.2 is
 * `0xFEFD` and DTLS 1.0 is `0xFEFF`. DTLS 1.3 keeps `0xFEFD` in the legacy record `version` field and
 * negotiates the real version through the `supported_versions` extension (`0xFEFC`).
 */
@JvmInline
internal value class ProtocolVersion(
    val value: Int,
) {
    companion object {
        val Dtls10 = ProtocolVersion(0xFEFF)
        val Dtls12 = ProtocolVersion(0xFEFD)
        val Dtls13 = ProtocolVersion(0xFEFC)
    }
}

/** A DTLS handshake message type (RFC 6347 §4.3.2 / RFC 8446 §4). Unknown values are preserved. */
@JvmInline
internal value class HandshakeType(
    val value: Int,
) {
    companion object {
        val HelloRequest = HandshakeType(0)
        val ClientHello = HandshakeType(1)
        val ServerHello = HandshakeType(2)
        val HelloVerifyRequest = HandshakeType(3)
        val NewSessionTicket = HandshakeType(4)
        val EncryptedExtensions = HandshakeType(8) // DTLS 1.3
        val Certificate = HandshakeType(11)
        val ServerKeyExchange = HandshakeType(12)
        val CertificateRequest = HandshakeType(13)
        val ServerHelloDone = HandshakeType(14)
        val CertificateVerify = HandshakeType(15)
        val ClientKeyExchange = HandshakeType(16)
        val Finished = HandshakeType(20)
    }
}

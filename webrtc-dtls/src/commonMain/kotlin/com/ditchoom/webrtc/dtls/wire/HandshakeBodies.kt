package com.ditchoom.webrtc.dtls.wire

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import kotlin.jvm.JvmInline

/** A TLS cipher suite code point (RFC 8446 / RFC 8422). */
@JvmInline
internal value class CipherSuiteId(
    val value: Int,
) {
    companion object {
        val TlsEcdheEcdsaAes128GcmSha256 = CipherSuiteId(0xC02B) // DTLS 1.2 WebRTC default
        val TlsAes128GcmSha256 = CipherSuiteId(0x1301) // DTLS 1.3
        val TlsAes256GcmSha384 = CipherSuiteId(0x1302) // DTLS 1.3
        val TlsChacha20Poly1305Sha256 = CipherSuiteId(0x1303) // DTLS 1.3
    }
}

/** The 32-byte `Random` (RFC 5246 §7.4.1.2): 4-byte `gmt_unix_time` ‖ 28 random bytes. */
internal const val RANDOM_BYTES = 32

/**
 * ClientHello body (RFC 6347 §4.2 + RFC 5246 §7.4.1.2). The DTLS `cookie` vector sits between
 * `session_id` and `cipher_suites`; an initial ClientHello carries an empty cookie, the retransmit after
 * a HelloVerifyRequest echoes the server's cookie.
 */
internal class ClientHello(
    val version: ProtocolVersion,
    val random: ReadBuffer,
    val sessionId: ReadBuffer,
    val cookie: ReadBuffer,
    val cipherSuites: List<CipherSuiteId>,
    val extensions: List<Extension>,
) {
    fun bodyInto(dest: WriteBuffer) {
        dest.writeShort(version.value.toShort())
        dest.writeView(random)
        writeU8Vector(dest, sessionId)
        writeU8Vector(dest, cookie)
        dest.writeShort((cipherSuites.size * 2).toShort())
        for (c in cipherSuites) dest.writeShort(c.value.toShort())
        dest.writeByte(1) // compression methods length
        dest.writeByte(0) // null compression
        Extension.encodeList(dest, extensions)
    }

    companion object {
        fun parse(body: ReadBuffer): ClientHello? {
            val n = body.remaining()
            var off = 0
            if (off + 2 + RANDOM_BYTES > n) return null
            val version = ProtocolVersion(body.u16(off))
            off += 2
            val random = body.sliceOf(off, off + RANDOM_BYTES)
            off += RANDOM_BYTES
            val sid = readU8Vector(body, off, n) ?: return null
            off = sid.second
            val cookie = readU8Vector(body, off, n) ?: return null
            off = cookie.second
            if (off + 2 > n) return null
            val csLen = body.u16(off)
            off += 2
            if (csLen % 2 != 0 || off + csLen > n) return null
            val suites = ArrayList<CipherSuiteId>(csLen / 2)
            repeat(csLen / 2) {
                suites += CipherSuiteId(body.u16(off))
                off += 2
            }
            if (off + 1 > n) return null
            val compLen = body.u8(off)
            off += 1 + compLen
            if (off > n) return null
            val exts = Extension.decodeList(body, off, n) ?: return null
            return ClientHello(version, random, sid.first, cookie.first, suites, exts)
        }
    }
}

/** HelloVerifyRequest body (RFC 6347 §4.2.1): the stateless-cookie challenge. */
internal class HelloVerifyRequest(
    val version: ProtocolVersion,
    val cookie: ReadBuffer,
) {
    fun bodyInto(dest: WriteBuffer) {
        dest.writeShort(version.value.toShort())
        writeU8Vector(dest, cookie)
    }

    companion object {
        fun parse(body: ReadBuffer): HelloVerifyRequest? {
            val n = body.remaining()
            if (n < 3) return null
            val version = ProtocolVersion(body.u16(0))
            val cookie = readU8Vector(body, 2, n) ?: return null
            return HelloVerifyRequest(version, cookie.first)
        }
    }
}

/** ServerHello body (RFC 5246 §7.4.1.3). One negotiated cipher suite; DTLS 1.3 hides the real version in `supported_versions`. */
internal class ServerHello(
    val version: ProtocolVersion,
    val random: ReadBuffer,
    val sessionId: ReadBuffer,
    val cipherSuite: CipherSuiteId,
    val extensions: List<Extension>,
) {
    fun bodyInto(dest: WriteBuffer) {
        dest.writeShort(version.value.toShort())
        dest.writeView(random)
        writeU8Vector(dest, sessionId)
        dest.writeShort(cipherSuite.value.toShort())
        dest.writeByte(0) // null compression
        Extension.encodeList(dest, extensions)
    }

    companion object {
        fun parse(body: ReadBuffer): ServerHello? {
            val n = body.remaining()
            var off = 0
            if (off + 2 + RANDOM_BYTES > n) return null
            val version = ProtocolVersion(body.u16(off))
            off += 2
            val random = body.sliceOf(off, off + RANDOM_BYTES)
            off += RANDOM_BYTES
            val sid = readU8Vector(body, off, n) ?: return null
            off = sid.second
            if (off + 3 > n) return null
            val suite = CipherSuiteId(body.u16(off))
            off += 2
            off += 1 // compression method
            val exts = Extension.decodeList(body, off, n) ?: return null
            return ServerHello(version, random, sid.first, suite, exts)
        }
    }
}

/**
 * Certificate body (RFC 5246 §7.4.2) — a `certificate_list` of DER certs, each a `uint24`-prefixed
 * opaque, the whole list `uint24`-prefixed. WebRTC sends exactly one self-signed cert (no chain).
 */
internal class CertificateMessage(
    val certificates: List<ReadBuffer>,
) {
    fun bodyInto(dest: WriteBuffer) {
        val total = certificates.sumOf { 3 + it.remaining() }
        dest.writeU24(total)
        for (c in certificates) {
            dest.writeU24(c.remaining())
            dest.writeView(c)
        }
    }

    companion object {
        fun parse(body: ReadBuffer): CertificateMessage? {
            val n = body.remaining()
            if (n < 3) return null
            val total = body.u24(0)
            var off = 3
            if (off + total > n) return null
            val end = off + total
            val certs = ArrayList<ReadBuffer>(1)
            while (off < end) {
                if (off + 3 > end) return null
                val len = body.u24(off)
                off += 3
                if (off + len > end) return null
                certs += body.sliceOf(off, off + len)
                off += len
            }
            return CertificateMessage(certs)
        }
    }
}

/**
 * The ephemeral ECDH parameters + signature of a ServerKeyExchange (RFC 8422 §5.4), for a `named_curve`
 * of `secp256r1`. [signedParams] is the `curve_type ‖ namedcurve ‖ point` blob the server signs over
 * (prefixed by both randoms) — retained so the client can verify the signature without re-serializing.
 */
internal class ServerKeyExchange(
    val curve: NamedGroup,
    val publicPoint: ReadBuffer,
    val signatureScheme: SignatureSchemeId,
    val signature: ReadBuffer,
) {
    fun bodyInto(dest: WriteBuffer) {
        dest.writeByte(NAMED_CURVE.toByte()) // ECCurveType.named_curve
        dest.writeShort(curve.value.toShort())
        writeU8Vector(dest, publicPoint)
        dest.writeShort(signatureScheme.value.toShort())
        dest.writeShort(signature.remaining().toShort())
        dest.writeView(signature)
    }

    /** The bytes covered by the signature: `curve_type ‖ namedcurve ‖ point_len ‖ point` (params only). */
    fun serverEcdhParamsInto(dest: WriteBuffer) {
        dest.writeByte(NAMED_CURVE.toByte())
        dest.writeShort(curve.value.toShort())
        writeU8Vector(dest, publicPoint)
    }

    companion object {
        private const val NAMED_CURVE = 3

        fun parse(body: ReadBuffer): ServerKeyExchange? {
            val n = body.remaining()
            if (n < 4 || body.u8(0) != NAMED_CURVE) return null
            val curve = NamedGroup(body.u16(1))
            val point = readU8Vector(body, 3, n) ?: return null
            var off = point.second
            if (off + 4 > n) return null
            val scheme = SignatureSchemeId(body.u16(off))
            off += 2
            val sigLen = body.u16(off)
            off += 2
            if (off + sigLen > n) return null
            return ServerKeyExchange(curve, point.first, scheme, body.sliceOf(off, off + sigLen))
        }
    }
}

/** ClientKeyExchange for ECDHE (RFC 8422 §5.7): just the client's ephemeral public point. */
internal class ClientKeyExchange(
    val publicPoint: ReadBuffer,
) {
    fun bodyInto(dest: WriteBuffer) = writeU8Vector(dest, publicPoint)

    companion object {
        fun parse(body: ReadBuffer): ClientKeyExchange? {
            val n = body.remaining()
            val point = readU8Vector(body, 0, n) ?: return null
            if (point.second != n) return null
            return ClientKeyExchange(point.first)
        }
    }
}

/** CertificateVerify (RFC 5246 §7.4.8): the signature over the handshake transcript. */
internal class CertificateVerify(
    val signatureScheme: SignatureSchemeId,
    val signature: ReadBuffer,
) {
    fun bodyInto(dest: WriteBuffer) {
        dest.writeShort(signatureScheme.value.toShort())
        dest.writeShort(signature.remaining().toShort())
        dest.writeView(signature)
    }

    companion object {
        fun parse(body: ReadBuffer): CertificateVerify? {
            val n = body.remaining()
            if (n < 4) return null
            val scheme = SignatureSchemeId(body.u16(0))
            val sigLen = body.u16(2)
            if (4 + sigLen != n) return null
            return CertificateVerify(scheme, body.sliceOf(4, n))
        }
    }
}

// ── length-prefixed opaque vector helpers ────────────────────────────────────────────────────────

/** Writes a `uint8`-length-prefixed opaque vector (session_id, cookie, ECPoint). */
internal fun writeU8Vector(
    dest: WriteBuffer,
    bytes: ReadBuffer,
) {
    dest.writeByte(bytes.remaining().toByte())
    dest.writeView(bytes)
}

/**
 * Reads a `uint8`-length-prefixed opaque vector at [off] within `[0, n)`. Returns the zero-copy value
 * view and the offset just past it, or null on overrun. Never throws.
 */
internal fun readU8Vector(
    body: ReadBuffer,
    off: Int,
    n: Int,
): Pair<ReadBuffer, Int>? {
    if (off + 1 > n) return null
    val len = body.u8(off)
    val start = off + 1
    val end = start + len
    if (end > n) return null
    return body.sliceOf(start, end) to end
}

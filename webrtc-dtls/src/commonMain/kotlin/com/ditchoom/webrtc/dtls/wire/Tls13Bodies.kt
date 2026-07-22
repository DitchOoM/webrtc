package com.ditchoom.webrtc.dtls.wire

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer

/**
 * The TLS 1.3 / DTLS 1.3 handshake extensions and message bodies the WebRTC handshake needs (RFC 8446 §4,
 * RFC 9147). These sit alongside the 1.2 bodies in [HandshakeBodies]; the ClientHello/ServerHello wire
 * frames themselves are reused from there (a 1.3 hello is a 1.2-shaped hello with 1.3 extensions).
 *
 * The `secp256r1` (P-256) and `x25519` key-exchange groups and `ecdsa_secp256r1_sha256` signatures are
 * modelled — the WebRTC common profile. The client lists **every** supported group in `supported_groups`
 * (browser-matching) but sends a `key_share` for only its preferred group, so a server that prefers the
 * other group answers with a HelloRetryRequest ([helloRetryRandom]); the common case (the peer accepts
 * our key_share group) still completes in one round trip (see [com.ditchoom.webrtc.dtls.KeyExchangeGroup]).
 */
internal object Tls13Bodies {
    /** The (EC)DHE groups this DTLS 1.3 stack can key-share, by wire code point (RFC 8446 §4.2.7). */
    val supportedGroups: Set<Int> = setOf(NamedGroup.X25519.value, NamedGroup.Secp256r1.value)

    /**
     * The special ServerHello `Random` that marks a message as a HelloRetryRequest (RFC 8446 §4.1.3):
     * `SHA-256("HelloRetryRequest")`. A ServerHello whose random equals these 32 bytes is an HRR, not a
     * real ServerHello. Emitted as one contiguous span so both the writer and the matcher share it.
     */
    private val helloRetryRandomBytes: List<Int> =
        listOf(
            0xCF,
            0x21,
            0xAD,
            0x74,
            0xE5,
            0x9A,
            0x61,
            0x11,
            0xBE,
            0x1D,
            0x8C,
            0x02,
            0x1E,
            0x65,
            0xB8,
            0x91,
            0xC2,
            0xA2,
            0x11,
            0x16,
            0x7A,
            0xBB,
            0x8C,
            0x5E,
            0x07,
            0x9E,
            0x09,
            0xE2,
            0xC8,
            0xA8,
            0x33,
            0x9C,
        )

    /** A fresh 32-byte HelloRetryRequest `Random` (the fixed RFC 8446 sentinel), read-ready. */
    fun helloRetryRandom(factory: BufferFactory): ReadBuffer {
        val b = factory.allocate(32, ByteOrder.BIG_ENDIAN)
        for (v in helloRetryRandomBytes) b.writeByte(v.toByte())
        b.resetForRead()
        return b
    }

    /** True if [random] (a 32-byte ServerHello `Random` view) is the HelloRetryRequest sentinel. */
    fun isHelloRetryRandom(random: ReadBuffer): Boolean {
        if (random.remaining() != 32) return false
        val p = random.position()
        for (i in 0 until 32) {
            if ((random.u8(p + i)) != helloRetryRandomBytes[i]) return false
        }
        return true
    }

    /** A parsed `key_share` entry: its [group] and raw public [point] (a zero-copy view into the body). */
    class KeyShareEntry(
        val group: NamedGroup,
        val point: ReadBuffer,
    )

    // ── supported_groups (RFC 8446 §4.2.7) ─────────────────────────────────────────────────────────

    /**
     * ClientHello `supported_groups`: every group in [groups] (the preferred/key-shared group first). The
     * client key-shares only the first, so a server preferring a later group answers with a HelloRetryRequest.
     */
    fun supportedGroupsClientHello(
        groups: List<NamedGroup>,
        factory: BufferFactory,
    ): Extension {
        val listLen = groups.size * 2
        val body = factory.allocate(2 + listLen, ByteOrder.BIG_ENDIAN)
        body.writeShort(listLen.toShort())
        for (g in groups) body.writeShort(g.value.toShort())
        body.resetForRead()
        return Extension(ExtensionType.SupportedGroups, body)
    }

    /** True if a ClientHello `supported_groups` body advertises [group] (used by the server's HRR decision). */
    fun supportedGroupsContains(
        body: ReadBuffer,
        group: NamedGroup,
    ): Boolean {
        val n = body.remaining()
        if (n < 2) return false
        val listLen = body.u16(0)
        var off = 2
        val end = minOf(2 + listLen, n)
        while (off + 2 <= end) {
            if (body.u16(off) == group.value) return true
            off += 2
        }
        return false
    }

    // ── key_share (RFC 8446 §4.2.8) ────────────────────────────────────────────────────────────────

    /** HelloRetryRequest `key_share`: just the 2-byte `selected_group` the server wants the client to use. */
    fun keyShareHelloRetryRequest(
        group: NamedGroup,
        factory: BufferFactory,
    ): Extension {
        val body = factory.allocate(2, ByteOrder.BIG_ENDIAN)
        body.writeShort(group.value.toShort())
        body.resetForRead()
        return Extension(ExtensionType.KeyShare, body)
    }

    /** The `selected_group` from a HelloRetryRequest `key_share` body (a bare 2-byte group), or null. */
    fun parseKeyShareSelectedGroup(body: ReadBuffer): NamedGroup? = if (body.remaining() >= 2) NamedGroup(body.u16(0)) else null

    /** ClientHello `key_share`: a `client_shares` list with our single [group] [point] (raw SEC1/RFC 7748). */
    fun keyShareClientHello(
        group: NamedGroup,
        point: ReadBuffer,
        factory: BufferFactory,
    ): Extension {
        val entryLen = 2 + 2 + point.remaining()
        val body = factory.allocate(2 + entryLen, ByteOrder.BIG_ENDIAN)
        body.writeShort(entryLen.toShort()) // client_shares list length
        writeKeyShareEntry(body, group, point)
        body.resetForRead()
        return Extension(ExtensionType.KeyShare, body)
    }

    /** ServerHello `key_share`: exactly one `server_share` KeyShareEntry for [group] (no list wrapper). */
    fun keyShareServerHello(
        group: NamedGroup,
        point: ReadBuffer,
        factory: BufferFactory,
    ): Extension {
        val body = factory.allocate(2 + 2 + point.remaining(), ByteOrder.BIG_ENDIAN)
        writeKeyShareEntry(body, group, point)
        body.resetForRead()
        return Extension(ExtensionType.KeyShare, body)
    }

    private fun writeKeyShareEntry(
        dest: WriteBuffer,
        group: NamedGroup,
        point: ReadBuffer,
    ) {
        dest.writeShort(group.value.toShort())
        dest.writeShort(point.remaining().toShort())
        dest.writeView(point)
    }

    /** The first **supported** key-exchange entry from a ClientHello `key_share` body, or null if none. */
    fun parseKeyShareClientHello(body: ReadBuffer): KeyShareEntry? {
        val n = body.remaining()
        if (n < 2) return null
        val listLen = body.u16(0)
        var off = 2
        val end = minOf(2 + listLen, n)
        while (off + 4 <= end) {
            val group = body.u16(off)
            val keyLen = body.u16(off + 2)
            val keyStart = off + 4
            val keyEnd = keyStart + keyLen
            if (keyEnd > end) return null
            if (group in supportedGroups) return KeyShareEntry(NamedGroup(group), body.sliceOf(keyStart, keyEnd))
            off = keyEnd
        }
        return null
    }

    /** The key-exchange entry from a ServerHello `key_share` body, or null if the group is unsupported. */
    fun parseKeyShareServerHello(body: ReadBuffer): KeyShareEntry? {
        val n = body.remaining()
        if (n < 4) return null
        val group = body.u16(0)
        val keyLen = body.u16(2)
        if (group !in supportedGroups || 4 + keyLen > n) return null
        return KeyShareEntry(NamedGroup(group), body.sliceOf(4, 4 + keyLen))
    }

    // ── supported_versions (RFC 8446 §4.2.1) ───────────────────────────────────────────────────────

    /** ClientHello `supported_versions`: offer DTLS 1.3 then DTLS 1.2 (preference order). */
    fun supportedVersionsClientHello(factory: BufferFactory): Extension {
        val body = factory.allocate(1 + 4, ByteOrder.BIG_ENDIAN)
        body.writeByte(4) // list length (two uint16 versions)
        body.writeShort(ProtocolVersion.Dtls13.value.toShort())
        body.writeShort(ProtocolVersion.Dtls12.value.toShort())
        body.resetForRead()
        return Extension(ExtensionType.SupportedVersions, body)
    }

    /** ServerHello `supported_versions`: the single selected version (DTLS 1.3). */
    fun supportedVersionsServerHello(factory: BufferFactory): Extension {
        val body = factory.allocate(2, ByteOrder.BIG_ENDIAN)
        body.writeShort(ProtocolVersion.Dtls13.value.toShort())
        body.resetForRead()
        return Extension(ExtensionType.SupportedVersions, body)
    }

    /** True if a ClientHello `supported_versions` body offers DTLS 1.3 (`0xFEFC`). */
    fun offersDtls13(body: ReadBuffer): Boolean {
        val n = body.remaining()
        if (n < 1) return false
        val listLen = body.u8(0)
        var off = 1
        val end = minOf(1 + listLen, n)
        while (off + 2 <= end) {
            if (body.u16(off) == ProtocolVersion.Dtls13.value) return true
            off += 2
        }
        return false
    }

    /** The selected version from a ServerHello `supported_versions` body (`0xFEFC` for DTLS 1.3), or null. */
    fun selectedVersion(body: ReadBuffer): Int? = if (body.remaining() >= 2) body.u16(0) else null

    // ── EncryptedExtensions (RFC 8446 §4.3.1) ──────────────────────────────────────────────────────

    /** An empty EncryptedExtensions body (no negotiated extensions this wave — SRTP is Phase 2 media). */
    fun encryptedExtensionsEmpty(factory: BufferFactory): ReadBuffer {
        val b = factory.allocate(2, ByteOrder.BIG_ENDIAN)
        b.writeShort(0) // extensions<0..2^16-1> = empty
        b.resetForRead()
        return b
    }

    // ── Certificate (TLS 1.3, RFC 8446 §4.4.2) ─────────────────────────────────────────────────────

    /** A TLS 1.3 Certificate body: empty request context, one CertificateEntry (the DER, no extensions). */
    fun certificate13Body(
        certDer: ReadBuffer,
        dest: WriteBuffer,
    ) {
        dest.writeByte(0) // certificate_request_context<0..255> = empty
        val entryLen = 3 + certDer.remaining() + 2 // uint24 cert_len ‖ cert ‖ uint16 ext_len(0)
        dest.writeU24(entryLen)
        dest.writeU24(certDer.remaining())
        dest.writeView(certDer)
        dest.writeShort(0) // extensions = empty
    }

    /** The first (end-entity) certificate DER from a TLS 1.3 Certificate body, or null if malformed. */
    fun parseCertificate13(body: ReadBuffer): ReadBuffer? {
        val n = body.remaining()
        if (n < 1) return null
        val ctxLen = body.u8(0)
        var off = 1 + ctxLen
        if (off + 3 > n) return null
        val listLen = body.u24(off)
        off += 3
        val listEnd = off + listLen
        if (listEnd > n || off + 3 > listEnd) return null
        val certLen = body.u24(off)
        off += 3
        if (off + certLen > listEnd) return null
        return body.sliceOf(off, off + certLen)
    }

    // ── CertificateRequest (TLS 1.3, RFC 8446 §4.3.2) ──────────────────────────────────────────────

    /** A CertificateRequest body: empty context + a `signature_algorithms` extension (ecdsa_secp256r1_sha256). */
    fun certificateRequest13Body(factory: BufferFactory): ReadBuffer {
        val b = factory.allocate(16, ByteOrder.BIG_ENDIAN)
        b.writeByte(0) // certificate_request_context<0..255> = empty
        // extensions<2..2^16-1>: one signature_algorithms extension.
        val sigAlgExtBody = 4 // uint16 list_len ‖ uint16 scheme
        b.writeShort((4 + sigAlgExtBody).toShort()) // extensions total length
        b.writeShort(ExtensionType.SignatureAlgorithms.value.toShort())
        b.writeShort(sigAlgExtBody.toShort())
        b.writeShort(2) // supported_signature_algorithms length
        b.writeShort(SignatureSchemeId.EcdsaSecp256r1Sha256.value.toShort())
        b.resetForRead()
        return b
    }
}

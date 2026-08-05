package com.ditchoom.webrtc.dtls.wire

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import com.ditchoom.buffer.freeIfNeeded
import kotlin.jvm.JvmInline

/** A TLS extension type (RFC 8446 §4.2 registry). Unknown values are preserved verbatim. */
@JvmInline
internal value class ExtensionType(
    val value: Int,
) {
    companion object {
        val SupportedGroups = ExtensionType(10) // RFC 8422/7919 — "elliptic_curves"
        val EcPointFormats = ExtensionType(11) // RFC 8422
        val SignatureAlgorithms = ExtensionType(13) // RFC 8446 §4.2.3
        val UseSrtp = ExtensionType(14) // RFC 5764 — DTLS-SRTP profile negotiation
        val ExtendedMasterSecret = ExtensionType(23) // RFC 7627 (empty body)
        val Cookie = ExtensionType(44) // RFC 8446 §4.2.2 — echoed from a HelloRetryRequest into ClientHello2
        val SupportedVersions = ExtensionType(43) // RFC 8446 §4.2.1 — carries DTLS 1.3
        val KeyShare = ExtensionType(51) // RFC 8446 §4.2.8 — DTLS 1.3 (EC)DHE shares
        val RenegotiationInfo = ExtensionType(0xFF01) // RFC 5746 (empty body for initial handshake)
    }
}

/**
 * A named group / curve (RFC 8446 §4.2.7 / RFC 8422). We support the WebRTC-common P-256; X25519 is the
 * other field-common group and is modelled so 1.3 `key_share` negotiation can accept it later.
 */
@JvmInline
internal value class NamedGroup(
    val value: Int,
) {
    companion object {
        val Secp256r1 = NamedGroup(23) // NIST P-256 — the WebRTC default
        val X25519 = NamedGroup(29)
    }
}

/** A signature scheme code point (RFC 8446 §4.2.3). */
@JvmInline
internal value class SignatureSchemeId(
    val value: Int,
) {
    companion object {
        val EcdsaSecp256r1Sha256 = SignatureSchemeId(0x0403)
    }
}

/** A DTLS-SRTP protection profile (RFC 5764 §4.1.2). */
@JvmInline
internal value class SrtpProtectionProfile(
    val value: Int,
) {
    companion object {
        val Aes128CmHmacSha1_80 = SrtpProtectionProfile(0x0001)
        val AeadAes128Gcm = SrtpProtectionProfile(0x0007)
    }
}

/**
 * A single TLS extension: a [type] and its opaque [body] (a zero-copy view when decoded). Typed
 * builders/parsers for the extensions the WebRTC handshake needs live in the companion; unknown
 * extensions round-trip verbatim.
 */
internal class Extension(
    val type: ExtensionType,
    val body: ReadBuffer,
) {
    val wireSize: Int get() = 4 + body.remaining()

    fun encodeInto(dest: WriteBuffer) {
        dest.writeShort(type.value.toShort())
        dest.writeShort(body.remaining().toShort())
        dest.writeView(body)
    }

    /**
     * Give back the reference [body] took. **Decoded extensions only** — see [releaseDecodedViews].
     */
    fun releaseViews() {
        body.freeIfNeeded()
    }

    companion object {
        /**
         * Encodes a `uint16`-length-prefixed extension list into [dest] (the trailing block of a
         * ClientHello/ServerHello). An empty list emits the two-byte zero length.
         */
        fun encodeList(
            dest: WriteBuffer,
            extensions: List<Extension>,
        ) {
            val total = extensions.sumOf { it.wireSize }
            dest.writeShort(total.toShort())
            for (e in extensions) e.encodeInto(dest)
        }

        /** On-wire size of the length-prefixed extension list (the 2-byte length included). */
        fun listWireSize(extensions: List<Extension>): Int = 2 + extensions.sumOf { it.wireSize }

        /**
         * Decodes the `uint16`-length-prefixed extension list starting at [start] in [region]. Returns
         * the parsed extensions or null if the framing overruns the region (malformed). Never throws.
         */
        fun decodeList(
            region: ReadBuffer,
            start: Int,
            end: Int,
        ): List<Extension>? {
            if (start == end) return emptyList() // no extensions block at all
            if (start + 2 > end) return null
            val total = region.u16(start)
            var pos = start + 2
            val listEnd = pos + total
            if (listEnd > end) return null
            val out = ArrayList<Extension>(4)
            while (pos < listEnd) {
                if (pos + 4 > listEnd) return out.rejected()
                val type = region.u16(pos)
                val len = region.u16(pos + 2)
                val bodyStart = pos + 4
                val bodyEnd = bodyStart + len
                if (bodyEnd > listEnd) return out.rejected()
                out += Extension(ExtensionType(type), region.sliceOf(bodyStart, bodyEnd))
                pos = bodyEnd
            }
            return out
        }

        /**
         * The typed reject, with the views already taken given back. A malformed tail after two good
         * extensions used to `return null` on top of two live slices, so a peer could pin one chunk per
         * datagram by sending exactly that — remote-triggered, not bookkeeping.
         */
        private fun List<Extension>.rejected(): List<Extension>? {
            releaseDecodedViews()
            return null
        }
    }
}

/**
 * Give back every reference a **decoded** extension list took.
 *
 * Decoded only, and the distinction is the same one `RawAttribute.owned` makes in webrtc-stun: a decoded
 * body is a `sliceOf` the region being parsed — a reference on a pooled chunk, and this list's to return —
 * while a *built* extension's body is a buffer its builder allocated and releases on its own flight path.
 * Calling this on a built list would be a double free, which is why nothing in the encode direction does.
 */
internal fun List<Extension>.releaseDecodedViews() {
    for (e in this) e.releaseViews()
}

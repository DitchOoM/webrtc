@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.dtls.handshake

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.dtls.DtlsRole
import com.ditchoom.webrtc.dtls.crypto.SelfSignedCertificate
import com.ditchoom.webrtc.dtls.engineCryptoAvailable
import com.ditchoom.webrtc.dtls.wire.ContentType
import com.ditchoom.webrtc.dtls.wire.DtlsRecord
import com.ditchoom.webrtc.dtls.wire.ExtensionType
import com.ditchoom.webrtc.dtls.wire.HandshakeFragment
import com.ditchoom.webrtc.dtls.wire.HandshakeMessage
import com.ditchoom.webrtc.dtls.wire.HandshakeType
import com.ditchoom.webrtc.dtls.wire.ProtocolVersion
import com.ditchoom.webrtc.dtls.wire.ServerHello
import com.ditchoom.webrtc.dtls.wire.SrtpProtectionProfile
import com.ditchoom.webrtc.dtls.wire.u16
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Regression fixture for the W7 interop bug (found on the live Pion lane, 2026-07-21): our DTLS 1.2 server
 * did not echo the RFC 5764 `use_srtp` extension, so pion/dtls — which **strictly** requires the echo, unlike
 * the tolerant BoringSSL/OpenSSL differentials — fatally aborted the handshake ("SRTP support was requested
 * but server did not respond with use_srtp extension"). This is the same lenient-vs-strict split as the
 * RFC 5746 renegotiation_info fix.
 *
 * The vector is **Pion's actual ClientHello bytes** captured from that run — an external, independent input
 * our own encoder can't launder. Feeding it to our server, the emitted ServerHello must now carry a
 * `use_srtp` extension selecting a profile Pion offered. Fails against the pre-fix server (no extension).
 */
class Dtls12SrtpNegotiationTest {
    private val now = Instant.fromEpochSeconds(0)

    // A real pion/dtls v3 ClientHello body (handshake-message body, from `WEBRTC_DTLS13=false` interop):
    // cipher_suites c02b,c02f,c00a,c014,c02c,c030; extensions signature_algorithms(13), renegotiation_info(65281),
    // supported_groups(10)=[x25519,secp256r1,secp384r1], ec_point_formats(11), use_srtp(14)=[0x0008,0x0007,0x0001],
    // extended_master_secret(23). The use_srtp offer is the load-bearing part of this vector.
    private val pionClientHelloBody =
        "fefd6a5ed7a2c58c233160d133166a3d5101128d31bb78cdb7d3c758d073d59d572a" +
            "0000000cc02bc02fc00ac014c02cc0300100003c000d0010000e0403050306030401050106010807" +
            "ff01000100000a00080006001d00170018000b00020100000e000900060008000700010000170000"

    @Test
    fun server_echoes_use_srtp_for_a_real_pion_client_hello() {
        if (!engineCryptoAvailable()) return // browsers delegate; the engine's blocking crypto isn't here
        val cert = SelfSignedCertificate.generate(BufferFactory.managed(), Random(3))
        val server = Dtls12Handshake(DtlsConfig(random = Random(3)), DtlsRole.Server, cert)
        try {
            server.start(now)
            val step = server.onDatagram(pionClientHelloRecord(), now)

            // The first record of the server's flight is the ServerHello — it must echo a use_srtp profile.
            val serverHello = parseServerHello(step.records.firstOrNull()) ?: error("no ServerHello in the server flight")
            val useSrtp = serverHello.extensions.firstOrNull { it.type.value == ExtensionType.UseSrtp.value }
            assertNotNull(useSrtp, "the ServerHello must echo a use_srtp extension for a pion/dtls client")

            // The server-side use_srtp body is `uint16 profiles_len(=2) ‖ profile ‖ uint8 mki_len(=0)`.
            val body = useSrtp.body
            assertTrue(body.remaining() >= 3, "use_srtp body carries one selected profile + empty MKI")
            assertEquals(2, body.u16(0), "server selects exactly one SRTP profile")
            val selected = body.u16(2)
            // We prefer AEAD_AES_128_GCM (0x0007), which Pion offered.
            assertEquals(SrtpProtectionProfile.AeadAes128Gcm.value, selected, "selected the mutually-preferred SRTP profile")
        } finally {
            server.close()
            cert.close()
        }
    }

    // ── helpers ─────────────────────────────────────────────────────────────────────────────────────

    private fun pionClientHelloRecord(): ReadBuffer {
        val body = hexToBuffer(pionClientHelloBody)
        val msg = HandshakeMessage(HandshakeType.ClientHello, messageSeq = 0, body = body)
        val hsWire = BufferFactory.managed().allocate(msg.wireSize, ByteOrder.BIG_ENDIAN)
        msg.encodeInto(hsWire)
        hsWire.resetForRead()
        val record = DtlsRecord(ContentType.Handshake, ProtocolVersion.Dtls12, epoch = 0, sequenceNumber = 0, fragment = hsWire)
        val wire = BufferFactory.managed().allocate(record.wireSize, ByteOrder.BIG_ENDIAN)
        record.encodeInto(wire)
        wire.resetForRead()
        return wire
    }

    private fun parseServerHello(recordDatagram: ReadBuffer?): ServerHello? {
        val records = recordDatagram?.let { DtlsRecord.decodeAll(it) } ?: return null
        for (record in records) {
            if (record.contentType.value != ContentType.Handshake.value) continue
            val fragments = HandshakeFragment.decodeAll(record.fragment) ?: continue
            for (fragment in fragments) {
                if (fragment.msgType.value == HandshakeType.ServerHello.value) return ServerHello.parse(fragment.fragmentBody)
            }
        }
        return null
    }

    private fun hexToBuffer(hex: String): ReadBuffer {
        val b = BufferFactory.managed().allocate(hex.length / 2, ByteOrder.BIG_ENDIAN)
        var i = 0
        while (i < hex.length) {
            b.writeByte(hex.substring(i, i + 2).toInt(16).toByte())
            i += 2
        }
        b.resetForRead()
        return b
    }
}

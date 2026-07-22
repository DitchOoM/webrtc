@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.dtls.handshake

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.dtls.DtlsFailureReason
import com.ditchoom.webrtc.dtls.DtlsRole
import com.ditchoom.webrtc.dtls.DtlsState
import com.ditchoom.webrtc.dtls.crypto.SelfSignedCertificate
import com.ditchoom.webrtc.dtls.engineCryptoAvailable
import com.ditchoom.webrtc.dtls.wire.CipherSuiteId
import com.ditchoom.webrtc.dtls.wire.ContentType
import com.ditchoom.webrtc.dtls.wire.DtlsRecord
import com.ditchoom.webrtc.dtls.wire.HandshakeFragment
import com.ditchoom.webrtc.dtls.wire.HandshakeMessage
import com.ditchoom.webrtc.dtls.wire.HandshakeType
import com.ditchoom.webrtc.dtls.wire.ProtocolVersion
import com.ditchoom.webrtc.dtls.wire.ServerHello
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * TLS 1.3 downgrade protection (RFC 8446 §4.1.3), both halves:
 *
 *  - **Server stamps the sentinel.** A DTLS-1.3-capable server (`enableDtls13 = true`) that negotiates
 *    DTLS 1.2 writes `44 4F 57 4E 47 52 44 01` ("DOWNGRD\x01") over the last 8 bytes of its
 *    ServerHello.Random; a server that is not 1.3-capable does not.
 *  - **Client rejects the downgrade.** Our 1.3 client, which offers DTLS 1.3, treats any ServerHello that
 *    selects a lower version as fatal — as [DtlsFailureReason.DowngradeDetected] when the sentinel is
 *    present (a genuine 1.3-capable server negotiating down means an attacker stripped our 1.3 offer), and
 *    as a plain [DtlsFailureReason.HandshakeFailure] otherwise.
 *
 * All deterministic (seeded RNG, virtual clock), no wall-clock, no network.
 */
class DtlsDowngradeSentinelTest {
    private val now: Instant = Instant.fromEpochSeconds(0)
    private val sentinelHex = "444f574e47524401"

    private fun config(enableDtls13: Boolean) =
        DtlsConfig(bufferFactory = BufferFactory.managed(), enableDtls13 = enableDtls13, random = Random(31))

    private fun cert(seed: Int) = SelfSignedCertificate.generate(BufferFactory.managed(), Random(seed))

    @Test
    fun a_1_3_capable_server_stamps_the_downgrade_sentinel_in_a_1_2_serverhello() {
        if (!engineCryptoAvailable()) return
        val random = serverHelloRandomHex(serverEnableDtls13 = true)
        assertNotNull(random, "the 1.2 server emitted a ServerHello")
        assertEquals(sentinelHex, random.takeLast(16), "the last 8 bytes are the DOWNGRD\\x01 sentinel")
    }

    @Test
    fun a_1_2_only_server_does_not_stamp_the_downgrade_sentinel() {
        if (!engineCryptoAvailable()) return
        val random = serverHelloRandomHex(serverEnableDtls13 = false)
        assertNotNull(random, "the 1.2 server emitted a ServerHello")
        assertNotEquals(sentinelHex, random.takeLast(16), "a 1.2-only server leaves its Random fully random")
    }

    @Test
    fun the_client_rejects_a_downgraded_serverhello_carrying_the_sentinel() {
        if (!engineCryptoAvailable()) return
        val state = feedCraftedServerHelloToClient(withSentinel = true)
        assertIs<DtlsState.Failed>(state, "a downgraded ServerHello with the sentinel is fatal, was $state")
        assertEquals(DtlsFailureReason.DowngradeDetected, state.reason)
    }

    @Test
    fun the_client_rejects_a_non_1_3_serverhello_without_the_sentinel_as_a_plain_failure() {
        if (!engineCryptoAvailable()) return
        val state = feedCraftedServerHelloToClient(withSentinel = false)
        assertIs<DtlsState.Failed>(state, "a non-1.3 ServerHello is fatal, was $state")
        assertEquals(DtlsFailureReason.HandshakeFailure, state.reason)
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────────

    /** Drive a 1.2 client → 1.2 server one flight and return the server's ServerHello.Random as hex. */
    private fun serverHelloRandomHex(serverEnableDtls13: Boolean): String? {
        val clientCert = cert(41)
        val serverCert = cert(42)
        val client = Dtls12Handshake(config(enableDtls13 = false), DtlsRole.Client, clientCert)
        val server = Dtls12Handshake(config(enableDtls13 = serverEnableDtls13), DtlsRole.Server, serverCert)
        try {
            server.start(now) // the server stamps its (sentinel-bearing) Random here, before any datagram
            var random: String? = null
            for (rec in client.start(now).records) {
                for (out in server.onDatagram(rec, now).records) {
                    extractServerHelloRandomHex(out)?.let { random = it }
                }
            }
            return random
        } finally {
            client.close()
            server.close()
            clientCert.close()
            serverCert.close()
        }
    }

    private fun extractServerHelloRandomHex(datagram: ReadBuffer): String? {
        val records = DtlsRecord.decodeAll(datagram) ?: return null
        for (r in records) {
            if (r.contentType.value != ContentType.Handshake.value) continue
            val fragments = HandshakeFragment.decodeAll(r.fragment) ?: continue
            for (f in fragments) {
                if (f.msgType.value != HandshakeType.ServerHello.value) continue
                if (f.fragmentOffset != 0 || f.fragmentLength != f.length) continue
                val sh = ServerHello.parse(f.fragmentBody) ?: continue
                return hexOf(sh.random)
            }
        }
        return null
    }

    /** Start a 1.3 client, then feed it a hand-crafted DTLS 1.2 ServerHello; return the resulting state. */
    private fun feedCraftedServerHelloToClient(withSentinel: Boolean): DtlsState {
        val clientCert = cert(43)
        val client = Dtls13Handshake(config(enableDtls13 = true), DtlsRole.Client, clientCert)
        try {
            client.start(now) // emits ClientHello; we ignore it and inject our own server response
            return client.onDatagram(craftDtls12ServerHello(withSentinel), now).state
        } finally {
            client.close()
            clientCert.close()
        }
    }

    private fun craftDtls12ServerHello(withSentinel: Boolean): ReadBuffer {
        val factory = BufferFactory.managed()
        val random = factory.allocate(32, ByteOrder.BIG_ENDIAN)
        repeat(24) { random.writeByte(0x5A) }
        if (withSentinel) {
            for (v in listOf(0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01)) random.writeByte(v.toByte())
        } else {
            repeat(8) { random.writeByte(0xAA.toByte()) }
        }
        random.resetForRead()

        val emptyVec =
            factory.allocate(1, ByteOrder.BIG_ENDIAN).also {
                it.resetForRead()
                it.setLimit(0)
            }
        val body = factory.allocate(256, ByteOrder.BIG_ENDIAN)
        ServerHello(
            ProtocolVersion.Dtls12,
            random,
            emptyVec,
            CipherSuiteId.TlsEcdheEcdsaAes128GcmSha256, // a real 1.2 cipher — a genuine downgrade selection
            emptyList(),
        ).bodyInto(body)
        body.resetForRead()

        val message = HandshakeMessage(HandshakeType.ServerHello, 0, body)
        val wire = factory.allocate(message.wireSize, ByteOrder.BIG_ENDIAN)
        message.encodeInto(wire)
        wire.resetForRead()

        val record = DtlsRecord(ContentType.Handshake, ProtocolVersion.Dtls12, 0, 0L, wire)
        val datagram = factory.allocate(record.wireSize, ByteOrder.BIG_ENDIAN)
        record.encodeInto(datagram)
        datagram.resetForRead()
        return datagram
    }

    private fun hexOf(buf: ReadBuffer): String {
        val p = buf.position()
        val sb = StringBuilder()
        while (buf.remaining() > 0) {
            val v = buf.readByte().toInt() and 0xFF
            sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 0xF])
        }
        buf.position(p)
        return sb.toString()
    }
}

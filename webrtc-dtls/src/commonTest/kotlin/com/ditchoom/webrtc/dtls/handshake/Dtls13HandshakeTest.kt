@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.dtls.handshake

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.dtls.DtlsRole
import com.ditchoom.webrtc.dtls.DtlsState
import com.ditchoom.webrtc.dtls.DtlsVersion
import com.ditchoom.webrtc.dtls.KeyExchangeGroup
import com.ditchoom.webrtc.dtls.crypto.SelfSignedCertificate
import com.ditchoom.webrtc.dtls.engineCryptoAvailable
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.microseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The DTLS 1.3 (RFC 9147) counterpart of [Dtls12HandshakeTest]: two pure-Kotlin DTLS 1.3 handshakes
 * complete over an in-memory datagram pipe under a virtual clock — exercising the TLS 1.3 key schedule,
 * the unified-header record layer with record-number encryption, and the mutually-authenticated flights.
 * Each side ends [DtlsState.Established] with the peer's real fingerprint and negotiated version 1.3, and
 * application data flows encrypted (epoch-3 traffic keys) both ways. Both negotiable (EC)DHE groups are
 * exercised — X25519 (the browser-matching default) and P-256. This is the fast self-loopback check;
 * the BoringSSL differential (linuxTest) is what proves byte-level interop with an independent stack.
 */
class Dtls13HandshakeTest {
    private var now: Instant = Instant.fromEpochSeconds(0)

    private fun config(group: KeyExchangeGroup) =
        DtlsConfig(bufferFactory = BufferFactory.managed(), keyExchangeGroup = group, random = Random(11))

    private fun cert() = SelfSignedCertificate.generate(BufferFactory.managed(), Random(11))

    @Test
    fun two_pure_kotlin_stacks_complete_a_dtls13_handshake_x25519() = handshakeCompletes(KeyExchangeGroup.X25519)

    @Test
    fun two_pure_kotlin_stacks_complete_a_dtls13_handshake_p256() = handshakeCompletes(KeyExchangeGroup.Secp256r1)

    @Test
    fun application_data_flows_encrypted_after_the_handshake_x25519() = appDataFlows(KeyExchangeGroup.X25519)

    @Test
    fun application_data_flows_encrypted_after_the_handshake_p256() = appDataFlows(KeyExchangeGroup.Secp256r1)

    private fun handshakeCompletes(group: KeyExchangeGroup) {
        if (!engineCryptoAvailable()) return // browsers delegate; the engine's blocking crypto isn't here
        val clientCert = cert()
        val serverCert = cert()
        val client = Dtls13Handshake(config(group), DtlsRole.Client, clientCert)
        val server = Dtls13Handshake(config(group), DtlsRole.Server, serverCert)
        try {
            val (c, s) = drive(client, server)
            assertIs<DtlsState.Established>(c, "client established ($group), was $c")
            assertIs<DtlsState.Established>(s, "server established ($group), was $s")

            assertEquals(serverCert.fingerprint, c.peerFingerprint)
            assertEquals(clientCert.fingerprint, s.peerFingerprint)
            assertEquals(DtlsVersion.Dtls13, c.negotiatedVersion)
            assertEquals(DtlsVersion.Dtls13, s.negotiatedVersion)
        } finally {
            client.close()
            server.close()
            clientCert.close()
            serverCert.close()
        }
    }

    private fun appDataFlows(group: KeyExchangeGroup) {
        if (!engineCryptoAvailable()) return
        val clientCert = cert()
        val serverCert = cert()
        val client = Dtls13Handshake(config(group), DtlsRole.Client, clientCert)
        val server = Dtls13Handshake(config(group), DtlsRole.Server, serverCert)
        try {
            drive(client, server)

            // Client → server.
            val fromClient = client.sealApplicationData(bytes(0xDE, 0xAD, 0xBE, 0xEF, 0x2A), now)
            assertTrue(fromClient.records.isNotEmpty(), "an encrypted app-data record is produced")
            var atServer: ReadBuffer? = null
            for (rec in fromClient.records) {
                server
                    .onDatagram(rec, now)
                    .applicationData
                    .firstOrNull()
                    ?.let { atServer = it }
            }
            assertNotNull(atServer, "server decrypted the app data")
            assertEquals("deadbeef2a", hexOf(atServer))

            // Server → client (a distinct epoch-3 direction).
            val fromServer = server.sealApplicationData(bytes(0x01, 0x23, 0x45, 0x67), now)
            var atClient: ReadBuffer? = null
            for (rec in fromServer.records) {
                client
                    .onDatagram(rec, now)
                    .applicationData
                    .firstOrNull()
                    ?.let { atClient = it }
            }
            assertNotNull(atClient, "client decrypted the app data")
            assertEquals("01234567", hexOf(atClient))
        } finally {
            client.close()
            server.close()
            clientCert.close()
            serverCert.close()
        }
    }

    // ── a synchronous two-endpoint conductor over a virtual clock ───────────────────────────────────

    private fun drive(
        client: Dtls13Handshake,
        server: Dtls13Handshake,
    ): Pair<DtlsState, DtlsState> {
        val toServer = ArrayDeque<ReadBuffer>()
        val toClient = ArrayDeque<ReadBuffer>()
        var cState: DtlsState = client.start(now).also { toServer.addAll(it.records) }.state
        var sState: DtlsState = server.start(now).also { toClient.addAll(it.records) }.state

        var guard = 0
        while (guard++ < 500) {
            if (cState is DtlsState.Established && sState is DtlsState.Established) break
            if (cState is DtlsState.Failed || sState is DtlsState.Failed) break
            when {
                toServer.isNotEmpty() ->
                    server.onDatagram(toServer.removeFirst(), now).let {
                        sState = it.state
                        toClient.addAll(it.records)
                    }
                toClient.isNotEmpty() ->
                    client.onDatagram(toClient.removeFirst(), now).let {
                        cState = it.state
                        toServer.addAll(it.records)
                    }
                else -> {
                    val deadlines = listOfNotNull(client.nextDeadline(now), server.nextDeadline(now))
                    if (deadlines.isEmpty()) break
                    now = maxOf(now + 1.microseconds, deadlines.min())
                    client.onTimeout(now).let {
                        cState = it.state
                        toServer.addAll(it.records)
                    }
                    server.onTimeout(now).let {
                        sState = it.state
                        toClient.addAll(it.records)
                    }
                }
            }
        }
        return cState to sState
    }

    private fun bytes(vararg v: Int): ReadBuffer {
        val b = BufferFactory.managed().allocate(v.size, ByteOrder.BIG_ENDIAN)
        v.forEach { b.writeByte(it.toByte()) }
        b.resetForRead()
        return b
    }

    private fun hexOf(buf: ReadBuffer): String {
        val sb = StringBuilder()
        while (buf.remaining() > 0) {
            val v = buf.readByte().toInt() and 0xFF
            sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 0xF])
        }
        return sb.toString()
    }
}

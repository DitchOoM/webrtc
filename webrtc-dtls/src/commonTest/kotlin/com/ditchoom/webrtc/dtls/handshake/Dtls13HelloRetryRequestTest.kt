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
 * The DTLS 1.3 **HelloRetryRequest** self-loopback (RFC 8446 §4.1.4 / RFC 9147). A client lists every
 * supported group in `supported_groups` but key-shares only its preferred group; when the peer prefers a
 * different (but offered) group it answers with exactly one HelloRetryRequest, the client retries with a
 * fresh `key_share` for the requested group, and the handshake completes — the transcript folded over the
 * synthetic `message_hash(ClientHello1)` on both sides (so the Finished/CertificateVerify hashes match).
 *
 * The scenario is engineered so HRR is the **only** path to completion: the client prefers P-256 (so it
 * key-shares P-256) while the server prefers X25519 (which the client offered but did not key-share). If
 * HRR handling were absent the two would never agree and never establish, so a green establishment here
 * is proof the retry round trip works end to end. The BoringSSL differential (linuxTest) pins the same
 * behaviour to an independent stack. This runs under a virtual clock at zero wall-clock.
 */
class Dtls13HelloRetryRequestTest {
    private var now: Instant = Instant.fromEpochSeconds(0)

    // Client prefers P-256 (key-shares P-256); server prefers X25519 → the server must HRR for X25519.
    private fun clientConfig() =
        DtlsConfig(bufferFactory = BufferFactory.managed(), keyExchangeGroup = KeyExchangeGroup.Secp256r1, random = Random(7))

    private fun serverConfig() =
        DtlsConfig(bufferFactory = BufferFactory.managed(), keyExchangeGroup = KeyExchangeGroup.X25519, random = Random(8))

    private fun cert(seed: Int) = SelfSignedCertificate.generate(BufferFactory.managed(), Random(seed))

    @Test
    fun a_hello_retry_request_completes_the_handshake() {
        if (!engineCryptoAvailable()) return // browsers delegate; the engine's blocking crypto isn't here
        val clientCert = cert(21)
        val serverCert = cert(22)
        val client = Dtls13Handshake(clientConfig(), DtlsRole.Client, clientCert)
        val server = Dtls13Handshake(serverConfig(), DtlsRole.Server, serverCert)
        try {
            val (c, s) = drive(client, server)
            assertIs<DtlsState.Established>(c, "client established after HRR, was $c")
            assertIs<DtlsState.Established>(s, "server established after HRR, was $s")

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

    @Test
    fun application_data_flows_after_a_hello_retry_request() {
        if (!engineCryptoAvailable()) return
        val clientCert = cert(23)
        val serverCert = cert(24)
        val client = Dtls13Handshake(clientConfig(), DtlsRole.Client, clientCert)
        val server = Dtls13Handshake(serverConfig(), DtlsRole.Server, serverCert)
        try {
            val (c, s) = drive(client, server)
            assertIs<DtlsState.Established>(c)
            assertIs<DtlsState.Established>(s)

            val fromClient = client.sealApplicationData(bytes(0xC0, 0xFF, 0xEE), now)
            assertTrue(fromClient.records.isNotEmpty())
            var atServer: ReadBuffer? = null
            for (rec in fromClient.records) {
                server
                    .onDatagram(rec, now)
                    .applicationData
                    .firstOrNull()
                    ?.let { atServer = it }
            }
            assertNotNull(atServer, "server decrypted app data over the retried session")
            assertEquals("c0ffee", hexOf(atServer))
        } finally {
            client.close()
            server.close()
            clientCert.close()
            serverCert.close()
        }
    }

    // ── a synchronous two-endpoint conductor over a virtual clock (mirrors Dtls13HandshakeTest) ──────

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

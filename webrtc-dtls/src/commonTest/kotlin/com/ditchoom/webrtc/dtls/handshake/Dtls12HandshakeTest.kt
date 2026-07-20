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
 * The W4b milestone: two pure-Kotlin DTLS 1.2 handshakes complete over an in-memory datagram pipe under
 * a virtual clock — no BoringSSL, no sockets, no wall-clock. Each side ends [DtlsState.Established] with
 * the peer's real certificate fingerprint (the `a=fingerprint` cross-check WebRTC relies on), and
 * application data then flows encrypted in both directions.
 */
class Dtls12HandshakeTest {
    private var now: Instant = Instant.fromEpochSeconds(0)

    private fun config() = DtlsConfig(bufferFactory = BufferFactory.managed(), random = Random(7))

    // The engine owns the long-lived identity and passes it into the handshake; at this FSM level the
    // test mints one cert per endpoint (its fingerprint is the `a=fingerprint` the peer authenticates).
    private fun cert() = SelfSignedCertificate.generate(BufferFactory.managed(), Random(7))

    @Test
    fun two_pure_kotlin_stacks_complete_a_dtls12_handshake() {
        if (!engineCryptoAvailable()) return // browsers delegate; the engine's blocking crypto isn't here
        val clientCert = cert()
        val serverCert = cert()
        val client = Dtls12Handshake(config(), DtlsRole.Client, clientCert)
        val server = Dtls12Handshake(config(), DtlsRole.Server, serverCert)
        try {
            val (c, s) = drive(client, server)
            assertIs<DtlsState.Established>(c, "client established, was $c")
            assertIs<DtlsState.Established>(s, "server established, was $s")

            // Each side authenticated the OTHER's certificate.
            assertEquals(serverCert.fingerprint, c.peerFingerprint)
            assertEquals(clientCert.fingerprint, s.peerFingerprint)
            assertEquals(DtlsVersion.Dtls12, c.negotiatedVersion)
            assertEquals(64, clientCert.fingerprint.sha256Hex.length)
        } finally {
            client.close()
            server.close()
            clientCert.close()
            serverCert.close()
        }
    }

    @Test
    fun application_data_flows_encrypted_after_the_handshake() {
        if (!engineCryptoAvailable()) return // browsers delegate; the engine's blocking crypto isn't here
        val clientCert = cert()
        val serverCert = cert()
        val client = Dtls12Handshake(config(), DtlsRole.Client, clientCert)
        val server = Dtls12Handshake(config(), DtlsRole.Server, serverCert)
        try {
            drive(client, server)
            val payload = bytes(0xDE, 0xAD, 0xBE, 0xEF, 0x2A)
            val sent = client.sealApplicationData(payload, now)
            assertTrue(sent.records.isNotEmpty(), "an encrypted app-data record is produced")

            var decrypted: ReadBuffer? = null
            for (rec in sent.records) {
                val stepResult = server.onDatagram(rec, now)
                if (stepResult.applicationData.isNotEmpty()) decrypted = stepResult.applicationData.first()
            }
            assertNotNull(decrypted, "server decrypted the app data")
            assertEquals("deadbeef2a", hexOf(decrypted))
        } finally {
            client.close()
            server.close()
            clientCert.close()
            serverCert.close()
        }
    }

    // ── a synchronous two-endpoint conductor over a virtual clock ───────────────────────────────────

    private fun drive(
        client: Dtls12Handshake,
        server: Dtls12Handshake,
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

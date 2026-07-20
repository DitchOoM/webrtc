package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.ReadBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The W4b #6 **DTLS 1.3 differential** exit fixture: our pure-Kotlin [DtlsEngine] completes a real DTLS
 * 1.3 handshake (RFC 9147) against the independent BoringSSL oracle ([BoringSslDtlsEngine]) under a virtual
 * clock, in **both** role directions. Unlike the self-loopback ([com.ditchoom.webrtc.dtls.handshake.Dtls13HandshakeTest]),
 * BoringSSL only establishes if every byte we emit is correct: the ClientHello/ServerHello with
 * `supported_versions` + `key_share`, the TLS 1.3 key schedule (`"dtls13"`-prefixed HKDF-Expand-Label),
 * the unified-header record layer with record-number encryption, the CertificateVerify over the RFC 8446
 * signed content, and the Finished HMAC. Both engines run at their **default** config (1.3 on) — the oracle
 * negotiates DTLS 1.3, not the 1.2 the sibling [DtlsHandshakeTest] pins.
 *
 * The 1.3 openssl-`s_client` lane is intentionally absent: OpenSSL 3.0.13 (the box's version) predates
 * DTLS 1.3 in `s_client`; that second-stack cross-check needs OpenSSL ≥ 3.2 and is deferred to interop (#7).
 */
class Dtls13DifferentialTest {
    // Default config → enableDtls13 = true → both sides negotiate DTLS 1.3.
    private fun config() = DtlsConfig()

    @Test
    fun our_client_completes_a_dtls13_handshake_against_the_boringssl_oracle() {
        val ours = DtlsEngine(config())
        val oracle = BoringSslDtlsEngine(config())
        try {
            val (c, s) = DtlsConductor().drive(ours.endpoint(), oracle.endpoint())
            assertIs<DtlsState.Established>(c, "our client established against BoringSSL 1.3, was $c")
            assertIs<DtlsState.Established>(s, "BoringSSL server established against ours, was $s")

            assertEquals(oracle.localFingerprint, c.peerFingerprint, "our client saw the oracle's cert")
            assertEquals(ours.localFingerprint, s.peerFingerprint, "the oracle saw our cert")
            assertEquals(DtlsVersion.Dtls13, c.negotiatedVersion)
            assertEquals(DtlsVersion.Dtls13, s.negotiatedVersion)
        } finally {
            ours.close()
            oracle.close()
        }
    }

    @Test
    fun our_server_completes_a_dtls13_handshake_against_the_boringssl_oracle() {
        val oracle = BoringSslDtlsEngine(config())
        val ours = DtlsEngine(config())
        try {
            // Oracle is the client here (sends ClientHello); our engine peeks it and answers as a 1.3 server.
            val (c, s) = DtlsConductor().drive(oracle.endpoint(), ours.endpoint())
            assertIs<DtlsState.Established>(c, "BoringSSL client established against our 1.3 server, was $c")
            assertIs<DtlsState.Established>(s, "our server established against BoringSSL 1.3, was $s")

            assertEquals(ours.localFingerprint, c.peerFingerprint, "the oracle saw our cert")
            assertEquals(oracle.localFingerprint, s.peerFingerprint, "our server saw the oracle's cert")
            assertEquals(DtlsVersion.Dtls13, s.negotiatedVersion)
        } finally {
            oracle.close()
            ours.close()
        }
    }

    @Test
    fun application_data_flows_both_ways_over_dtls13() {
        val ours = DtlsEngine(config())
        val oracle = BoringSslDtlsEngine(config())
        try {
            val conductor = DtlsConductor()
            val (c, s) = conductor.drive(ours.endpoint(), oracle.endpoint())
            assertIs<DtlsState.Established>(c)
            assertIs<DtlsState.Established>(s)
            val now = conductor.now

            // Our engine encrypts (epoch-3 app keys) → the oracle decrypts the identical bytes.
            val fromOurs = ours.send(bytesOf(0xDE, 0xAD, 0xBE, 0xEF, 0x2A), now)
            assertTrue(fromOurs.records.isNotEmpty(), "our engine produced an encrypted 1.3 record")
            var atOracle: ReadBuffer? = null
            for (rec in fromOurs.records) {
                oracle
                    .onDatagram(rec, now)
                    .applicationData
                    .firstOrNull()
                    ?.let { atOracle = it }
            }
            assertNotNull(atOracle, "the oracle decrypted our application data")
            assertEquals("deadbeef2a", hexOf(atOracle))

            // The oracle encrypts → our engine decrypts the identical bytes.
            val fromOracle = oracle.send(bytesOf(0x01, 0x23, 0x45, 0x67), now)
            assertTrue(fromOracle.records.isNotEmpty(), "the oracle produced an encrypted 1.3 record")
            var atOurs: ReadBuffer? = null
            for (rec in fromOracle.records) {
                ours
                    .onDatagram(rec, now)
                    .applicationData
                    .firstOrNull()
                    ?.let { atOurs = it }
            }
            assertNotNull(atOurs, "our engine decrypted the oracle's application data")
            assertEquals("01234567", hexOf(atOurs))
        } finally {
            ours.close()
            oracle.close()
        }
    }
}

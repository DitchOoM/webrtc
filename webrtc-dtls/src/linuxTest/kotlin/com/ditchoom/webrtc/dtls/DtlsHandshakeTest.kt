package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.ReadBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The W4b **differential** exit fixture: our pure-Kotlin [DtlsEngine] completes a real DTLS 1.2
 * handshake against an independent, battle-tested stack — the BoringSSL oracle ([BoringSslDtlsEngine]) —
 * driven entirely by a virtual clock. This closes the coverage gap the self-loopback left: a *consistent*
 * bug on both of our own sides would pass a mirror test, but BoringSSL only completes the handshake if
 * our ClientHello/ServerHello, our ECDHE ServerKeyExchange signature, our CertificateVerify, our TLS-1.2
 * PRF `verify_data`, and our AES-128-GCM record protection are all byte-correct. We test both roles
 * (our-client ⇄ oracle-server and oracle-client ⇄ our-server), since each exercises the opposite half of
 * the flight logic. The oracle is pinned to DTLS 1.2 (our engine's version this wave); 1.3 is W4b #6.
 */
class DtlsHandshakeTest {
    private fun config() = DtlsConfig(enableDtls13 = false)

    @Test
    fun our_client_completes_a_handshake_against_the_boringssl_oracle() {
        val ours = DtlsEngine(config())
        val oracle = BoringSslDtlsEngine(config())
        try {
            val (c, s) = DtlsConductor().drive(ours.endpoint(), oracle.endpoint())
            assertIs<DtlsState.Established>(c, "our client established against BoringSSL, was $c")
            assertIs<DtlsState.Established>(s, "BoringSSL server established against ours, was $s")

            // Each side authenticated the OTHER's real certificate — the a=fingerprint cross-check.
            assertEquals(oracle.localFingerprint, c.peerFingerprint, "our client saw the oracle's cert")
            assertEquals(ours.localFingerprint, s.peerFingerprint, "the oracle saw our cert")
            assertEquals(DtlsVersion.Dtls12, c.negotiatedVersion)
            assertEquals(DtlsVersion.Dtls12, s.negotiatedVersion)
        } finally {
            ours.close()
            oracle.close()
        }
    }

    @Test
    fun our_server_completes_a_handshake_against_the_boringssl_oracle() {
        val oracle = BoringSslDtlsEngine(config())
        val ours = DtlsEngine(config())
        try {
            // Oracle is the client here (sends ClientHello); our engine answers as the server.
            val (c, s) = DtlsConductor().drive(oracle.endpoint(), ours.endpoint())
            assertIs<DtlsState.Established>(c, "BoringSSL client established against our server, was $c")
            assertIs<DtlsState.Established>(s, "our server established against BoringSSL, was $s")

            assertEquals(ours.localFingerprint, c.peerFingerprint, "the oracle saw our cert")
            assertEquals(oracle.localFingerprint, s.peerFingerprint, "our server saw the oracle's cert")
            assertEquals(DtlsVersion.Dtls12, s.negotiatedVersion)
        } finally {
            oracle.close()
            ours.close()
        }
    }

    @Test
    fun application_data_flows_both_ways_against_the_oracle() {
        val ours = DtlsEngine(config())
        val oracle = BoringSslDtlsEngine(config())
        try {
            val conductor = DtlsConductor()
            val (c, s) = conductor.drive(ours.endpoint(), oracle.endpoint())
            assertIs<DtlsState.Established>(c)
            assertIs<DtlsState.Established>(s)
            val now = conductor.now

            // Our engine encrypts → the oracle decrypts the identical bytes.
            val fromOurs = ours.send(bytesOf(0xDE, 0xAD, 0xBE, 0xEF, 0x2A), now)
            assertTrue(fromOurs.records.isNotEmpty(), "our engine produced an encrypted record")
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
            assertTrue(fromOracle.records.isNotEmpty(), "the oracle produced an encrypted record")
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

    /**
     * T0 robustness against a real peer: a malformed datagram (unknown content type) interleaved ahead
     * of each side's real flight must be silently dropped (RFC 6347) — never crash our parser, fault the
     * handshake, or wedge the engine. Both endpoints must still reach [DtlsState.Established].
     */
    @Test
    fun malformed_datagrams_during_the_handshake_are_dropped_and_never_wedge_it() {
        val ours = DtlsEngine(config())
        val oracle = BoringSslDtlsEngine(config())
        try {
            val (c, s) = DtlsConductor().drive(ours.endpoint(), oracle.endpoint(), junk = true)
            assertIs<DtlsState.Established>(c, "our client established despite the junk record, was $c")
            assertIs<DtlsState.Established>(s, "the oracle established despite the junk record, was $s")
        } finally {
            ours.close()
            oracle.close()
        }
    }
}

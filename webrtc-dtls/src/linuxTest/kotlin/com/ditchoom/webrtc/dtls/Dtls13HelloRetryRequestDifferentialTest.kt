package com.ditchoom.webrtc.dtls

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * The DTLS 1.3 **HelloRetryRequest differential** against BoringSSL (RFC 8446 §4.1.4 / RFC 9147). Our pure
 * Kotlin engine offers every supported group in `supported_groups` but key-shares only its configured
 * group, so a peer that prefers a different (offered) group triggers exactly one HRR. BoringSSL only
 * completes if every retried byte is right: the collapsed `message_hash(ClientHello1)` transcript, the
 * second ClientHello with the new `key_share`, and the resumed key schedule over the retried transcript.
 *
 * Both directions are covered:
 *  - **our client ← BoringSSL server:** our client key-shares P-256 while BoringSSL's group list prefers
 *    X25519 (which our client also offered), so BoringSSL answers with an HRR our client must handle.
 *  - **our server → BoringSSL client:** BoringSSL's group list is `P-256:X25519`, so it key-shares P-256
 *    but offers both; our server prefers X25519 and must emit an HRR that BoringSSL then honours.
 *
 * Each lane ends [DtlsState.Established] on both sides with the peer's real fingerprint and version 1.3.
 * The plain (no-HRR) 1.3 differential lives in [Dtls13DifferentialTest]; this one proves the retry path.
 */
class Dtls13HelloRetryRequestDifferentialTest {
    @Test
    fun our_client_handles_a_boringssl_hello_retry_request() {
        // Our client key-shares P-256; BoringSSL server prefers X25519 → HRR for X25519.
        val ours = DtlsEngine(DtlsConfig(keyExchangeGroup = KeyExchangeGroup.Secp256r1))
        val oracle = BoringSslDtlsEngine(DtlsConfig(keyExchangeGroup = KeyExchangeGroup.Secp256r1), groupsListOverride = "X25519")
        try {
            val (c, s) = DtlsConductor().drive(ours.endpoint(), oracle.endpoint())
            assertIs<DtlsState.Established>(c, "our client established after a BoringSSL HRR, was $c")
            assertIs<DtlsState.Established>(s, "BoringSSL server established, was $s")

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
    fun our_server_sends_a_hello_retry_request_a_boringssl_client_honours() {
        // BoringSSL client key-shares P-256 but offers X25519 too; our server prefers X25519 → we HRR.
        val oracle = BoringSslDtlsEngine(DtlsConfig(keyExchangeGroup = KeyExchangeGroup.Secp256r1), groupsListOverride = "P-256:X25519")
        val ours = DtlsEngine(DtlsConfig(keyExchangeGroup = KeyExchangeGroup.X25519))
        try {
            val (c, s) = DtlsConductor().drive(oracle.endpoint(), ours.endpoint())
            assertIs<DtlsState.Established>(c, "BoringSSL client established after our HRR, was $c")
            assertIs<DtlsState.Established>(s, "our server established, was $s")

            assertEquals(ours.localFingerprint, c.peerFingerprint, "the oracle saw our cert")
            assertEquals(oracle.localFingerprint, s.peerFingerprint, "our server saw the oracle's cert")
            assertEquals(DtlsVersion.Dtls13, s.negotiatedVersion)
        } finally {
            oracle.close()
            ours.close()
        }
    }
}

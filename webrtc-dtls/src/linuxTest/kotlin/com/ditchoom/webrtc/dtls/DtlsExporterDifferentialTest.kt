package com.ditchoom.webrtc.dtls

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

/**
 * The W4b #7c **DTLS-SRTP exporter differential**: our pure-Kotlin [DtlsEngine]'s exported keying material
 * (the TLS exporter — RFC 5705 for DTLS 1.2, RFC 8446 §7.5 for DTLS 1.3 — that DTLS-SRTP derives its keys
 * from, RFC 5764) is **byte-exact** with what BoringSSL's `SSL_export_keying_material` produces from the
 * same handshake. Both peers derive identical material from the shared secret, so after a handshake our
 * engine's `exportKeyingMaterial("EXTRACTOR-dtls_srtp", null, N)` must equal the oracle's `exportSrtpKeys(N)`.
 *
 * Covered across both DTLS versions and both role directions — the exporter's `"dtls13"`-prefixed
 * HKDF-Expand-Label (1.3) and `P_SHA256` PRF (1.2) are each a distinct code path this pins to BoringSSL.
 * This is the Phase-2-media prerequisite: the SRTP key+salt for each direction is sliced out of this output.
 */
class DtlsExporterDifferentialTest {
    private val srtpLabel = "EXTRACTOR-dtls_srtp"

    // 2 × (client_write_key 16 ‖ client_salt 14) + server = 60 B for SRTP_AES128_CM_SHA1_80 (RFC 5764 §4.1.2).
    private val length = 60

    @Test
    fun exporter_byte_exact_vs_boringssl_dtls13_our_client() = exporterDifferential(DtlsConfig(), ourIsClient = true)

    @Test
    fun exporter_byte_exact_vs_boringssl_dtls13_our_server() = exporterDifferential(DtlsConfig(), ourIsClient = false)

    @Test
    fun exporter_byte_exact_vs_boringssl_dtls12_our_client() = exporterDifferential(DtlsConfig(enableDtls13 = false), ourIsClient = true)

    @Test
    fun exporter_byte_exact_vs_boringssl_dtls12_our_server() = exporterDifferential(DtlsConfig(enableDtls13 = false), ourIsClient = false)

    private fun exporterDifferential(
        config: DtlsConfig,
        ourIsClient: Boolean,
    ) {
        val ours = DtlsEngine(config)
        val oracle = BoringSslDtlsEngine(config)
        try {
            val (c, s) =
                if (ourIsClient) {
                    DtlsConductor().drive(ours.endpoint(), oracle.endpoint())
                } else {
                    DtlsConductor().drive(oracle.endpoint(), ours.endpoint())
                }
            assertIs<DtlsState.Established>(c, "client established, was $c")
            assertIs<DtlsState.Established>(s, "server established, was $s")

            val oursKeys = ours.exportKeyingMaterial(srtpLabel, null, length)
            assertNotNull(oursKeys, "our engine exported keying material once established")
            val oracleKeys = oracle.exportSrtpKeys(length)
            assertEquals(
                hexOf(oracleKeys),
                hexOf(oursKeys),
                "DTLS-SRTP keying material is byte-exact vs BoringSSL (enableDtls13=${config.enableDtls13}, ourIsClient=$ourIsClient)",
            )
        } finally {
            ours.close()
            oracle.close()
        }
    }
}

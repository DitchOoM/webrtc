package com.ditchoom.webrtc.dtls

import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The W4 linkage de-risk (EXECUTION_PLAN "W4 sequencing"): this test binary links webrtc-dtls's
 * `libssl.a` **and** buffer-crypto's `libcrypto.a` into one Kotlin/Native executable. Had the two
 * BoringSSL archives duplicate-symbol-clashed (the socket/quiche hazard), it would fail to link — so
 * a green run proves libssl resolves against buffer-crypto's single libcrypto, no second copy.
 */
class DtlsBackendLinkNativeTest {
    @Test
    fun libssl_links_against_buffer_cryptos_libcrypto() {
        assertTrue(boringSslProbe() != 0L, "expected a live BoringSSL DTLS_method handle from libssl")
    }
}

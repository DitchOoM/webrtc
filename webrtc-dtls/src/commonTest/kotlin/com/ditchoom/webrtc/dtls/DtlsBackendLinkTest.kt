package com.ditchoom.webrtc.dtls

import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Smoke: the backend probe is callable on every target (0 where DTLS is deferred to boringssl-kmp or
 * browser-delegated). The strong link-proof — that libssl and libcrypto coexist in one binary — is
 * the native assertion in `src/linuxTest` (see DtlsBackendLinkNativeTest).
 */
class DtlsBackendLinkTest {
    @Test
    fun backend_probe_is_callable() {
        assertTrue(dtlsBackendProbe() >= 0L)
    }
}

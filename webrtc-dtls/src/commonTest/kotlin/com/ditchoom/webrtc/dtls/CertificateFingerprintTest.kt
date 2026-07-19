package com.ditchoom.webrtc.dtls

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Regression fixture for the adversarial-gate BLOCKER: [CertificateFingerprint] is the RFC 8122
 * `a=fingerprint` identity, compared as a security discriminant (RFC 8827) in the DTLS driver. Its
 * primary constructor is private and [CertificateFingerprint.ofHex] is the only way to build one, so a
 * value can never hold a non-normalized or malformed digest — otherwise the same certificate could
 * compare unequal across two spellings and silently defeat peer authentication.
 */
class CertificateFingerprintTest {
    // 32 bytes → 64 hex chars. Distinct byte values so a truncation/format bug can't accidentally pass.
    private val lowerHex = (0 until 32).joinToString("") { (it * 7 and 0xFF).toString(16).padStart(2, '0') }

    @Test
    fun ofHex_normalizes_case_and_colons_so_the_same_digest_is_always_equal() {
        val colonUpper = lowerHex.uppercase().chunked(2).joinToString(":") // "AB:CD:…" SDP form
        // Three spellings of ONE digest must all be the same value — the a=fingerprint check compares a
        // peer's cert digest (built lowercase by the engine) against the SDP-advertised one (any casing).
        assertEquals(CertificateFingerprint.ofHex(lowerHex), CertificateFingerprint.ofHex(colonUpper))
        assertEquals(CertificateFingerprint.ofHex(lowerHex), CertificateFingerprint.ofHex(lowerHex.uppercase()))
        assertEquals(lowerHex, CertificateFingerprint.ofHex(colonUpper).sha256Hex)
    }

    @Test
    fun ofHex_rejects_anything_that_is_not_a_32_byte_sha256_digest() {
        assertFailsWith<IllegalArgumentException>("empty") { CertificateFingerprint.ofHex("") }
        assertFailsWith<IllegalArgumentException>("too short") { CertificateFingerprint.ofHex("abcd") }
        assertFailsWith<IllegalArgumentException>("too long") { CertificateFingerprint.ofHex(lowerHex + "ab") }
        // Right length, but not hex — the case that would slip past a length-only guard.
        assertFailsWith<IllegalArgumentException>("non-hex") { CertificateFingerprint.ofHex("zz".repeat(32)) }
    }

    @Test
    fun sdp_renders_the_rfc8122_uppercase_colon_form() {
        val fp = CertificateFingerprint.ofHex(lowerHex)
        val expectedValue = lowerHex.uppercase().chunked(2).joinToString(":")
        assertEquals(expectedValue, fp.sdpValue)
        assertEquals("sha-256 $expectedValue", fp.sdp)
    }
}

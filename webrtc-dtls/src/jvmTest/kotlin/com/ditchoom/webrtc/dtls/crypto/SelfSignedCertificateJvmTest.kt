package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Differential oracle for the hand-written TBSCertificate DER template: the JVM's own X.509 parser
 * (`java.security`) must parse our self-signed cert, its `verify(publicKey)` must accept the
 * self-signature (proving the ECDSA-P256 signature over the TBS is well-formed and DER-correct), and the
 * SHA-256 fingerprint we compute must equal the one over the exact DER bytes. If the DER is malformed,
 * `generateCertificate` throws; if the signature or TBS is wrong, `verify` throws.
 */
class SelfSignedCertificateJvmTest {
    @Test
    fun self_signed_cert_parses_verifies_and_fingerprint_matches_the_der() {
        val cert = SelfSignedCertificate.generate(BufferFactory.managed(), Random(1234))
        try {
            val der = toByteArray(cert.derEncoded)
            val x509 =
                CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(ByteArrayInputStream(der)) as X509Certificate

            // The self-signature verifies against the cert's own public key (throws on failure).
            x509.verify(x509.publicKey)

            assertEquals("EC", x509.publicKey.algorithm)
            assertTrue(x509.subjectX500Principal.name.contains("CN=WebRTC"))
            assertEquals(x509.subjectX500Principal, x509.issuerX500Principal) // self-signed

            val expectedHex =
                MessageDigest
                    .getInstance("SHA-256")
                    .digest(der)
                    .joinToString("") { "%02x".format(it) }
            assertEquals(expectedHex, cert.fingerprint.sha256Hex)
            assertEquals(64, cert.fingerprint.sha256Hex.length)
        } finally {
            cert.close()
        }
    }

    @Suppress("NoByteArrayInProd") // test-only: JVM X.509 parser input; not a *Main source set
    private fun toByteArray(buf: ReadBuffer): ByteArray {
        val p = buf.position()
        val out = ByteArray(buf.remaining())
        var i = 0
        while (buf.remaining() > 0) out[i++] = buf.readByte()
        buf.position(p)
        return out
    }
}

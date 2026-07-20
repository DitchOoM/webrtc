package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.dtls.engineCryptoAvailable
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The ECDHE key exchange + the `rawEcdhPremaster` suspend→blocking bridge: two independently-generated
 * P-256 keypairs must derive the **same** raw shared secret from each other's public point (the DH
 * agreement property), and that secret is the TLS 1.2 pre-master. Proves the bridge returns a real
 * secret synchronously on this target, not a stub.
 */
class EcdheKeyExchangeTest {
    @Test
    fun both_sides_derive_the_same_premaster_secret() {
        if (!engineCryptoAvailable()) return // browsers delegate; the engine's blocking crypto isn't here
        val a = EcdheKeyExchange.generate()
        val b = EcdheKeyExchange.generate()
        try {
            assertEquals(65, a.localPublicPoint.remaining(), "P-256 uncompressed point is 65 bytes")
            val secretAb = a.premasterSecret(b.localPublicPoint)
            val secretBa = b.premasterSecret(a.localPublicPoint)
            try {
                assertEquals(32, secretAb.remaining(), "P-256 shared secret is the 32-byte X coordinate")
                assertEquals(hexOf(secretAb), hexOf(secretBa), "DH agreement: both sides compute the same secret")
                assertTrue(hexOf(secretAb).any { it != '0' }, "secret is not all-zero")
            } finally {
                secretAb.freeNativeMemory()
                secretBa.freeNativeMemory()
            }
        } finally {
            a.close()
            b.close()
        }
    }

    private fun hexOf(buf: ReadBuffer): String {
        val p = buf.position()
        val sb = StringBuilder()
        while (buf.remaining() > 0) {
            val v = buf.readByte().toInt() and 0xFF
            sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 0xF])
        }
        buf.position(p)
        return sb.toString()
    }
}

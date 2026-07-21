package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Pins the TLS 1.2 PRF to the canonical `P_SHA256` known-answer vector (the widely-cited IETF TLS WG
 * test: secret/seed/label → 100 output bytes) so the key schedule is byte-exact against an independent
 * reference, not just self-consistent. If this drifts, every derived secret (master, key block,
 * verify_data) is silently wrong — so it is the load-bearing crypto check for DTLS 1.2.
 */
class Tls12KeyScheduleTest {
    private val schedule = Tls12KeySchedule(BufferFactory.managed())

    @Test
    fun prf_sha256_matches_the_canonical_tls12_test_vector() {
        val secret = hex("9bbe436ba940f017b17652849a71db35")
        val seed = hex("a0ba9f936cda311827a6f796ffd5198c")
        val expected =
            "e3f229ba727be17b8d122620557cd453" +
                "c2aab21d07c3d495329b52d4e61edb5a" +
                "6b301791e90d35c9c9a46b4e14baf9af" +
                "0fa022f7077def17abfd3797c0564bab" +
                "4fbc91666e9def9b97fce34f796789ba" +
                "a48082d122ee42c5a72e5a5110fff701" +
                "87347b66"
        val out = schedule.prf(secret, "test label", seed, 100)
        assertEquals(expected, hexOf(out))
    }

    @Test
    fun master_secret_and_key_block_have_the_expected_widths() {
        val pms = hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        val cr = hex("01".repeat(32))
        val sr = hex("02".repeat(32))
        val ms = schedule.masterSecret(pms, cr, sr, sessionHash = null)
        assertEquals(48, ms.remaining())
        // AES-128-GCM key block: 2×16 keys + 2×4 IVs = 40 bytes.
        val kb = schedule.keyBlock(ms, sr, cr, 40)
        assertEquals(40, kb.remaining())
        val vd = schedule.verifyData(ms, Tls12KeySchedule.CLIENT_FINISHED_LABEL, hex("aa".repeat(32)))
        assertEquals(12, vd.remaining())
    }

    private fun hex(s: String): ReadBuffer {
        val b = BufferFactory.managed().allocate(s.length / 2, ByteOrder.BIG_ENDIAN)
        var i = 0
        while (i < s.length) {
            b.writeByte(s.substring(i, i + 2).toInt(16).toByte())
            i += 2
        }
        b.resetForRead()
        return b
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

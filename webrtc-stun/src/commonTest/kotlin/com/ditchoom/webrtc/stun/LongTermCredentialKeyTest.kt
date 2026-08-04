package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.toReadBuffer
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Known-answer tests for the long-term credential key (RFC 8489 §9.2.2) and the MD5 underneath it.
 *
 * The MD5 vectors are RFC 1321 Appendix A.5 verbatim, plus the padding boundaries that appendix does
 * not reach: a message ending at 55/56/63/64 bytes is where the length field either fits in the final
 * block or forces an extra one, and it is the classic place a hand-written digest is wrong.
 * [longTermCredentialKeyMatchesRfc5769] is the interop-grade one — see its KDoc.
 */
class LongTermCredentialKeyTest {
    @Test
    fun rfc1321AppendixA5Vectors() {
        assertMd5("d41d8cd98f00b204e9800998ecf8427e", "")
        assertMd5("0cc175b9c0f1b6a831c399e269772661", "a")
        assertMd5("900150983cd24fb0d6963f7d28e17f72", "abc")
        assertMd5("f96b697d7cb7938d525a2f31aaf161d0", "message digest")
        assertMd5("c3fcd3d76192e4007dfb496cca67e13b", "abcdefghijklmnopqrstuvwxyz")
        assertMd5(
            "d174ab98d277d9f5a5611c2c9f419d9f",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        )
        assertMd5(
            "57edf4a22be3c955ac49da2e2107b67a",
            "1234567890".repeat(8),
        )
    }

    @Test
    fun paddingBoundaries() {
        // 55 = the last length whose 0x80 + 8-byte length still fits one block; 56..63 force a second
        // block; 64 is an exact block, 65 starts a third. Each is a different branch of `finish()`.
        assertMd5("ef1772b6dff9a122358552954ad0df65", "a".repeat(55))
        assertMd5("3b0c8ac703f828b04c6c197006d17218", "a".repeat(56))
        assertMd5("b06521f39153d618550606be297466d5", "a".repeat(63))
        assertMd5("014842d480b571495a4a0363793f7367", "a".repeat(64))
        assertMd5("c743a45e0d2e6a95cb859adae0248435", "a".repeat(65))
        assertMd5("8a7bd0732ed6a28ce75f6dabc90e1613", "a".repeat(119))
        assertMd5("5f61c0ccad4cac44c75ff505e1f1e537", "a".repeat(120))
    }

    /**
     * The credential fields are joined by `:` and hashed as one UTF-8 string, so a multi-byte username
     * must contribute its *encoded* bytes — not one byte per UTF-16 char. The key here is the one RFC
     * 5769 §2.4's MESSAGE-INTEGRITY is computed under (proven end-to-end in
     * [Rfc5769VectorsTest.sampleRequestWithLongTermAuthentication]).
     */
    @Test
    fun keyIsMd5OfColonJoinedUtf8Fields() {
        assertEquals(
            "e8ca7ad59d5eb0518e312911d2dab2a9",
            hex(longTermCredentialKey(RFC5769_USERNAME, "example.org", "TheMatrIX")),
        )
        // Equivalently: MD5 of the concatenation. Pins the separator and the field order.
        assertMd5("e8ca7ad59d5eb0518e312911d2dab2a9", "$RFC5769_USERNAME:example.org:TheMatrIX")
    }

    @Test
    fun keyIsSixteenBytesAndReadReady() {
        val key = longTermCredentialKey("user", "realm", "pass")
        assertEquals(0, key.position())
        assertEquals(Md5Core.MD5_DIGEST_BYTES, key.remaining())
    }

    /** A different realm derives a different key — this is what makes a stale-realm retry fail closed. */
    @Test
    fun realmIsPartOfTheKey() {
        val a = hex(longTermCredentialKey("user", "example.org", "pass"))
        val b = hex(longTermCredentialKey("user", "example.net", "pass"))
        assertEquals(false, a == b, "realm must change the derived key")
    }

    /** Empty fields are legal input and must not trip the padding path (the `""` MD5 vector's sibling). */
    @Test
    fun emptyFieldsAreHashedAsWritten() {
        assertEquals(hex(longTermCredentialKey("", "", "")), md5Hex("::"))
    }

    private fun assertMd5(
        expected: String,
        message: String,
    ) = assertEquals(expected, md5Hex(message), "MD5(${message.take(MESSAGE_PREVIEW_CHARS)}…)")

    private fun md5Hex(message: String): String {
        val md5 = Md5Core()
        md5.update(message.toReadBuffer(Charset.UTF8))
        md5.finish()
        return buildString {
            for (i in 0 until Md5Core.MD5_DIGEST_BYTES) append(byteHex(md5.digestByte(i)))
        }
    }

    private fun hex(buffer: ReadBuffer): String =
        buildString {
            for (i in buffer.position() until buffer.limit()) append(byteHex(buffer.get(i)))
        }

    private fun byteHex(b: Byte): String = (b.toInt() and BYTE_MASK).toString(HEX_RADIX).padStart(2, '0')

    private companion object {
        const val HEX_RADIX = 16
        const val BYTE_MASK = 0xFF
        const val MESSAGE_PREVIEW_CHARS = 32

        /** RFC 5769 §2.4's username: "マトリックス", six katakana that are three UTF-8 bytes each. */
        const val RFC5769_USERNAME = "マトリックス"
    }
}

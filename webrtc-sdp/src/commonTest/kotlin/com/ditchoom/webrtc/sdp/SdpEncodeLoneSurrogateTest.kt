// Surrogate code units (0xD800..0xDFFF) are the subject under test; naming each would obscure the
// cases rather than clarify them.
@file:Suppress("MagicNumber")

package com.ditchoom.webrtc.sdp

import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.freeIfNeeded
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * **`SessionDescription.encode()` must not throw, and must allocate exactly what it writes — including
 * when a line value holds invalid UTF-16.**
 *
 * That input is reachable through public API: [SessionDescriptionBuilder.line], `sessionName` and
 * `attribute` all take an arbitrary `String`, so any application text lands in a line verbatim. Neither
 * `SdpCodecFuzzer` nor `SdpMalformedCorpusTest` can reach it — both drive [SessionDescription.parse],
 * whose `readString` rejects invalid UTF-8, and valid UTF-8 never decodes to an unpaired surrogate. So
 * the "encode must not throw" contract those two assert was **only** ever exercised on the parse side.
 *
 * Before the fix, one lone surrogate was three different defects depending on where it ran (measured at
 * buffer 6.28.1, not assumed):
 *
 * | target | `writeString("\uD800€")` | consequence |
 * |---|---|---|
 * | JVM | throws `MalformedInputException` | `encode()` throws, contract broken |
 * | Apple, JS | writes 6 bytes | 2-byte overrun of a 4-byte allocation |
 * | Linux K/N | writes 0, position unchanged | silent truncation to an empty document |
 *
 * The 4 came from `utf8ByteLength` charging a full surrogate pair for any high surrogate and consuming
 * the next char without counting it — so the `€` contributed nothing. `wellFormed` substitutes U+FFFD
 * ahead of the encode, which is what two of the four targets already did, so all four now write the same
 * bytes and the count is exact everywhere.
 *
 * The assertions read the length back **from the encoder** (`remaining()` after `encode`) rather than
 * from a second hand-written counter, which would only assert that two implementations of the same
 * mistake agree.
 */
class SdpEncodeLoneSurrogateTest {
    /** `s=<value>` and nothing else, so the byte count is `2 + value + CRLF` and easy to reason about. */
    private fun encodeSessionName(value: String): Pair<Int, String> {
        val sdp =
            SessionDescriptionBuilder()
                .line('s', value)
                .build()
        val buffer = sdp.encode()
        return try {
            val n = buffer.remaining()
            // Declared CharSequence because that is the common-source return type; `.toString()` is
            // required there and only looks redundant on JVM, where it resolves to String.
            val decoded: CharSequence = buffer.readString(n, Charset.UTF8)
            n to decoded.toString()
        } finally {
            buffer.freeIfNeeded()
        }
    }

    @Test
    fun loneHighSurrogateBecomesReplacementCharacter() {
        val (bytes, text) = encodeSessionName("\uD800")
        assertEquals("s=�\r\n", text)
        assertEquals(7, bytes, "2 for \"s=\" + 3 for U+FFFD + 2 for CRLF")
    }

    @Test
    fun loneLowSurrogateBecomesReplacementCharacter() {
        val (bytes, text) = encodeSessionName("\uDC00")
        assertEquals("s=�\r\n", text)
        assertEquals(7, bytes)
    }

    /**
     * The regression proper. The old counter returned 4 for `"\uD800€"` — a full pair for the surrogate,
     * nothing at all for the `€` it swallowed — against the 6 bytes Apple and JS actually write.
     */
    @Test
    fun loneHighSurrogateDoesNotSwallowTheFollowingCharacter() {
        val (bytes, text) = encodeSessionName("\uD800€")
        assertEquals("s=�€\r\n", text)
        assertEquals(10, bytes, "2 + 3 for U+FFFD + 3 for € + 2 — the old counter sized this 8")
    }

    /** The swallowed char is only visibly lost when it is multi-byte, which is why ASCII hid this. */
    @Test
    fun loneHighSurrogateFollowedByAscii() {
        val (bytes, text) = encodeSessionName("\uD800A")
        assertEquals("s=�A\r\n", text)
        assertEquals(8, bytes)
    }

    /** A well-formed pair is untouched: one 4-byte code point, not two replacement characters. */
    @Test
    fun wellFormedSurrogatePairIsUnchanged() {
        val (bytes, text) = encodeSessionName("😀")
        assertEquals("s=😀\r\n", text)
        assertEquals(8, bytes, "2 + 4 for the emoji + 2")
    }

    /** Multi-byte BMP text was already correct and must stay exact — no over-allocation either. */
    @Test
    fun multiByteBmpTextIsSizedExactly() {
        val (bytes, text) = encodeSessionName("€ü")
        assertEquals("s=€ü\r\n", text)
        assertEquals(9, bytes, "2 + 3 for € + 2 for ü + 2")
    }

    /** Every surrogate in a run is substituted independently, not collapsed or paired across the run. */
    @Test
    fun adjacentLoneSurrogatesEachBecomeOneReplacement() {
        val (bytes, text) = encodeSessionName("\uD800\uD800")
        assertEquals("s=��\r\n", text)
        assertEquals(10, bytes)
    }

    /** A pair immediately after a lone surrogate still pairs — the substitution must not consume it. */
    @Test
    fun loneSurrogateFollowedByAPairKeepsThePair() {
        val (bytes, text) = encodeSessionName("\uD800😀")
        assertEquals("s=�😀\r\n", text)
        assertEquals(11, bytes, "2 + 3 for U+FFFD + 4 for the emoji + 2")
    }
}

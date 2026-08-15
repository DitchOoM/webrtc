// Surrogate code units (0xD800..0xDFFF) are the subject under test; naming each would obscure the
// cases rather than clarify them.
@file:Suppress("MagicNumber")

package com.ditchoom.webrtc.sdp

import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.readText
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * **`SessionDescription.encode()` must not throw, and must allocate exactly what it writes — including
 * when a line value holds invalid UTF-16.**
 *
 * That input is reachable through public API: [SessionDescriptionBuilder.line], `sessionName` and
 * `attribute` all take an arbitrary `String`, so any application text lands in a line verbatim. Neither
 * `SdpCodecFuzzer` nor `SdpMalformedCorpusTest` can reach it — both drive [SessionDescription.parse],
 * which rejects invalid UTF-8, and valid UTF-8 never decodes to an unpaired surrogate. So the "encode
 * must not throw" contract those two assert was **only** ever exercised on the parse side.
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
 * the next char without counting it — so the `€` contributed nothing. Both of that fix's halves are now
 * buffer's: `encode` writes through `Utf8.Lenient`, which substitutes U+FFFD on every platform, and sizes
 * from `utf8Size()`, which buffer guarantees equals what that policy writes. These assertions are
 * unchanged across that migration, which is the point of keeping them — they pin the *observable*
 * contract (bytes out, text out), not the implementation that satisfies it.
 *
 * The assertions read the length back **from the encoder** (`remaining()` after `encode`) rather than
 * from a second hand-written counter, which would only assert that two implementations of the same
 * mistake agree.
 */
class SdpEncodeLoneSurrogateTest {
    /**
     * Surrogates are built at **runtime**, never written as string literals.
     *
     * DitchOoM/buffer#354 measured Kotlin/JS's clean-build codegen lossily rewriting an unpaired
     * surrogate in a string *literal* to `'?'` (incremental builds emitted it faithfully, so it hid until
     * a cold leg), which flipped their `TextEncodingTests` red. That is the exact substitution this suite
     * exists to pin, performed by the compiler on the fixture rather than by the encoder under test — it
     * would quietly turn every expectation below into a claim about `"?"`.
     *
     * **Not reproduced here**: measured on a clean `:webrtc-sdp:jsNodeTest` at Kotlin 2.4.0, a literal
     * `"\uD800"` survives with `[0].code == 0xD800`, identical to the runtime-constructed form. So this is
     * not currently load-bearing on this toolchain. It is kept because it costs nothing, because the
     * failure mode is silent and target-specific, and because the corpus should not depend on which
     * Kotlin version compiles it. Do not "simplify" it back to literals on the strength of a green JS
     * lane — that lane is exactly what would stay green while the fixture stopped testing anything.
     *
     * Valid pairs are unaffected either way, so the emoji cases below stay literal.
     */
    private val hi = Char(0xD800).toString()
    private val lo = Char(0xDC00).toString()

    /** `s=<value>` and nothing else, so the byte count is `2 + value + CRLF` and easy to reason about. */
    private fun encodeSessionName(value: String): Pair<Int, String> {
        val sdp =
            SessionDescriptionBuilder()
                .line('s', value)
                .build()
        val buffer = sdp.encode()
        return try {
            val n = buffer.remaining()
            n to buffer.readText(n)
        } finally {
            buffer.freeIfNeeded()
        }
    }

    @Test
    fun loneHighSurrogateBecomesReplacementCharacter() {
        val (bytes, text) = encodeSessionName(hi)
        assertEquals("s=�\r\n", text)
        assertEquals(7, bytes, "2 for \"s=\" + 3 for U+FFFD + 2 for CRLF")
    }

    @Test
    fun loneLowSurrogateBecomesReplacementCharacter() {
        val (bytes, text) = encodeSessionName(lo)
        assertEquals("s=�\r\n", text)
        assertEquals(7, bytes)
    }

    /**
     * The regression proper. The old counter returned 4 for `"\uD800€"` — a full pair for the surrogate,
     * nothing at all for the `€` it swallowed — against the 6 bytes Apple and JS actually write.
     */
    @Test
    fun loneHighSurrogateDoesNotSwallowTheFollowingCharacter() {
        val (bytes, text) = encodeSessionName(hi + "€")
        assertEquals("s=�€\r\n", text)
        assertEquals(10, bytes, "2 + 3 for U+FFFD + 3 for € + 2 — the old counter sized this 8")
    }

    /** The swallowed char is only visibly lost when it is multi-byte, which is why ASCII hid this. */
    @Test
    fun loneHighSurrogateFollowedByAscii() {
        val (bytes, text) = encodeSessionName(hi + "A")
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
        val (bytes, text) = encodeSessionName(hi + hi)
        assertEquals("s=��\r\n", text)
        assertEquals(10, bytes)
    }

    /** A pair immediately after a lone surrogate still pairs — the substitution must not consume it. */
    @Test
    fun loneSurrogateFollowedByAPairKeepsThePair() {
        val (bytes, text) = encodeSessionName(hi + "😀")
        assertEquals("s=�😀\r\n", text)
        assertEquals(11, bytes, "2 + 3 for U+FFFD + 4 for the emoji + 2")
    }

    /**
     * A low surrogate *followed* by a high one is two unpaired surrogates, not a pair read backwards —
     * the arm a scanner that only looks ahead from a high surrogate can get wrong in the other direction.
     */
    @Test
    fun reversedSurrogateOrderIsTwoReplacements() {
        val (bytes, text) = encodeSessionName(lo + hi)
        assertEquals("s=��\r\n", text)
        assertEquals(10, bytes)
    }
}

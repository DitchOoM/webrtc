package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.Utf8
import com.ditchoom.buffer.writeText
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * **[textBuffer]'s read window must be exactly the encoded text, on every target.**
 *
 * This is a real invariant rather than a tidiness one: the window is where the harness peer's message
 * ends. Too long and it publishes uninitialised bytes past the text; too short and it truncates. Either
 * way the peer puts something on the wire that is not the string it meant to send, and the interop lane
 * that catches it reports a content mismatch with no hint as to why.
 *
 * The fixture used to assert this one layer down, against a local `utf8Len` counter that [textBuffer]
 * called `setLimit` with — that counter is gone (buffer 6.30.0's `utf8Size()` is guaranteed to equal what
 * `Utf8.Lenient` writes, so sizing needs no local implementation), and with it the failure mode it
 * existed to catch. What survives is the property that was always the point: **round-trip fidelity and an
 * exact extent**, asserted against the encoder rather than against a second hand-written counter, which
 * would only prove that two implementations of the same mistake agree.
 */
class Utf8LenTest {
    // The encoder's own answer, measured with the same policy [textBuffer] writes through. Sized four
    // bytes per char — the widest UTF-8 gets — so it cannot be too small for any input, and so that what
    // is measured is what the encoder WRITES rather than what it was given room for.
    private fun encodedLength(s: String): Int {
        val buf = BufferFactory.Default.allocate(maxOf(1, s.length * BYTES_PER_CHAR_MAX), ByteOrder.BIG_ENDIAN)
        buf.writeText(s, Utf8.Lenient)
        return buf.position()
    }

    @Test
    fun textBuffer_extent_agrees_with_the_encoder_on_every_shape_of_text() {
        val corpus =
            listOf(
                "" to "empty",
                "ping" to "ASCII — the only shape the harness sends today",
                "s2#0" to "an index tag",
                "é" to "two-byte (U+00E9)",
                "€" to "three-byte (U+20AC)",
                "😀" to "four-byte astral pair (U+1F600) — the arm that was wrong",
                "a😀b" to "an astral pair between ASCII",
                "😀😀" to "two astral pairs, adjacent",
                "héllo wörld" to "mixed one- and two-byte",
                "日本語" to "three three-byte characters",
            )
        for ((text, what) in corpus) {
            assertEquals(encodedLength(text), textBuffer(text).remaining(), "textBuffer's extent disagrees for $what")
        }
    }

    /**
     * The consequence, asserted end to end: whatever [textBuffer] hands the wire must read back as the
     * string it was given, through the harness's own [text] decoder. This is the assertion that failed
     * before the surrogate arm existed — the old counter said six for a four-byte emoji, so the limit sat
     * two bytes past the encoded text.
     */
    @Test
    fun textBuffer_round_trips_every_shape_of_text() {
        for (text in listOf("ping", "é", "€", "😀", "a😀b", "日本語")) {
            assertEquals(text, textBuffer(text).text(), "round trip of \"$text\"")
        }
    }

    private companion object {
        private const val BYTES_PER_CHAR_MAX = 4
    }
}

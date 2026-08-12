package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * [utf8Len] must agree with what the encoder actually writes, on every target.
 *
 * This is a real invariant rather than a tidiness one: [textBuffer] calls `setLimit(utf8Len(s))` **after**
 * `writeString` has written the bytes, so the count is what decides where the buffer ends. An over-count
 * publishes uninitialised bytes past the text; an under-count truncates it. Either way the harness peer
 * puts something on the wire that is not the string it meant to send, and the interop lane that catches it
 * reports a content mismatch with no hint as to why.
 *
 * The measurement is taken from the encoder itself (`position()` after `writeString`) rather than from a
 * second hand-written counter, which would only assert that two implementations of the same mistake agree.
 */
class Utf8LenTest {
    private fun encodedLength(s: String): Int {
        // Four bytes per char is the widest UTF-8 gets, so this cannot be too small for any input.
        val buf = BufferFactory.Default.allocate(maxOf(1, s.length * 4), ByteOrder.BIG_ENDIAN)
        buf.writeString(s, Charset.UTF8)
        return buf.position()
    }

    @Test
    fun utf8Len_agrees_with_the_encoder_on_every_shape_of_text() {
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
            assertEquals(encodedLength(text), utf8Len(text), "utf8Len disagrees with the encoder for $what")
        }
    }

    /**
     * The consequence, asserted end to end: whatever [textBuffer] hands the wire must read back as the
     * string it was given. This is the assertion that would have failed before the surrogate arm existed —
     * `utf8Len` said six for a four-byte emoji, so the limit sat two bytes past the encoded text.
     */
    @Test
    fun textBuffer_round_trips_every_shape_of_text() {
        for (text in listOf("ping", "é", "€", "😀", "a😀b", "日本語")) {
            val buf = textBuffer(text)
            assertEquals(encodedLength(text), buf.remaining(), "textBuffer's extent for \"$text\"")
            assertEquals(text, buf.readString(buf.remaining(), Charset.UTF8), "round trip of \"$text\"")
        }
    }
}

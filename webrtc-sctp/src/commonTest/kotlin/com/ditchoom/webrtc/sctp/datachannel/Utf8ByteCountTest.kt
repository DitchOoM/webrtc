// Surrogate code units (0xD800..0xDFFF) are the subject of two fixtures here; naming each would obscure
// the cases rather than clarify them.
@file:Suppress("MagicNumber")

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Utf8
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.managed
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * **`DataChannelPayload.Text.wireByteCount` must equal what the encoder actually writes, on every target.**
 *
 * This is the residue the whole send gate rests on. The gate refuses a message against the peer's
 * `a=max-message-size` using this count, while the bytes that reach the wire come from the encoder, so a
 * disagreement is a silent hole in one direction or a spurious refusal in the other:
 *
 * - **under-count** → a message the gate passed is larger on the wire than the peer agreed to receive,
 *   which RFC 8831 §6.6 makes a MUST NOT. It surfaces as the peer aborting the association, with nothing
 *   local to point at.
 * - **over-count** → a message the peer would have taken is refused. Visible, and harmless.
 *
 * Since buffer 6.30.0 the count is load-bearing a second way: `SctpDataChannelStack.encodeUtf8` sizes its
 * scratch allocation from this exact number, so an **over**-count is no longer merely a spurious refusal
 * — it would leave uninitialised bytes inside the allocation, and an under-count would overflow it.
 *
 * The expectation is measured **from the encoder itself** (`position()` after the write) rather than from
 * a second hand-written counter, which would only assert that two implementations of the same mistake
 * agree. That distinction is not hypothetical: `webrtc-harness-endpoint`'s `utf8Len` charged three bytes
 * per `Char` and so counted six for a four-byte emoji, and a mirror-image counter in the test would have
 * agreed with it.
 *
 * **The unpaired-surrogate fixture asserts equality now, and it used to assert only `>=`.** That was not
 * timidity: the send path wrote through `writeString`, which *threw* `MalformedInputException` on the JVM
 * where a `TextEncoder`-backed target substituted U+FFFD, so no equality held across targets and "never
 * under-count" was the strongest true statement. The path now writes through [Utf8.Lenient], which
 * substitutes on every target, so the three-byte arm is exactly right rather than merely safe — and the
 * measured expectation below can no longer come back null, which is why the encoder helper has no catch.
 */
class Utf8ByteCountTest {
    /**
     * Surrogates are built at **runtime**, never written as string literals.
     *
     * DitchOoM/buffer#354 measured Kotlin/JS's clean-build codegen rewriting an unpaired surrogate in a
     * literal to `'?'` (incremental builds emitted it faithfully, so it hid until a cold leg), which
     * would silently turn the fixture below into a one-byte-ASCII corpus that proves nothing.
     *
     * **Not reproduced on this toolchain** — measured at Kotlin 2.4.0, a literal `"\uD800"` survives a
     * clean JS build intact — so it is not load-bearing today. Kept regardless: it costs nothing, the
     * failure is silent and target-specific, and a corpus about surrogate handling should not be at the
     * mercy of which compiler version reads it. See `SdpEncodeLoneSurrogateTest` for the same note.
     *
     * Valid pairs are unaffected, so the emoji cases stay literal.
     */
    private val hi = Char(0xD83D).toString()
    private val lo = Char(0xDE00).toString()

    // The encoder's own answer. Sized generously: what is under test is what the send path WRITES, and
    // constraining the buffer to the count being verified would make the assertion circular.
    private fun encodedLength(text: String): Long {
        val scratch = BufferFactory.managed().allocate(text.length * BYTES_PER_CHAR_MAX + 1, ByteOrder.BIG_ENDIAN)
        return try {
            scratch.writeText(text, Utf8.Lenient)
            scratch.position().toLong()
        } finally {
            scratch.freeIfNeeded()
        }
    }

    private fun assertAgrees(
        text: String,
        what: String,
    ) = assertEquals(
        encodedLength(text),
        DataChannelPayload.Text(text).wireByteCount,
        "wireByteCount disagrees with the encoder for $what",
    )

    @Test
    fun wireByteCount_agrees_with_the_encoder_on_every_well_formed_text() {
        val corpus =
            listOf(
                "" to "the empty string",
                "ping" to "plain ASCII",
                "s2#0" to "ASCII with punctuation",
                "é" to "one two-byte code point",
                "héllo" to "ASCII around a two-byte code point",
                "" to "the last one-byte code point",
                "" to "the first two-byte code point",
                "߿" to "the last two-byte code point",
                "ࠀ" to "the first three-byte code point",
                "￿" to "the last BMP code point",
                "中文字" to "three three-byte code points",
                "😀" to "an emoji — ONE code point, FOUR bytes, TWO Chars",
                "a😀b" to "an emoji between ASCII",
                "😀😁" to "two adjacent surrogate pairs",
            )
        for ((text, what) in corpus) assertAgrees(text, what)
    }

    /**
     * An unpaired surrogate is not encodable, so what reaches the wire is [Utf8.Lenient]'s U+FFFD — three
     * bytes, on every target. The three-byte arm of the counter is therefore exact, not conservative.
     */
    @Test
    fun an_unpaired_surrogate_is_counted_as_the_replacement_character_it_becomes() {
        val corpus =
            listOf(
                hi to "an unpaired high surrogate",
                lo to "an unpaired low surrogate",
                "a${hi}b" to "an unpaired high surrogate between ASCII",
                "$hi😀" to "an unpaired high surrogate followed by a real pair",
                "😀$lo" to "a real pair followed by an unpaired low surrogate",
                lo + hi to "a low surrogate before a high one — two unpaired, not a reversed pair",
                hi + hi to "two adjacent high surrogates",
            )
        for ((text, what) in corpus) assertAgrees(text, what)
        // Stated absolutely as well, so a change that moved BOTH the counter and the encoder off U+FFFD
        // together could not keep this green by agreeing with itself.
        assertEquals(3L, DataChannelPayload.Text(hi).wireByteCount, "U+FFFD is three UTF-8 bytes")
    }

    // The distinction the gate exists for, stated on its own: a size check fed `String.length` passes a
    // message that is two or four times larger on the wire.
    @Test
    fun wireByteCount_is_not_the_character_count() {
        assertEquals(1, "é".length)
        assertEquals(2L, DataChannelPayload.Text("é").wireByteCount)
        assertEquals(2, "😀".length)
        assertEquals(4L, DataChannelPayload.Text("😀").wireByteCount)
    }

    @Test
    fun a_binary_payload_reports_its_remaining_bytes() {
        val buf = BufferFactory.managed().allocate(4, ByteOrder.BIG_ENDIAN)
        repeat(4) { buf.writeByte(it.toByte()) }
        buf.resetForRead()
        buf.setLimit(4)
        try {
            assertEquals(4L, DataChannelPayload.Binary(buf).wireByteCount)
            buf.readByte()
            assertEquals(3L, DataChannelPayload.Binary(buf).wireByteCount, "it is what REMAINS, read at the seam")
        } finally {
            buf.freeIfNeeded()
        }
    }

    private companion object {
        private const val BYTES_PER_CHAR_MAX = 4
    }
}

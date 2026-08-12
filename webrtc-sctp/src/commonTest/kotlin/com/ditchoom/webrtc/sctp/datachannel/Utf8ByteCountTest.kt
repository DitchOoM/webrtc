package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.managed
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * **`DataChannelPayload.Text.wireByteCount` must equal what the encoder actually writes, on every target.**
 *
 * This is the residue the whole send gate rests on. The gate refuses a message against the peer's
 * `a=max-message-size` using this count, while the bytes that reach the wire come from `writeString`, so
 * a disagreement is a silent hole in one direction or a spurious refusal in the other:
 *
 * - **under-count** → a message the gate passed is larger on the wire than the peer agreed to receive,
 *   which RFC 8831 §6.6 makes a MUST NOT. It surfaces as the peer aborting the association, with nothing
 *   local to point at.
 * - **over-count** → a message the peer would have taken is refused. Visible, and harmless.
 *
 * The expectation is measured **from the encoder itself** (`position()` after `writeString`) rather than
 * from a second hand-written counter, which would only assert that two implementations of the same
 * mistake agree. That distinction is not hypothetical: `webrtc-harness-endpoint`'s `utf8Len` charged
 * three bytes per `Char` and so counted six for a four-byte emoji, and a mirror-image counter in the test
 * would have agreed with it.
 *
 * The unpaired surrogates get a fixture of their own, because the premise the three-byte arm was written
 * under is **false on at least one target, and that was measured rather than assumed**. `utf8Len` charges
 * three under a comment reading "three is what a replacement character costs, which is what an encoder
 * substitutes" — but on the JVM `writeString` does not substitute, it throws `MalformedInputException`.
 * Nothing noticed because that corpus contains no unpaired surrogate. So what is asserted for those is
 * the property that holds on every target and is the one the gate actually needs: **never under-count**.
 */
class Utf8ByteCountTest {
    // The encoder's own answer, or null on a target that refuses to encode this text at all. Sized
    // generously: what is under test is what `writeString` WRITES, and constraining the buffer to the
    // count being verified would make the assertion circular.
    private fun encodedLength(text: String): Long? {
        val scratch = BufferFactory.managed().allocate(text.length * BYTES_PER_CHAR_MAX + 1, ByteOrder.BIG_ENDIAN)
        return try {
            scratch.writeString(text, Charset.UTF8)
            scratch.position().toLong()
        } catch (_: Throwable) {
            // Three exception types across four targets for a failed UTF-8 transcode (CLAUDE.md records
            // the decode side of exactly this), so the catch is on Throwable rather than anything named.
            null
        } finally {
            scratch.freeIfNeeded()
        }
    }

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
        for ((text, what) in corpus) {
            val encoded = encodedLength(text) ?: throw AssertionError("the encoder refused well-formed text: $what")
            assertEquals(
                encoded,
                DataChannelPayload.Text(text).wireByteCount,
                "wireByteCount disagrees with the encoder for $what",
            )
        }
    }

    /**
     * An unpaired surrogate is not encodable, and targets disagree about what to do with one — the JVM
     * throws, a `TextEncoder`-backed target substitutes U+FFFD. Both are covered by the same rule, and it
     * is the only rule the gate needs: the count may not be **smaller** than what reaches the wire.
     */
    @Test
    fun an_unpaired_surrogate_never_under_counts_whatever_the_encoder_does() {
        val corpus =
            listOf(
                "\uD83D" to "an unpaired high surrogate",
                "\uDE00" to "an unpaired low surrogate",
                "a\uD83Db" to "an unpaired high surrogate between ASCII",
                "\uD83D😀" to "an unpaired high surrogate followed by a real pair",
                "😀\uDE00" to "a real pair followed by an unpaired low surrogate",
            )
        for ((text, what) in corpus) {
            val counted = DataChannelPayload.Text(text).wireByteCount
            val encoded = encodedLength(text)
            if (encoded != null) {
                assertTrue(counted >= encoded, "wireByteCount $counted under-counts the encoder's $encoded for $what")
            }
        }
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

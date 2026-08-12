package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer

// Text↔buffer helpers for the harness peer. Deliberately array-free (no `encodeToByteArray()`): the
// standing-directive grep forbids primitive arrays in *Main/, and buffer's writeString/readString give
// us UTF-8 transcoding straight over the zero-copy buffer with no intermediate ByteArray.

/**
 * The UTF-8 byte length of [s] without allocating an array. Signaling payloads (SDP + `candidate:` lines,
 * ICE ufrag/pwd) are ASCII in practice, so this equals `s.length` there; the multi-byte arms keep it
 * correct for any text. Used to size the exact buffer and to write the length prefix before the bytes.
 *
 * The surrogate arm is load-bearing rather than defensive: [textBuffer] sets its buffer's limit from this
 * count, so an over-count publishes uninitialised bytes past what `writeString` actually wrote. An
 * astral-plane character (an emoji, say) is ONE code point encoding to four bytes but TWO `Char`s, so
 * counting each half as three said six — two bytes of whatever the allocator last held.
 */
internal fun utf8Len(s: String): Int {
    var n = 0
    var i = 0
    while (i < s.length) {
        val code = s[i].code
        val isHighSurrogate = code in 0xD800..0xDBFF
        val pairedWithLow = isHighSurrogate && i + 1 < s.length && s[i + 1].code in 0xDC00..0xDFFF
        when {
            code < 0x80 -> { n += 1; i += 1 }
            code < 0x800 -> { n += 2; i += 1 }
            // A well-formed pair is one code point in four bytes. An UNPAIRED surrogate is not encodable
            // at all; three is what a replacement character costs, which is what an encoder substitutes.
            pairedWithLow -> { n += 4; i += 2 }
            else -> { n += 3; i += 1 }
        }
    }
    return n
}

/** Allocate a read-ready [ReadBuffer] holding the UTF-8 bytes of [s] (never empty — min 1 byte). */
internal fun textBuffer(s: String): ReadBuffer {
    val n = utf8Len(s)
    val buf = BufferFactory.Default.allocate(maxOf(1, n), ByteOrder.BIG_ENDIAN)
    buf.writeString(s, Charset.UTF8)
    buf.resetForRead()
    buf.setLimit(n)
    return buf
}

/** Decode a [ReadBuffer]'s remaining bytes as UTF-8 text (does not mutate beyond a normal read). */
internal fun ReadBuffer.text(): String = readString(remaining(), Charset.UTF8)

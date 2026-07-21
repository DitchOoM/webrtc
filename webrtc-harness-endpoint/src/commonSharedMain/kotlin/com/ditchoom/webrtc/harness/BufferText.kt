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
 * correct for any BMP text. Used to size the exact buffer and to write the length prefix before the bytes.
 */
internal fun utf8Len(s: String): Int {
    var n = 0
    for (c in s) {
        val code = c.code
        n +=
            when {
                code < 0x80 -> 1
                code < 0x800 -> 2
                else -> 3
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

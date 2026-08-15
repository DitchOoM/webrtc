package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.Utf8
import com.ditchoom.buffer.readText
import com.ditchoom.buffer.utf8Size
import com.ditchoom.buffer.writeText

// Text↔buffer helpers for the harness peer. Deliberately array-free (no `encodeToByteArray()`): the
// standing-directive grep forbids primitive arrays in *Main/, and buffer's text policies transcode UTF-8
// straight over the zero-copy buffer with no intermediate ByteArray.
//
// The local `utf8Len` these used to size against is gone. It was one of five hand-rolled UTF-8 counters
// in this repo, and the only reason any of them existed was that buffer's own `utf8Length()` carried an
// unpaired-surrogate defect and no guarantee of agreeing with the encoder. Both halves landed in buffer
// 6.30.0 (DitchOoM/buffer#352 fixed the count, #353 made `utf8Size()` exactly what `Utf8.Lenient` writes),
// so a counter here could now only be a second implementation of a solved problem — and `utf8Len` had
// already been wrong once, charging three bytes per `Char` and so six for a four-byte emoji.

/**
 * Allocate a read-ready [ReadBuffer] holding the UTF-8 bytes of [s] (allocation is never zero-length —
 * min 1 byte — though an empty [s] still yields an empty read window).
 *
 * `resetForRead` is flip, so the window ends where the write ended. That is only the encoded text because
 * [utf8Size] and [Utf8.Lenient] are guaranteed equal; when the size came from a local counter this needed
 * a trailing `setLimit` to trim it, and an over-count would have published uninitialised bytes past the
 * text.
 */
internal fun textBuffer(s: String): ReadBuffer {
    val buf = BufferFactory.Default.allocate(maxOf(1, s.utf8Size()), ByteOrder.BIG_ENDIAN)
    buf.writeText(s, Utf8.Lenient)
    buf.resetForRead()
    return buf
}

/**
 * Decode a [ReadBuffer]'s remaining bytes as UTF-8 text (does not mutate beyond a normal read).
 *
 * Lenient: ill-formed bytes become U+FFFD rather than throwing, so a corrupted echo surfaces as a content
 * mismatch in the phase that asserts on it — which names the string it expected — instead of an exception
 * out of a decode three frames away from anything that knows what was being tested.
 */
internal fun ReadBuffer.text(): String = readText(remaining())

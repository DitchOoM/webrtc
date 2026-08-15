package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.buffer.freeIfNeeded

/**
 * One data-channel message, and which kind of message it is (RFC 8831 §6.6).
 *
 * WebRTC data channels carry **two** message types, distinguished on the wire by the SCTP Payload
 * Protocol Identifier: `WebRTC String` (51) and `WebRTC Binary` (53), each with an empty-message twin
 * (56 / 57) because SCTP cannot carry a zero-length DATA chunk. A browser peer surfaces that difference
 * directly — `event.data` is a `String` or an `ArrayBuffer` — so a stack that models only bytes cannot
 * send a string at all, and cannot tell a peer's `dc.send("hi")` from four binary bytes.
 *
 * ### Why not `ReadBuffer` + `isString: Boolean`
 * That pair is constructible in states the protocol does not have. It admits a "string" holding bytes
 * that are not valid UTF-8 — which RFC 8831 §6.6 requires string messages to be, and which a receiving
 * browser will reject *after* we have put it on the wire. Here [Text] holds a `CharSequence`: there is no
 * byte sequence to be invalid, so the illegal message cannot be built, let alone sent.
 *
 * ### Zero-copy is preserved where it matters
 * [Binary] carries the buffer itself and is never copied or decoded — that is the path this library
 * exists to keep fast. [Text] carries characters because a string message is going to be decoded by
 * somebody regardless; doing it once at the seam, with the stack's injected factory, beats handing every
 * caller an encoded buffer and the job of decoding it (and of deciding what to do when it will not
 * decode). The encode/decode happens at the SCTP send/receive seam, so no `BufferFactory` appears in
 * this type and callers never allocate to send a string.
 *
 * ### Ownership
 * A received [Binary] **transfers** its buffer to the collector, which owes it a release once it has
 * finished reading (ARCHITECTURE §11.7 — a received message is a reassembly copy, and on a pooled or
 * native-memory factory an unreleased one is memory out of circulation for the life of the process).
 * [Text] owns nothing. [release] exists so a collector can discharge that duty uniformly without
 * matching on the variant — the asymmetry is real, and making every call site remember it is how the
 * leaks in `TurnAllocation` happened.
 */
public sealed interface DataChannelPayload {
    /**
     * How many bytes this message occupies on the wire — the number RFC 8841 §6's `a=max-message-size`
     * bounds, and the one a caller may pre-check against `PeerMessageLimit` before sending.
     *
     * **Not `text.length`.** For a [Text] this is the UTF-8 encoded length, which for anything outside
     * ASCII is larger: `Text("é")` is one character and two bytes. A gate that measured characters would
     * pass a message that overruns the peer's ceiling, and RFC 8831 §6.6 makes exceeding it a MUST NOT —
     * so the one number a size check may use is this one.
     *
     * Derived, never stored beside the payload. A [Binary]'s buffer and a [Text]'s `CharSequence` are
     * both mutable after construction, so a cached count could describe a message that no longer exists;
     * the send seam re-reads it at the moment it matters.
     */
    public val wireByteCount: Long

    /**
     * A binary message — `WebRTC Binary` (PPID 53), or `WebRTC Binary Empty` (57) when [bytes] has no
     * remaining bytes. The buffer is the message: it is transmitted as-is and never decoded.
     */
    public class Binary(
        public val bytes: ReadBuffer,
    ) : DataChannelPayload {
        override val wireByteCount: Long get() = bytes.remaining().toLong()

        override fun release() {
            bytes.freeIfNeeded()
        }

        override fun toString(): String = "Binary(${bytes.remaining()} bytes)"
    }

    /**
     * A text message — `WebRTC String` (PPID 51), or `WebRTC String Empty` (56) when [text] is empty.
     * Encoded to UTF-8 once, at the send seam, using the stack's configured buffer factory.
     */
    public class Text(
        public val text: CharSequence,
    ) : DataChannelPayload {
        override val wireByteCount: Long get() = utf8ByteCount(text)

        /** Nothing to release: this variant never owns a buffer. */
        override fun release(): Unit = Unit

        override fun toString(): String = "Text(${text.length} chars)"
    }

    /**
     * Hand back whatever this payload owns. A no-op for [Text]; for a received [Binary] it releases the
     * reassembly buffer transferred to the collector. Safe to call on a payload you constructed to send —
     * but note that sending does not consume the payload, so a caller that allocated the buffer still
     * owns it either way.
     */
    public fun release()
}

/**
 * The UTF-8 byte length of [text], counted without allocating anything — no array, no encode, no
 * intermediate `String` (directive #1, and the whole point of knowing the size before paying for the
 * encoding).
 *
 * It must **agree with the encoder**, not merely approximate it, because it is what a send is refused
 * against: under-counting sends a message past a peer's stated ceiling (a MUST NOT), and over-counting
 * refuses one the peer would have taken. The surrogate arm is where that agreement is won or lost — an
 * astral-plane code point is ONE code point in FOUR bytes carried as TWO `Char`s, so charging three per
 * `Char` says six.
 *
 * An **unpaired** surrogate charges three, which is exactly `Utf8.Lenient`'s U+FFFD substitution cost, so
 * the agreement is now **equality on every target**. It used to be the weaker "never under-states any
 * target's answer", because the targets did not agree with each other: `writeString` threw on the JVM
 * where a `TextEncoder`-backed target substituted. The send path moved to `Utf8.Lenient`, which
 * substitutes everywhere, and `SctpDataChannelStack.encodeUtf8` sizes its allocation from this number —
 * so equality is what that buffer's exactness rests on, not just the RFC 8841 §6 gate.
 *
 * **This is deliberately not buffer's `CharSequence.utf8Size()`**, which is the same count and is what
 * every other site here uses. `utf8Size()` returns an `Int`; `wireByteCount` is a `Long` because the gate
 * compares it against a peer-advertised `maxMessageSize` that is a 32-bit unsigned quantity, and a
 * count that overflowed into a negative `Int` would pass a ceiling check it should fail. The width is the
 * whole reason this one survived the migration.
 *
 * `Utf8ByteCountTest` measures the expectation from the encoder itself rather than from a second
 * hand-written counter, which would only assert that two implementations of the same mistake agree.
 */
private fun utf8ByteCount(text: CharSequence): Long {
    var count = 0L
    var i = 0
    while (i < text.length) {
        val code = text[i].code
        val highSurrogate = code in HIGH_SURROGATE_FIRST..HIGH_SURROGATE_LAST
        val paired = highSurrogate && i + 1 < text.length && text[i + 1].code in LOW_SURROGATE_FIRST..LOW_SURROGATE_LAST
        when {
            code < ONE_BYTE_LIMIT -> {
                count += 1
                i += 1
            }
            code < TWO_BYTE_LIMIT -> {
                count += 2
                i += 1
            }
            paired -> {
                count += 4
                i += 2
            }
            else -> {
                count += 3
                i += 1
            }
        }
    }
    return count
}

private const val ONE_BYTE_LIMIT = 0x80
private const val TWO_BYTE_LIMIT = 0x800
private const val HIGH_SURROGATE_FIRST = 0xD800
private const val HIGH_SURROGATE_LAST = 0xDBFF
private const val LOW_SURROGATE_FIRST = 0xDC00
private const val LOW_SURROGATE_LAST = 0xDFFF

/**
 * Send one binary message — sugar for `send(DataChannelPayload.Binary(bytes))`, which is what the
 * overwhelming majority of sends are. The buffer is borrowed for the duration of the call and is still
 * the caller's afterwards (sending does not consume it).
 */
public suspend fun Connection<DataChannelPayload>.send(bytes: ReadBuffer): Unit = send(DataChannelPayload.Binary(bytes))

/**
 * Send one text message — sugar for `send(DataChannelPayload.Text(text))`. The UTF-8 encoding happens
 * once, inside the stack, with its injected buffer factory; nothing is allocated by the caller.
 *
 * This is the call that had no equivalent before: every message this library sent was `WebRTC Binary`,
 * so a browser peer's `onmessage` never once saw a `String`.
 */
public suspend fun Connection<DataChannelPayload>.send(text: CharSequence): Unit = send(DataChannelPayload.Text(text))

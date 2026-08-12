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
     * A binary message — `WebRTC Binary` (PPID 53), or `WebRTC Binary Empty` (57) when [bytes] has no
     * remaining bytes. The buffer is the message: it is transmitted as-is and never decoded.
     */
    public class Binary(
        public val bytes: ReadBuffer,
    ) : DataChannelPayload {
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

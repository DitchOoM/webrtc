package com.ditchoom.webrtc.dtls.wire

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer

/**
 * A complete (reassembled) DTLS handshake message (RFC 6347 §4.2.2). The 12-byte header carries the
 * DTLS reliability fields on top of TLS's `msg_type`+`length`:
 *
 * ```
 * struct {
 *   HandshakeType msg_type;        // 1
 *   uint24 length;                 // 3   total message length
 *   uint16 message_seq;            // 2
 *   uint24 fragment_offset;        // 3
 *   uint24 fragment_length;        // 3
 *   opaque body[fragment_length];
 * } Handshake;
 * ```
 *
 * A [HandshakeMessage] is always the *whole* message ([body] spans the full `length`); fragmentation is
 * a wire concern handled by [HandshakeFragment] + [HandshakeReassembler] on the way in, and by
 * `encodeInto` (which emits a single unfragmented fragment) on the way out.
 *
 * **Transcript gotcha (spike-hardened):** the DTLS Finished/`verify_data` transcript hashes the FULL
 * 12-byte handshake header with the fragment fields **normalized** — `fragment_offset = 0`,
 * `fragment_length = length` — NOT the TLS 4-byte header. [transcriptInto] emits exactly that form.
 */
internal class HandshakeMessage(
    val msgType: HandshakeType,
    val messageSeq: Int,
    val body: ReadBuffer,
) {
    val length: Int get() = body.remaining()

    /** On-wire size when emitted as one unfragmented fragment. */
    val wireSize: Int get() = HEADER_BYTES + length

    /** Emits the message as a single unfragmented fragment (offset 0, fragment_length = length). */
    fun encodeInto(dest: WriteBuffer) {
        writeHeader(dest, msgType, length, messageSeq, fragmentOffset = 0, fragmentLength = length)
        dest.writeView(body)
    }

    /**
     * Emits the transcript form: the normalized 12-byte header (fragment_offset 0, fragment_length =
     * length) followed by the body. This is what feeds the running transcript hash and the PRF, exactly
     * as a reassembled message contributes regardless of how it was fragmented on the wire.
     */
    fun transcriptInto(dest: WriteBuffer) = encodeInto(dest)

    companion object {
        const val HEADER_BYTES = 12

        private fun writeHeader(
            dest: WriteBuffer,
            msgType: HandshakeType,
            length: Int,
            messageSeq: Int,
            fragmentOffset: Int,
            fragmentLength: Int,
        ) {
            dest.writeByte((msgType.value and 0xFF).toByte())
            dest.writeU24(length)
            dest.writeByte(((messageSeq ushr 8) and 0xFF).toByte())
            dest.writeByte((messageSeq and 0xFF).toByte())
            dest.writeU24(fragmentOffset)
            dest.writeU24(fragmentLength)
        }
    }
}

/**
 * A single handshake fragment as it appears in a record's fragment region — one message may arrive in
 * several of these (a 409-byte Certificate observed in 95-byte fragments during the spike). Carries the
 * parsed header fields plus a zero-copy view of the [fragmentBody] bytes actually present.
 */
internal class HandshakeFragment(
    val msgType: HandshakeType,
    val length: Int,
    val messageSeq: Int,
    val fragmentOffset: Int,
    val fragmentLength: Int,
    val fragmentBody: ReadBuffer,
) {
    companion object {
        /**
         * Walks every handshake fragment concatenated in [region] (a decrypted handshake record may hold
         * several). Returns null if any fragment header/body runs past the region (malformed → dropped by
         * the caller). Never throws (T0).
         */
        fun decodeAll(region: ReadBuffer): List<HandshakeFragment>? {
            val start = region.position()
            val end = region.limit()
            val out = ArrayList<HandshakeFragment>(2)
            var pos = start
            while (pos < end) {
                if (pos + HandshakeMessage.HEADER_BYTES > end) return null
                val length = region.u24(pos + 1)
                val messageSeq = region.u16(pos + 4)
                val fragmentOffset = region.u24(pos + 6)
                val fragmentLength = region.u24(pos + 9)
                val bodyStart = pos + HandshakeMessage.HEADER_BYTES
                val bodyEnd = bodyStart + fragmentLength
                if (bodyEnd > end) return null
                if (fragmentOffset + fragmentLength > length) return null // fragment escapes the message
                out +=
                    HandshakeFragment(
                        msgType = HandshakeType(region.u8(pos)),
                        length = length,
                        messageSeq = messageSeq,
                        fragmentOffset = fragmentOffset,
                        fragmentLength = fragmentLength,
                        fragmentBody = region.sliceOf(bodyStart, bodyEnd),
                    )
                pos = bodyEnd
            }
            return out
        }
    }
}

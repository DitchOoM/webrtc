package com.ditchoom.webrtc.dtls.wire

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer

/**
 * One DTLS record (RFC 6347 §4.1 `DTLSPlaintext` / `DTLSCiphertext`). The 13-byte header is common to
 * plaintext and AEAD-protected records; [fragment] is either cleartext (handshake before the cipher is
 * active) or the AEAD payload (`explicit_nonce ‖ ciphertext ‖ tag`). The record-protection layer
 * transforms [fragment]; this type only frames it. A datagram may coalesce several records back-to-back
 * ([decodeAll]).
 *
 * ```
 * struct {
 *   ContentType type;              // 1
 *   ProtocolVersion version;       // 2  (DTLS 1.2 = 0xFEFD)
 *   uint16 epoch;                  // 2
 *   uint48 sequence_number;        // 6
 *   uint16 length;                 // 2
 *   opaque fragment[length];
 * } DTLSPlaintext;
 * ```
 */
internal class DtlsRecord(
    val contentType: ContentType,
    val version: ProtocolVersion,
    val epoch: Int,
    val sequenceNumber: Long,
    val fragment: ReadBuffer,
) {
    /** Total on-wire size of this record: the fixed header plus the fragment. */
    val wireSize: Int get() = HEADER_BYTES + fragment.remaining()

    /** Writes the 13-byte header followed by the fragment bytes (position-preserving on [fragment]). */
    fun encodeInto(dest: WriteBuffer) {
        dest.writeByte(contentType.value.toByte())
        dest.writeByte(((version.value ushr 8) and 0xFF).toByte())
        dest.writeByte((version.value and 0xFF).toByte())
        dest.writeByte(((epoch ushr 8) and 0xFF).toByte())
        dest.writeByte((epoch and 0xFF).toByte())
        dest.writeU48(sequenceNumber)
        val len = fragment.remaining()
        dest.writeByte(((len ushr 8) and 0xFF).toByte())
        dest.writeByte((len and 0xFF).toByte())
        dest.writeView(fragment)
    }

    companion object {
        const val HEADER_BYTES = 13

        /** The high 16 bits of the 48-bit record sequence carry the epoch in DTLS 1.2's per-epoch space. */
        private const val CONTENT_TYPE_OFFSET = 0
        private const val VERSION_OFFSET = 1
        private const val EPOCH_OFFSET = 3
        private const val SEQUENCE_OFFSET = 5
        private const val LENGTH_OFFSET = 11

        /**
         * Walks every DTLS record coalesced in [datagram] (RFC 6347 §4.1.1 permits several records per
         * datagram). Returns the records as zero-copy views over [datagram], or null if the framing is
         * malformed (a header or fragment that runs past the datagram) — the framing layer maps null to a
         * silent drop (RFC 6347: an unparseable datagram is discarded, never fatal). Never throws (T0).
         *
         * A record whose [ContentType] this codec does not recognise is still returned verbatim so the
         * caller can drop just that record; a truncated header at the tail ends the walk cleanly.
         */
        fun decodeAll(datagram: ReadBuffer): List<DtlsRecord>? {
            val start = datagram.position()
            val end = datagram.limit()
            val out = ArrayList<DtlsRecord>(2)
            var pos = start
            while (pos < end) {
                if (pos + HEADER_BYTES > end) return null // a partial header is malformed framing
                val length = datagram.u16(pos + LENGTH_OFFSET)
                val bodyStart = pos + HEADER_BYTES
                val bodyEnd = bodyStart + length
                if (bodyEnd > end) return null // fragment runs past the datagram
                out +=
                    DtlsRecord(
                        contentType = ContentType(datagram.u8(pos + CONTENT_TYPE_OFFSET)),
                        version = ProtocolVersion(datagram.u16(pos + VERSION_OFFSET)),
                        epoch = datagram.u16(pos + EPOCH_OFFSET),
                        sequenceNumber = datagram.u48(pos + SEQUENCE_OFFSET),
                        fragment = datagram.sliceOf(bodyStart, bodyEnd),
                    )
                pos = bodyEnd
            }
            return out
        }
    }
}

/**
 * The per-epoch 48-bit record sequence number, split as DTLS lays it out: the high 16 bits are the
 * `epoch`, the low 48 bits count up per record within that epoch. Kept as a plain counter helper so the
 * record layer never open-codes the width. The value is monotonic per epoch and resets when the epoch
 * advances (a ChangeCipherSpec).
 */
internal class RecordSequence {
    var epoch: Int = 0
        private set
    private var next: Long = 0

    /** Returns the next sequence number for the current epoch and advances the counter. */
    fun next(): Long = next++

    /** Advances to the next epoch (a ChangeCipherSpec), resetting the per-epoch sequence to zero. */
    fun advanceEpoch() {
        epoch++
        next = 0
    }
}

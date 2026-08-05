package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import com.ditchoom.buffer.codec.DecodeContext
import com.ditchoom.buffer.codec.EncodeContext
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.SctpDecodeResult.Reject
import com.ditchoom.webrtc.sctp.SctpDecodeResult.Success

/**
 * A decoded or hand-built SCTP packet (RFC 4960 §3): a 12-byte [SctpCommonHeader] followed by one or
 * more [chunks]. The common header rides the KSP-generated [SctpCommonHeaderCodec]; the chunk framing
 * (type, flags, length, pad to a 4-byte boundary) and the sub-TLV parameter/cause walks are
 * hand-written, because SCTP's "length counts the 4-byte header + value but not the trailing pad" and
 * the nested TLVs are outside what the declarative codec expresses.
 *
 * Decoding is zero-copy: variable regions inside chunks (user data, cookies, parameter/cause values)
 * are slices over [source], so a decoded packet must not outlive that datagram's scope.
 * [verifyChecksum] reads those same bytes in place. Build outgoing packets with [SctpPacketBuilder].
 */
public class SctpPacket internal constructor(
    public val header: SctpCommonHeader,
    public val chunks: List<SctpChunk>,
    private val source: ReadBuffer?,
    private val sourceStart: Int,
    private val packetLength: Int,
    // The per-chunk spans `decode` sliced off the datagram. Held only so [release] can give them back:
    // each chunk's own fields are slices of these, but `TrackedSlice` re-parents to the ROOT chunk, so
    // these are independent references against the datagram rather than a chain, and dropping them
    // pinned it just as surely as dropping the chunks' own views.
    private val chunkSpans: List<ReadBuffer> = emptyList(),
) {
    /**
     * Give back every buffer reference **decoding this packet took** — and nothing else. Call it once the
     * last reader is done, before the datagram's own owner releases it.
     *
     * It does **not** free the datagram. [decode] is zero-copy: every chunk's variable region is a slice
     * over the received buffer, and on a pooled one `slice()` is `addRef()`. A packet bundling N chunks
     * therefore takes several references against the chunk while the datagram's owner returns exactly
     * **one**, under the last-reader rule. Without this the arithmetic never closes and the memory never
     * returns to the pool, however disciplined that owner is — measured at 23 chunks created and 0
     * returned across a full session, while every buffer-level leak assertion passed.
     *
     * Safe on every configuration: releasing a borrow returns only the reference that borrow took. On a
     * pooled parent it decrements; on a plain native buffer `NativeBufferSlice.freeNativeMemory()` is a
     * documented no-op, so a non-pooled path pays nothing. The datagram is still freed exactly once, by
     * whoever owns it.
     *
     * **The rule for callers:** no borrow may outlive this. The association reads chunks into value types
     * and copies out the two things that must survive (`ReassemblyQueue`'s user data and the INIT-ACK
     * cookie, both via `copyOf`), so nothing it keeps points back into the packet.
     */
    public fun release() {
        for (chunk in chunks) chunk.releaseViews()
        for (span in chunkSpans) span.freeIfNeeded()
    }

    public val sourcePort: UShort get() = header.sourcePort
    public val destinationPort: UShort get() = header.destinationPort
    public val verificationTag: VerificationTag get() = header.verificationTag

    /** The first chunk of [type], or null if absent. */
    public fun firstOrNull(type: SctpChunkType): SctpChunk? = chunks.firstOrNull { it.type == type }

    /**
     * Recomputes the CRC32c (RFC 4960 §6.8) over the decoded packet with the checksum field treated as
     * zero, and compares it to the value on the wire. Returns false if this packet was not decoded from
     * a buffer.
     *
     * SCTP stores the checksum as the **little-endian** encoding of the [Crc32c.of] value (RFC 4960
     * Appendix B), while [SctpCommonHeader.checksum] is the big-endian-read word — so the stored value
     * equals the byte-reversed CRC32c. The four checksum bytes (header offset 8..11) are skipped via a
     * two-slice feed so the datagram is never mutated.
     */
    public fun verifyChecksum(): Boolean {
        val src = source ?: return false
        return computeChecksum(src, sourceStart, packetLength) == reverseBytes(header.checksum)
    }

    /**
     * Serializes this packet (common header + chunks, each chunk padded to a 4-byte boundary) into a
     * freshly allocated read-ready buffer, with the CRC32c checksum computed and placed. A decoded
     * packet re-encodes byte-for-byte (given the canonical zero padding every conforming sender emits).
     */
    public fun encode(factory: BufferFactory = BufferFactory.managed()): PlatformBuffer {
        val chunkBytes = chunks.sumOf { paddedLength(TLV_HEADER_BYTES + it.valueSize) }
        val dest = factory.allocate(SctpCommonHeader.SIZE_BYTES + chunkBytes, ByteOrder.BIG_ENDIAN)
        // Encode with a zero checksum first, then compute CRC32c over the whole buffer and patch it in.
        writeInto(dest, header.copy(checksum = 0u), chunks)
        dest.resetForRead()
        val crc = computeChecksum(dest, 0, SctpCommonHeader.SIZE_BYTES + chunkBytes)
        // Store little-endian: byte-reversed relative to the big-endian-read checksum word.
        dest.set(CHECKSUM_OFFSET, reverseBytes(crc).toInt())
        dest.position(0)
        return dest
    }

    public companion object {
        internal const val CHECKSUM_OFFSET = 8 // byte offset of the checksum field within the common header

        /**
         * Parses one SCTP packet from [source] (starting at its current position). Never throws on a
         * malformed datagram — every failure is a typed [Reject]. On success the variable chunk regions
         * are zero-copy slices over [source]. The checksum is **not** verified here (call
         * [verifyChecksum]); a codec decode is independent of key/tag validation.
         */
        public fun decode(source: ReadBuffer): SctpDecodeResult {
            val start = source.position()
            val available = source.limit() - start
            if (available < SctpCommonHeader.SIZE_BYTES) return Reject(SctpRejectReason.ShorterThanCommonHeader)

            val header = SctpCommonHeaderCodec.decode(source, DecodeContext.Empty)
            // The generated codec advanced position by 12; walk chunks from there using absolute reads.
            val chunks = mutableListOf<SctpChunk>()
            val spans = mutableListOf<ReadBuffer>()
            var pos = start + SctpCommonHeader.SIZE_BYTES
            val end = source.limit()

            // A reject part-way through the walk still owes every view built so far. Decoding is
            // zero-copy, so those are references against the datagram on a pooled buffer (see [release]),
            // and a Reject hands the caller no object to release them through — so abandoning them pinned
            // the chunk permanently. That is peer-controlled input: a stream of malformed SCTP would have
            // exhausted the pool without ever completing a parse.
            fun reject(reason: SctpRejectReason): Reject {
                for (chunk in chunks) chunk.releaseViews()
                for (span in spans) span.freeIfNeeded()
                return Reject(reason)
            }
            while (pos < end) {
                if (pos + TLV_HEADER_BYTES > end) return reject(SctpRejectReason.MalformedChunkHeader(pos))
                val chunkType = SctpChunkType(source.u8(pos).toUByte())
                val flags = source.u8(pos + 1).toUByte()
                val declaredLength = source.u16(pos + 2)
                if (declaredLength < TLV_HEADER_BYTES) return reject(SctpRejectReason.MalformedChunkHeader(pos))
                val valueEnd = pos + declaredLength
                if (valueEnd > end) {
                    return reject(SctpRejectReason.ChunkLengthBeyondPacket(pos, declaredLength, end - pos))
                }
                val valueView = source.sliceOf(pos + TLV_HEADER_BYTES, valueEnd)
                spans += valueView
                val chunk =
                    SctpChunk.decodeBody(chunkType, flags, valueView)
                        ?: return reject(SctpRejectReason.MalformedChunkBody(pos, chunkType))
                chunks += chunk
                // The next chunk starts at the 4-byte-aligned end of this one (RFC 4960 §3.2 padding);
                // stop cleanly if only < 4 pad bytes remain.
                pos += paddedLength(declaredLength)
            }
            if (chunks.isEmpty()) return reject(SctpRejectReason.NoChunks)

            // The consumed extent from the packet start — what verify/re-encode cover.
            val consumed = pos.coerceAtMost(end) - start
            return Success(SctpPacket(header, chunks, source, start, consumed, spans))
        }

        /** Writes [header] then each chunk (type, flags, length, value, zero-padding to a 4-byte boundary). */
        internal fun writeInto(
            dest: WriteBuffer,
            header: SctpCommonHeader,
            chunks: List<SctpChunk>,
        ) {
            SctpCommonHeaderCodec.encode(dest, header, EncodeContext.Empty)
            for (chunk in chunks) {
                dest.writeByte(chunk.type.value.toByte())
                dest.writeByte(chunk.flagsByte.toByte())
                dest.writeUShort((TLV_HEADER_BYTES + chunk.valueSize).toUShort())
                chunk.writeValue(dest)
                repeat(paddedLength(chunk.valueSize) - chunk.valueSize) { dest.writeByte(0) }
            }
        }

        /**
         * CRC32c over `[start, start + length)` of [buffer] with the 4-byte checksum field (at
         * `start + 8`) treated as zero, fed as two spans so the datagram is never mutated (RFC 4960 §6.8).
         */
        private fun computeChecksum(
            buffer: ReadBuffer,
            start: Int,
            length: Int,
        ): UInt {
            // Fold the bytes before the checksum field, then four zero bytes in its place, then the
            // bytes after — so the datagram is never mutated (RFC 4960 §6.8).
            val before = Crc32c.update(Crc32c.INIT, buffer, start, CHECKSUM_OFFSET)
            val withZeros = Crc32c.update(before, ZERO_CHECKSUM, 0, CHECKSUM_FIELD_BYTES)
            val afterStart = start + CHECKSUM_OFFSET + CHECKSUM_FIELD_BYTES
            val afterLen = length - CHECKSUM_OFFSET - CHECKSUM_FIELD_BYTES
            return Crc32c.finalize(Crc32c.update(withZeros, buffer, afterStart, afterLen))
        }

        private const val CHECKSUM_FIELD_BYTES = 4
        private val ZERO_CHECKSUM: ReadBuffer =
            BufferFactory.managed().allocate(CHECKSUM_FIELD_BYTES, ByteOrder.BIG_ENDIAN).apply {
                repeat(CHECKSUM_FIELD_BYTES) { writeByte(0) }
                resetForRead()
            }

        /** Reverses the four bytes of a 32-bit word (the SCTP checksum little-endian ↔ CRC32c value). */
        internal fun reverseBytes(v: UInt): UInt {
            val x = v.toInt()
            val r =
                ((x and 0xFF) shl 24) or
                    ((x ushr 8 and 0xFF) shl 16) or
                    ((x ushr 16 and 0xFF) shl 8) or
                    (x ushr 24 and 0xFF)
            return r.toUInt()
        }
    }
}

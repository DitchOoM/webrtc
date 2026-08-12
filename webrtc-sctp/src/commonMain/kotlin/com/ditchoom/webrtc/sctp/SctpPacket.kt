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
 * are slices over the datagram, so a decoded packet must not outlive that datagram's scope.
 * [validateChecksum] reads those same bytes in place, via the span [PacketOrigin.Decoded] retains. Build
 * outgoing packets with [SctpPacketBuilder].
 */
public class SctpPacket internal constructor(
    public val header: SctpCommonHeader,
    public val chunks: List<SctpChunk>,
    private val origin: PacketOrigin,
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
     * zero, compares it to the value on the wire, and says **which** of the outcomes happened.
     *
     * SCTP stores the checksum as the **little-endian** encoding of the [Crc32c.of] value (RFC 4960
     * Appendix B), while [SctpCommonHeader.checksum] is the big-endian-read word — so the stored value
     * equals the byte-reversed CRC32c. The four checksum bytes (header offset 8..11) are skipped via a
     * two-slice feed so the datagram is never mutated.
     *
     * Requires a correct CRC32c. This overload is what a caller that has negotiated nothing wants, and
     * keeping it is what makes RFC 9653 opt-in at every existing call site rather than at a default.
     */
    public fun validateChecksum(): ChecksumVerdict = validateChecksum(ZeroChecksumAcceptance.RequireCrc32c)

    /**
     * [validateChecksum] under an RFC 9653 §5.3 acceptance: a packet whose checksum field is zero is
     * [ChecksumVerdict.AcceptedZero] when — and only when — *we* advertised an alternate error detection
     * method to this peer.
     *
     * **[acceptance] is the receive direction and nothing else.** Passing what the peer permitted us to
     * send would accept an unverifiable packet from an endpoint we never made that promise to, which is
     * why [ZeroChecksumAcceptance] and [OutboundChecksum] share no supertype: the mistake does not
     * compile.
     *
     * Under an [ZeroChecksumAcceptance.Advertised] acceptance the zero field is checked **first** and the
     * CRC32c is then not computed at all. That is the point of the extension (RFC 9653 §3: the
     * computation "consumes computational resources without providing any benefit"), and it costs only
     * the label: a packet whose true CRC32c happens to be zero is reported [ChecksumVerdict.AcceptedZero]
     * rather than [ChecksumVerdict.Verified]. RFC 9653 §3 states outright that a receiver cannot tell
     * those two apart and that the ambiguity is irrelevant to an endpoint willing to use the alternate
     * method — so the verdict is naming a real indistinguishability rather than losing information.
     */
    public fun validateChecksum(acceptance: ZeroChecksumAcceptance): ChecksumVerdict =
        when (origin) {
            PacketOrigin.Built -> ChecksumVerdict.NotFromWire
            is PacketOrigin.Decoded ->
                when (acceptance) {
                    ZeroChecksumAcceptance.RequireCrc32c -> recomputedVerdict(origin)
                    is ZeroChecksumAcceptance.Advertised ->
                        if (header.checksum == 0u) ChecksumVerdict.AcceptedZero else recomputedVerdict(origin)
                }
        }

    private fun recomputedVerdict(origin: PacketOrigin.Decoded): ChecksumVerdict =
        if (computeChecksum(origin.buffer, origin.start, origin.length) == reverseBytes(header.checksum)) {
            ChecksumVerdict.Verified
        } else {
            ChecksumVerdict.Mismatch
        }

    /**
     * The strictest requirement any chunk in this packet imposes (RFC 9653 §5.2) — the packet-level join
     * of [SctpChunk.checksumRequirement].
     *
     * One demanding chunk decides for the whole packet, because the checksum covers all of them. That is
     * what makes bundling safe: a DATA chunk riding beside a COOKIE ECHO is checksummed, without the
     * bundling site having to know why.
     */
    internal val checksumRequirement: ChunkChecksumRequirement
        get() =
            if (chunks.any { it.checksumRequirement == ChunkChecksumRequirement.Crc32cRequired }) {
                ChunkChecksumRequirement.Crc32cRequired
            } else {
                ChunkChecksumRequirement.EitherPermitted
            }

    /**
     * [validateChecksum] projected to "may this packet be processed" — the question every current caller
     * was asking, kept so none of them have to change and so the common case stays one word at the call
     * site.
     *
     * It is [ChecksumVerdict.accepted] rather than `== Verified` on purpose. Once RFC 9653 lands, a peer
     * that negotiated zero-checksum sends a legitimately unverifiable packet, and a Boolean written as an
     * equality against one variant would start silently discarding exactly the traffic that feature
     * exists to permit — while still looking correct.
     */
    public fun verifyChecksum(): Boolean = validateChecksum().accepted

    /**
     * Serializes this packet (common header + chunks, each chunk padded to a 4-byte boundary) into a
     * freshly allocated read-ready buffer, with the CRC32c checksum computed and placed. A decoded
     * packet re-encodes byte-for-byte (given the canonical zero padding every conforming sender emits).
     */
    public fun encode(factory: BufferFactory = BufferFactory.managed()): PlatformBuffer = encode(factory, OutboundChecksum.Crc32c)

    /**
     * [encode] under an RFC 9653 §5.2 permission: the checksum field is left at zero when [outbound]
     * permits it **and** no chunk in this packet demands otherwise ([checksumRequirement]).
     *
     * Both halves are load-bearing and neither implies the other. The peer's permission does not reach an
     * INIT, a COOKIE ECHO, a reflected ABORT or an unrecognized chunk; and no chunk's own permissiveness
     * grants anything the peer did not. When the zero stands, the CRC32c is not computed at all — the
     * serializer already wrote a zero into that field, so the saving is the whole computation rather than
     * a branch around a store.
     *
     * Passing a [ZeroChecksumAcceptance] here does not compile, which is the point: emitting a zero
     * checksum because *we* said we would accept one is the per-direction mistake RFC 9653 invites, and
     * it produces packets a peer that never agreed silently discards.
     */
    public fun encode(
        factory: BufferFactory,
        outbound: OutboundChecksum,
    ): PlatformBuffer {
        val chunkBytes = chunks.sumOf { paddedLength(TLV_HEADER_BYTES + it.valueSize) }
        val dest = factory.allocate(SctpCommonHeader.SIZE_BYTES + chunkBytes, ByteOrder.BIG_ENDIAN)
        // Encode with a zero checksum first, then compute CRC32c over the whole buffer and patch it in.
        writeInto(dest, header.copy(checksum = 0u), chunks)
        dest.resetForRead()
        val zeroStands =
            when (outbound) {
                OutboundChecksum.Crc32c -> false
                is OutboundChecksum.ZeroWherePermitted ->
                    when (checksumRequirement) {
                        ChunkChecksumRequirement.Crc32cRequired -> false
                        ChunkChecksumRequirement.EitherPermitted -> true
                    }
            }
        if (!zeroStands) {
            val crc = computeChecksum(dest, 0, SctpCommonHeader.SIZE_BYTES + chunkBytes)
            // Store little-endian: byte-reversed relative to the big-endian-read checksum word.
            dest.set(CHECKSUM_OFFSET, reverseBytes(crc).toInt())
        }
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
            return Success(SctpPacket(header, chunks, PacketOrigin.Decoded(source, start, consumed), spans))
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

package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import kotlin.jvm.JvmInline

/**
 * The flags octet of a DATA chunk (RFC 4960 §3.3.1) — the I/U/B/E bits wrapped so no call site reads a
 * bare `flags and 0x04`. The whole `UByte` is preserved (reserved high bits included), so a decoded
 * chunk re-encodes byte-for-byte.
 */
@JvmInline
public value class DataChunkFlags(
    public val raw: UByte,
) {
    /** `E` (bit 0) — this is the last fragment of a user message (RFC 4960 §3.3.1). */
    public val ending: Boolean get() = raw.toInt() and E_BIT != 0

    /** `B` (bit 1) — this is the first fragment of a user message. */
    public val beginning: Boolean get() = raw.toInt() and B_BIT != 0

    /** `U` (bit 2) — unordered delivery: the Stream Sequence Number is ignored. */
    public val unordered: Boolean get() = raw.toInt() and U_BIT != 0

    /** `I` (bit 3) — the SACK-Immediately hint (RFC 7053): the receiver should SACK without delay. */
    public val immediate: Boolean get() = raw.toInt() and I_BIT != 0

    /** True when both `B` and `E` are set — the chunk carries a complete, unfragmented user message. */
    public val unfragmented: Boolean get() = beginning && ending

    public companion object {
        private const val E_BIT = 0x01
        private const val B_BIT = 0x02
        private const val U_BIT = 0x04
        private const val I_BIT = 0x08

        /** Builds the flags octet from the four meaningful bits (reserved bits are zero). */
        public fun of(
            beginning: Boolean,
            ending: Boolean,
            unordered: Boolean = false,
            immediate: Boolean = false,
        ): DataChunkFlags {
            var v = 0
            if (ending) v = v or E_BIT
            if (beginning) v = v or B_BIT
            if (unordered) v = v or U_BIT
            if (immediate) v = v or I_BIT
            return DataChunkFlags(v.toUByte())
        }
    }
}

/** One Gap Ack Block of a SACK (RFC 4960 §3.3.4): TSN offsets relative to the Cumulative TSN Ack. */
public data class GapAckBlock(
    public val start: UShort,
    public val end: UShort,
)

/** One `(stream, ssn)` entry of a FORWARD-TSN chunk (RFC 3758 §3.2). */
public data class ForwardTsnStream(
    public val streamId: StreamId,
    public val streamSequenceNumber: StreamSequenceNumber,
)

/**
 * An SCTP chunk (RFC 4960 §3.2) — a **sealed hierarchy**, so a receiver's `when(chunk)` is exhaustive
 * with no `else` and adding a chunk kind is a compile error at every call site until handled. This is
 * where behavioral dispatch lives (the registry-point value classes — [SctpChunkType], [ParameterType],
 * [ErrorCauseCode] — are the open leaf identifiers beneath it).
 *
 * The TLV framing (1-byte type, 1-byte flags, 2-byte length that counts the 4-byte header + value but
 * not the pad to a 4-byte boundary) is owned by [SctpPacket]; a variant owns only its value. Variable
 * regions (user data, cookies, parameter/cause values) are **zero-copy views** over the datagram
 * (RFC §6), so a decoded chunk must not outlive that buffer's scope. Decoded chunks re-encode
 * byte-for-byte; reserved flag bits on the flagless chunks are canonicalized to zero (RFC 4960: a
 * sender sets them to 0).
 */
public sealed interface SctpChunk {
    /** The chunk type octet (RFC 4960 §3.2). */
    public val type: SctpChunkType

    /** The chunk flags octet as it goes on the wire. */
    public val flagsByte: UByte

    /** Byte length of the value region (the chunk length minus the 4-byte header, pad excluded). */
    public val valueSize: Int

    /** Writes exactly [valueSize] value bytes (no type/flags/length/padding — [SctpPacket] owns those). */
    public fun writeValue(dest: WriteBuffer)

    /** DATA (type 0, RFC 4960 §3.3.1) — a fragment of a user message with its ordering + PPID. */
    public data class Data(
        public val flags: DataChunkFlags,
        public val tsn: Tsn,
        public val streamId: StreamId,
        public val streamSequenceNumber: StreamSequenceNumber,
        public val payloadProtocolId: PayloadProtocolId,
        public val userData: ReadBuffer,
    ) : SctpChunk {
        override val type: SctpChunkType get() = SctpChunkType.Data
        override val flagsByte: UByte get() = flags.raw
        override val valueSize: Int get() = DATA_FIXED_BYTES + userData.remaining()

        override fun writeValue(dest: WriteBuffer) {
            dest.writeUInt(tsn.value)
            dest.writeUShort(streamId.value.toUShort())
            dest.writeUShort(streamSequenceNumber.value)
            dest.writeUInt(payloadProtocolId.value)
            writeView(dest, userData)
        }
    }

    /** INIT (type 1, RFC 4960 §3.3.2) — the first handshake chunk with its variable parameters. */
    public data class Init(
        public val initiateTag: VerificationTag,
        public val advertisedReceiverWindow: UInt,
        public val outboundStreams: UShort,
        public val inboundStreams: UShort,
        public val initialTsn: Tsn,
        public val parameters: List<SctpParameter>,
    ) : SctpChunk {
        override val type: SctpChunkType get() = SctpChunkType.Init
        override val flagsByte: UByte get() = 0u
        override val valueSize: Int get() = INIT_FIXED_BYTES + tlvWireSize(parameters.map { it.paddedValue.remaining() })

        override fun writeValue(dest: WriteBuffer) =
            writeInitFixedAndParams(dest, initiateTag, advertisedReceiverWindow, outboundStreams, inboundStreams, initialTsn, parameters)

        /** Whether this INIT advertised Forward-TSN support (RFC 3758 §3.1). */
        public fun supportsForwardTsn(): Boolean = parameters.any { it.type == ParameterType.ForwardTsnSupported }
    }

    /** INIT-ACK (type 2, RFC 4960 §3.3.3) — same body shape as INIT; carries the State Cookie parameter. */
    public data class InitAck(
        public val initiateTag: VerificationTag,
        public val advertisedReceiverWindow: UInt,
        public val outboundStreams: UShort,
        public val inboundStreams: UShort,
        public val initialTsn: Tsn,
        public val parameters: List<SctpParameter>,
    ) : SctpChunk {
        override val type: SctpChunkType get() = SctpChunkType.InitAck
        override val flagsByte: UByte get() = 0u
        override val valueSize: Int get() = INIT_FIXED_BYTES + tlvWireSize(parameters.map { it.paddedValue.remaining() })

        override fun writeValue(dest: WriteBuffer) =
            writeInitFixedAndParams(dest, initiateTag, advertisedReceiverWindow, outboundStreams, inboundStreams, initialTsn, parameters)

        /** The State Cookie parameter (RFC 4960 §3.3.3.1) an INIT-ACK must carry, or null if absent. */
        public fun stateCookie(): SctpParameter? = parameters.firstOrNull { it.type == ParameterType.StateCookie }
    }

    /** SACK (type 3, RFC 4960 §3.3.4) — cumulative ack + gap-ack blocks + duplicate TSNs. */
    public data class Sack(
        public val cumulativeTsnAck: Tsn,
        public val advertisedReceiverWindow: UInt,
        public val gapAckBlocks: List<GapAckBlock>,
        public val duplicateTsns: List<Tsn>,
    ) : SctpChunk {
        override val type: SctpChunkType get() = SctpChunkType.Sack
        override val flagsByte: UByte get() = 0u
        override val valueSize: Int get() = SACK_FIXED_BYTES + gapAckBlocks.size * GAP_BLOCK_BYTES + duplicateTsns.size * TSN_BYTES

        override fun writeValue(dest: WriteBuffer) {
            dest.writeUInt(cumulativeTsnAck.value)
            dest.writeUInt(advertisedReceiverWindow)
            dest.writeUShort(gapAckBlocks.size.toUShort())
            dest.writeUShort(duplicateTsns.size.toUShort())
            for (g in gapAckBlocks) {
                dest.writeUShort(g.start)
                dest.writeUShort(g.end)
            }
            for (d in duplicateTsns) dest.writeUInt(d.value)
        }
    }

    /** HEARTBEAT (type 4, RFC 4960 §3.3.5) — carries the opaque Heartbeat Info parameter to echo. */
    public data class Heartbeat(
        public val info: SctpParameter,
    ) : SctpChunk {
        override val type: SctpChunkType get() = SctpChunkType.Heartbeat
        override val flagsByte: UByte get() = 0u
        override val valueSize: Int get() = TLV_HEADER_BYTES + info.paddedValue.remaining()

        override fun writeValue(dest: WriteBuffer) = writeParameter(dest, info)
    }

    /** HEARTBEAT-ACK (type 5, RFC 4960 §3.3.6) — echoes the HEARTBEAT's Heartbeat Info parameter. */
    public data class HeartbeatAck(
        public val info: SctpParameter,
    ) : SctpChunk {
        override val type: SctpChunkType get() = SctpChunkType.HeartbeatAck
        override val flagsByte: UByte get() = 0u
        override val valueSize: Int get() = TLV_HEADER_BYTES + info.paddedValue.remaining()

        override fun writeValue(dest: WriteBuffer) = writeParameter(dest, info)
    }

    /** ABORT (type 6, RFC 4960 §3.3.7) — teardown with zero or more error causes; the `T` bit. */
    public data class Abort(
        public val verificationTagReflected: Boolean,
        public val causes: List<SctpErrorCause>,
    ) : SctpChunk {
        override val type: SctpChunkType get() = SctpChunkType.Abort
        override val flagsByte: UByte get() = if (verificationTagReflected) T_BIT else 0u
        override val valueSize: Int get() = tlvWireSize(causes.map { it.paddedValue.remaining() })

        override fun writeValue(dest: WriteBuffer) {
            for (c in causes) writeCause(dest, c)
        }
    }

    /** SHUTDOWN (type 7, RFC 4960 §3.3.8) — begins graceful teardown with the cumulative TSN ack. */
    public data class Shutdown(
        public val cumulativeTsnAck: Tsn,
    ) : SctpChunk {
        override val type: SctpChunkType get() = SctpChunkType.Shutdown
        override val flagsByte: UByte get() = 0u
        override val valueSize: Int get() = TSN_BYTES

        override fun writeValue(dest: WriteBuffer) {
            dest.writeUInt(cumulativeTsnAck.value)
        }
    }

    /** SHUTDOWN-ACK (type 8, RFC 4960 §3.3.9) — acknowledges a SHUTDOWN; no body. */
    public data object ShutdownAck : SctpChunk {
        override val type: SctpChunkType get() = SctpChunkType.ShutdownAck
        override val flagsByte: UByte get() = 0u
        override val valueSize: Int get() = 0

        override fun writeValue(dest: WriteBuffer): Unit = Unit
    }

    /** ERROR (type 9, RFC 4960 §3.3.10) — operational error report carrying error causes. */
    public data class Error(
        public val causes: List<SctpErrorCause>,
    ) : SctpChunk {
        override val type: SctpChunkType get() = SctpChunkType.Error
        override val flagsByte: UByte get() = 0u
        override val valueSize: Int get() = tlvWireSize(causes.map { it.paddedValue.remaining() })

        override fun writeValue(dest: WriteBuffer) {
            for (c in causes) writeCause(dest, c)
        }
    }

    /** COOKIE-ECHO (type 10, RFC 4960 §3.3.11) — echoes the opaque State Cookie back to the peer. */
    public data class CookieEcho(
        public val cookie: ReadBuffer,
    ) : SctpChunk {
        override val type: SctpChunkType get() = SctpChunkType.CookieEcho
        override val flagsByte: UByte get() = 0u
        override val valueSize: Int get() = cookie.remaining()

        override fun writeValue(dest: WriteBuffer) = writeView(dest, cookie)
    }

    /** COOKIE-ACK (type 11, RFC 4960 §3.3.12) — completes the four-way handshake; no body. */
    public data object CookieAck : SctpChunk {
        override val type: SctpChunkType get() = SctpChunkType.CookieAck
        override val flagsByte: UByte get() = 0u
        override val valueSize: Int get() = 0

        override fun writeValue(dest: WriteBuffer): Unit = Unit
    }

    /** SHUTDOWN-COMPLETE (type 14, RFC 4960 §3.3.13) — final teardown chunk; the `T` bit, no body. */
    public data class ShutdownComplete(
        public val verificationTagReflected: Boolean,
    ) : SctpChunk {
        override val type: SctpChunkType get() = SctpChunkType.ShutdownComplete
        override val flagsByte: UByte get() = if (verificationTagReflected) T_BIT else 0u
        override val valueSize: Int get() = 0

        override fun writeValue(dest: WriteBuffer): Unit = Unit
    }

    /** FORWARD-TSN (type 192, RFC 3758 §3.2) — advances the cumulative TSN past abandoned messages. */
    public data class ForwardTsn(
        public val newCumulativeTsn: Tsn,
        public val streams: List<ForwardTsnStream>,
    ) : SctpChunk {
        override val type: SctpChunkType get() = SctpChunkType.ForwardTsn
        override val flagsByte: UByte get() = 0u
        override val valueSize: Int get() = TSN_BYTES + streams.size * FWD_TSN_STREAM_BYTES

        override fun writeValue(dest: WriteBuffer) {
            dest.writeUInt(newCumulativeTsn.value)
            for (s in streams) {
                dest.writeUShort(s.streamId.value.toUShort())
                dest.writeUShort(s.streamSequenceNumber.value)
            }
        }
    }

    /**
     * A chunk whose type this codec does not model — preserved verbatim (RFC 4960 §3.2 forward
     * compatibility). Carries the raw [type], [flags], and a zero-copy [value] view; re-encodes exactly.
     * A receiver consults [SctpChunkType.unrecognizedAction] to decide what to do with it.
     */
    public data class Unrecognized(
        override val type: SctpChunkType,
        public val flags: UByte,
        public val value: ReadBuffer,
    ) : SctpChunk {
        override val flagsByte: UByte get() = flags
        override val valueSize: Int get() = value.remaining()

        override fun writeValue(dest: WriteBuffer) = writeView(dest, value)
    }

    public companion object {
        private const val DATA_FIXED_BYTES = 12 // TSN(4) + stream id(2) + SSN(2) + PPID(4)
        private const val INIT_FIXED_BYTES = 16 // initiate tag(4) + a_rwnd(4) + out streams(2) + in streams(2) + initial TSN(4)
        private const val SACK_FIXED_BYTES = 12 // cum TSN(4) + a_rwnd(4) + #gap(2) + #dup(2)
        private const val GAP_BLOCK_BYTES = 4
        private const val TSN_BYTES = 4
        private const val FWD_TSN_STREAM_BYTES = 4 // stream id(2) + SSN(2)
        private const val T_BIT: UByte = 0x01u

        /**
         * Decodes one chunk body given its [type], [flags], and the zero-copy [value] region (exactly
         * the declared value bytes — chunk length minus the 4-byte header). Returns null when the body
         * does not match the fixed shape its type requires; [SctpPacket] maps that to a typed
         * `MalformedChunkBody` reject. Never throws (T0 totality).
         */
        internal fun decodeBody(
            type: SctpChunkType,
            flags: UByte,
            value: ReadBuffer,
        ): SctpChunk? {
            val n = value.remaining()
            return when (type) {
                SctpChunkType.Data -> {
                    if (n < DATA_FIXED_BYTES) return null
                    Data(
                        DataChunkFlags(flags),
                        Tsn(value.u32(0)),
                        StreamId(value.u16(4)),
                        StreamSequenceNumber(value.u16(6).toUShort()),
                        PayloadProtocolId(value.u32(8)),
                        value.sliceOf(DATA_FIXED_BYTES, n),
                    )
                }
                SctpChunkType.Init ->
                    decodeInit(value, n)?.let { (params) ->
                        Init(
                            VerificationTag(value.u32(0)),
                            value.u32(4),
                            value.u16(8).toUShort(),
                            value.u16(10).toUShort(),
                            Tsn(value.u32(12)),
                            params,
                        )
                    }
                SctpChunkType.InitAck ->
                    decodeInit(value, n)?.let { (params) ->
                        InitAck(
                            VerificationTag(value.u32(0)),
                            value.u32(4),
                            value.u16(8).toUShort(),
                            value.u16(10).toUShort(),
                            Tsn(value.u32(12)),
                            params,
                        )
                    }
                SctpChunkType.Sack -> decodeSack(value, n)
                SctpChunkType.Heartbeat -> decodeSingleParameter(value, n)?.let { Heartbeat(it) }
                SctpChunkType.HeartbeatAck -> decodeSingleParameter(value, n)?.let { HeartbeatAck(it) }
                SctpChunkType.Abort -> decodeCauses(value, 0, n)?.let { Abort(flags.toInt() and T_BIT.toInt() != 0, it) }
                SctpChunkType.Shutdown -> if (n != TSN_BYTES) null else Shutdown(Tsn(value.u32(0)))
                SctpChunkType.ShutdownAck -> if (n != 0) null else ShutdownAck
                SctpChunkType.Error -> decodeCauses(value, 0, n)?.let { Error(it) }
                SctpChunkType.CookieEcho -> CookieEcho(value.sliceOf(0, n))
                SctpChunkType.CookieAck -> if (n != 0) null else CookieAck
                SctpChunkType.ShutdownComplete -> if (n != 0) null else ShutdownComplete(flags.toInt() and T_BIT.toInt() != 0)
                SctpChunkType.ForwardTsn -> decodeForwardTsn(value, n)
                else -> Unrecognized(type, flags, value.sliceOf(0, n))
            }
        }

        // A one-element holder so decodeInit can bail (null) before the two INIT/INIT-ACK variants read
        // the shared fixed fields; destructured at the call site.
        private data class InitParams(
            val parameters: List<SctpParameter>,
        )

        private fun decodeInit(
            value: ReadBuffer,
            n: Int,
        ): InitParams? {
            if (n < INIT_FIXED_BYTES) return null
            val params = decodeParameters(value, INIT_FIXED_BYTES, n) ?: return null
            return InitParams(params)
        }

        private fun decodeSack(
            value: ReadBuffer,
            n: Int,
        ): Sack? {
            if (n < SACK_FIXED_BYTES) return null
            val numGap = value.u16(8)
            val numDup = value.u16(10)
            val needed = SACK_FIXED_BYTES + numGap * GAP_BLOCK_BYTES + numDup * TSN_BYTES
            if (n < needed) return null
            val gaps = ArrayList<GapAckBlock>(numGap)
            var off = SACK_FIXED_BYTES
            repeat(numGap) {
                gaps += GapAckBlock(value.u16(off).toUShort(), value.u16(off + 2).toUShort())
                off += GAP_BLOCK_BYTES
            }
            val dups = ArrayList<Tsn>(numDup)
            repeat(numDup) {
                dups += Tsn(value.u32(off))
                off += TSN_BYTES
            }
            return Sack(Tsn(value.u32(0)), value.u32(4), gaps, dups)
        }

        private fun decodeForwardTsn(
            value: ReadBuffer,
            n: Int,
        ): ForwardTsn? {
            if (n < TSN_BYTES) return null
            val rest = n - TSN_BYTES
            if (rest % FWD_TSN_STREAM_BYTES != 0) return null
            val streams = ArrayList<ForwardTsnStream>(rest / FWD_TSN_STREAM_BYTES)
            var off = TSN_BYTES
            repeat(rest / FWD_TSN_STREAM_BYTES) {
                streams += ForwardTsnStream(StreamId(value.u16(off)), StreamSequenceNumber(value.u16(off + 2).toUShort()))
                off += FWD_TSN_STREAM_BYTES
            }
            return ForwardTsn(Tsn(value.u32(0)), streams)
        }

        // HEARTBEAT/HEARTBEAT-ACK bodies are exactly one parameter (the Heartbeat Info); a body that is
        // not a single well-formed parameter spanning the region is a typed malformed reject.
        private fun decodeSingleParameter(
            value: ReadBuffer,
            n: Int,
        ): SctpParameter? {
            val params = decodeParameters(value, 0, n) ?: return null
            return params.singleOrNull()
        }

        private fun decodeParameters(
            region: ReadBuffer,
            start: Int,
            end: Int,
        ): List<SctpParameter>? =
            walkTlv(region, start, end) { typeField, len, paddedView ->
                SctpParameter.ofWire(ParameterType(typeField.toUShort()), len, paddedView)
            }

        private fun decodeCauses(
            region: ReadBuffer,
            start: Int,
            end: Int,
        ): List<SctpErrorCause>? =
            walkTlv(region, start, end) { typeField, len, paddedView ->
                SctpErrorCause.ofWire(ErrorCauseCode(typeField.toUShort()), len, paddedView)
            }

        // Walks a run of TLVs (type u16, length u16 that counts the 4-byte header + value, value, pad to
        // 4) in `[start, end)` of [region]. Each value view is padding-inclusive but bounded to `end`
        // (a final unpadded TLV keeps only its real bytes) — so re-encode is byte-exact. Returns null on
        // a TLV whose declared length runs past `end` or is shorter than its own header; tolerates a
        // trailing run of fewer than 4 bytes as ignorable padding (RFC 4960: receivers ignore padding).
        private inline fun <T> walkTlv(
            region: ReadBuffer,
            start: Int,
            end: Int,
            make: (typeField: Int, valueLen: Int, paddedView: ReadBuffer) -> T,
        ): List<T>? {
            val out = mutableListOf<T>()
            var pos = start
            while (pos < end) {
                if (pos + TLV_HEADER_BYTES > end) break // < 4 trailing bytes: ignorable padding
                val typeField = region.u16(pos)
                val len = region.u16(pos + 2)
                if (len < TLV_HEADER_BYTES) return null
                val valueLen = len - TLV_HEADER_BYTES
                if (pos + TLV_HEADER_BYTES + valueLen > end) return null
                val paddedEnd = minOf(pos + TLV_HEADER_BYTES + paddedLength(valueLen), end)
                out += make(typeField, valueLen, region.sliceOf(pos + TLV_HEADER_BYTES, paddedEnd))
                pos = paddedEnd
            }
            return out
        }

        private fun writeInitFixedAndParams(
            dest: WriteBuffer,
            initiateTag: VerificationTag,
            advertisedReceiverWindow: UInt,
            outboundStreams: UShort,
            inboundStreams: UShort,
            initialTsn: Tsn,
            parameters: List<SctpParameter>,
        ) {
            dest.writeUInt(initiateTag.value)
            dest.writeUInt(advertisedReceiverWindow)
            dest.writeUShort(outboundStreams)
            dest.writeUShort(inboundStreams)
            dest.writeUInt(initialTsn.value)
            for (p in parameters) writeParameter(dest, p)
        }

        private fun writeParameter(
            dest: WriteBuffer,
            parameter: SctpParameter,
        ) {
            dest.writeUShort(parameter.type.value)
            dest.writeUShort((TLV_HEADER_BYTES + parameter.length).toUShort())
            writeView(dest, parameter.paddedValue)
        }

        private fun writeCause(
            dest: WriteBuffer,
            cause: SctpErrorCause,
        ) {
            dest.writeUShort(cause.code.value)
            dest.writeUShort((TLV_HEADER_BYTES + cause.length).toUShort())
            writeView(dest, cause.paddedValue)
        }

        // On-wire byte count of a run of TLVs given each stored padded-value size: 4-byte header + the
        // padded value bytes, each. Uses the ACTUAL padded-view length (which a decoded final TLV may
        // have had truncated to its chunk region), so valueSize always equals what writeValue emits —
        // otherwise resetForRead would shrink the buffer below the length the checksum reads.
        //
        // For a builder-constructed chunk this counts the final parameter's 4-byte-boundary padding in
        // the Chunk Length. RFC 4960 §3.2 says the SHOULD-form excludes a chunk's trailing pad, but its
        // own Note settles the ambiguity: "A robust implementation should accept the chunk whether or
        // not the final padding has been included in the Chunk Length." Both forms put identical bytes
        // on the wire (the pad sits there regardless); we emit the included form, and our decoder
        // round-trips BOTH byte-exactly — a strict-form (excluded) INIT decodes with a truncated final
        // padded view and re-encodes to its original shorter length; the included form re-encodes to its
        // longer one. So this is one of the two RFC-sanctioned encodings, not a deviation.
        private fun tlvWireSize(paddedValueSizes: List<Int>): Int = paddedValueSizes.sumOf { TLV_HEADER_BYTES + it }

        // Writes [view]'s remaining bytes without disturbing its position (decoded views are shared).
        private fun writeView(
            dest: WriteBuffer,
            view: ReadBuffer,
        ) {
            val p = view.position()
            dest.write(view)
            view.position(p)
        }
    }
}

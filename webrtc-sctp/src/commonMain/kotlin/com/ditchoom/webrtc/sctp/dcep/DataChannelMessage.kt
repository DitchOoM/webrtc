package com.ditchoom.webrtc.sctp.dcep

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed

/**
 * A DCEP (Data Channel Establishment Protocol, RFC 8832) control message — the payload of an SCTP DATA
 * chunk whose PPID is `WebRTC DCEP` (50). A **sealed** pair so a handler's `when` is exhaustive:
 * [Open] negotiates a channel, [Ack] confirms it.
 *
 * Decode is total and typed-reject ([DataChannelDecodeResult]); [Open]'s label/protocol are decoded as
 * UTF-8 (RFC 8832 §5.1), and invalid UTF-8 is a typed reject, never a throw. This is the DCEP wire
 * codec only — the open/ack handshake state machine (which stream to use, even/odd stream selection
 * per RFC 8832 §6) sits above it with the SCTP association.
 */
public sealed interface DataChannelMessage {
    /** The one-byte DCEP message type (RFC 8832 §8.2.1). */
    public val messageType: UByte

    /** Serializes this message into a fresh read-ready buffer (RFC 8832 §5 layout). */
    public fun encode(factory: BufferFactory = BufferFactory.managed()): PlatformBuffer

    /**
     * DATA_CHANNEL_OPEN (message type 0x03, RFC 8832 §5.1) — opens a channel, carrying its reliability
     * ([channelType]), scheduling [priority], the reliability parameter (see [Reliability]), and the
     * UTF-8 [label] / sub-[protocol].
     */
    public data class Open(
        public val channelType: ChannelType,
        public val priority: UShort,
        public val reliabilityParameter: UInt,
        public val label: String,
        public val protocol: String,
    ) : DataChannelMessage {
        override val messageType: UByte get() = OPEN_TYPE

        /** Serializes this OPEN into a fresh read-ready buffer (RFC 8832 §5.1 layout). */
        override fun encode(factory: BufferFactory): PlatformBuffer {
            // Encode the text bodies first and measure the ACTUAL UTF-8 byte counts, so the Label/
            // Protocol Length fields match `writeString` exactly. A hand-count over UTF-16 chars
            // mis-sizes any supplementary-plane code point (an emoji is a surrogate pair — two chars,
            // 4 UTF-8 bytes — not 6), which would desync the receiver.
            val labelBuf = encodeUtf8(label, factory)
            val protocolBuf = encodeUtf8(protocol, factory)
            val labelBytes = labelBuf.remaining()
            val protocolBytes = protocolBuf.remaining()
            val dest = factory.allocate(OPEN_FIXED_BYTES + labelBytes + protocolBytes, ByteOrder.BIG_ENDIAN)
            dest.writeByte(OPEN_TYPE.toByte())
            dest.writeByte(channelType.raw.toByte())
            dest.writeUShort(priority)
            dest.writeUInt(reliabilityParameter)
            dest.writeUShort(labelBytes.toUShort())
            dest.writeUShort(protocolBytes.toUShort())
            dest.write(labelBuf)
            dest.write(protocolBuf)
            dest.resetForRead()
            return dest
        }
    }

    /** DATA_CHANNEL_ACK (message type 0x02, RFC 8832 §5.2) — a single byte confirming an OPEN. */
    public data object Ack : DataChannelMessage {
        override val messageType: UByte get() = ACK_TYPE

        /** Serializes this ACK (the single message-type byte) into a fresh read-ready buffer. */
        override fun encode(factory: BufferFactory): PlatformBuffer {
            val dest = factory.allocate(1, ByteOrder.BIG_ENDIAN)
            dest.writeByte(ACK_TYPE.toByte())
            dest.resetForRead()
            return dest
        }
    }

    public companion object {
        private const val ACK_TYPE: UByte = 0x02u
        private const val OPEN_TYPE: UByte = 0x03u
        private const val OPEN_FIXED_BYTES = 12 // type(1) + channel type(1) + priority(2) + reliability(4) + label len(2) + protocol len(2)
        private const val LABEL_LEN_OFFSET = 8
        private const val PROTOCOL_LEN_OFFSET = 10
        private const val TEXT_OFFSET = 12
        private const val MAX_UTF8_BYTES_PER_UNIT = 3 // ≤ 3 UTF-8 bytes per UTF-16 code unit (upper bound)

        /**
         * Parses one DCEP message from [payload] (its current position to its limit — the DATA chunk's
         * user-data view). Never throws — every failure is a typed [DataChannelDecodeResult.Reject].
         */
        public fun decode(payload: ReadBuffer): DataChannelDecodeResult {
            val start = payload.position()
            val n = payload.limit() - start
            if (n < 1) return DataChannelDecodeResult.Reject(DataChannelRejectReason.Empty)
            return when (val messageType = payload.get(start).toUByte()) {
                ACK_TYPE -> DataChannelDecodeResult.Success(Ack)
                OPEN_TYPE -> decodeOpen(payload, start, n)
                else -> DataChannelDecodeResult.Reject(DataChannelRejectReason.UnknownMessageType(messageType))
            }
        }

        private fun decodeOpen(
            payload: ReadBuffer,
            start: Int,
            n: Int,
        ): DataChannelDecodeResult {
            if (n < OPEN_FIXED_BYTES) return DataChannelDecodeResult.Reject(DataChannelRejectReason.OpenTooShort)
            val channelType = ChannelType(payload.get(start + 1).toUByte())
            val priority = beU16(payload, start + 2).toUShort()
            val reliabilityParameter = beU32(payload, start + 4)
            val labelLen = beU16(payload, start + LABEL_LEN_OFFSET)
            val protocolLen = beU16(payload, start + PROTOCOL_LEN_OFFSET)
            if (TEXT_OFFSET + labelLen + protocolLen > n) {
                return DataChannelDecodeResult.Reject(DataChannelRejectReason.LabelProtocolBeyondMessage)
            }
            val label =
                readUtf8(payload, start + TEXT_OFFSET, labelLen)
                    ?: return DataChannelDecodeResult.Reject(DataChannelRejectReason.InvalidUtf8)
            val protocol =
                readUtf8(payload, start + TEXT_OFFSET + labelLen, protocolLen)
                    ?: return DataChannelDecodeResult.Reject(DataChannelRejectReason.InvalidUtf8)
            return DataChannelDecodeResult.Success(Open(channelType, priority, reliabilityParameter, label, protocol))
        }

        private fun beU16(
            b: ReadBuffer,
            i: Int,
        ): Int = ((b.get(i).toInt() and 0xFF) shl 8) or (b.get(i + 1).toInt() and 0xFF)

        private fun beU32(
            b: ReadBuffer,
            i: Int,
        ): UInt = ((beU16(b, i).toLong() shl 16) or beU16(b, i + 2).toLong()).toUInt()

        // Reads [len] bytes at absolute [start] as UTF-8, or null if not valid UTF-8 (a typed miss, not
        // a throw). Must catch Throwable, not Exception — Kotlin/JS's TextDecoder throws a raw JS error
        // (the STUN asText lesson). Restores position.
        private fun readUtf8(
            b: ReadBuffer,
            start: Int,
            len: Int,
        ): String? {
            if (len == 0) return ""
            val saved = b.position()
            return try {
                b.position(start)
                b.readString(len, Charset.UTF8)
            } catch (_: Throwable) {
                null
            } finally {
                b.position(saved)
            }
        }

        // Encodes [text] to a fresh read-ready UTF-8 buffer whose remaining() is the exact byte count.
        // Sized by an upper bound (≤ 3 UTF-8 bytes per UTF-16 code unit — a surrogate pair is 2 units
        // and 4 bytes, so 2 bytes/unit), then trimmed to the real length by resetForRead.
        private fun encodeUtf8(
            text: String,
            factory: BufferFactory,
        ): ReadBuffer {
            if (text.isEmpty()) return ReadBuffer.EMPTY_BUFFER
            val scratch = factory.allocate(text.length * MAX_UTF8_BYTES_PER_UNIT, ByteOrder.BIG_ENDIAN)
            scratch.writeString(text, Charset.UTF8)
            scratch.resetForRead()
            return scratch
        }
    }
}

/**
 * The outcome of [DataChannelMessage.decode] — a typed reject, never a throw (T0 discipline).
 */
public sealed interface DataChannelDecodeResult {
    public data class Success(
        public val message: DataChannelMessage,
    ) : DataChannelDecodeResult

    public data class Reject(
        public val reason: DataChannelRejectReason,
    ) : DataChannelDecodeResult
}

/** Why a payload is not a well-formed DCEP message. Sealed, exhaustive, typed (directive #3). */
public sealed interface DataChannelRejectReason {
    /** The payload was empty (no message-type byte). */
    public data object Empty : DataChannelRejectReason

    /** The message-type byte was neither DATA_CHANNEL_ACK (0x02) nor DATA_CHANNEL_OPEN (0x03). */
    public data class UnknownMessageType(
        public val messageType: UByte,
    ) : DataChannelRejectReason

    /** A DATA_CHANNEL_OPEN shorter than its 12-byte fixed header. */
    public data object OpenTooShort : DataChannelRejectReason

    /** The declared label + protocol lengths extend past the message. */
    public data object LabelProtocolBeyondMessage : DataChannelRejectReason

    /** The label or protocol bytes were not valid UTF-8 (RFC 8832 §5.1). */
    public data object InvalidUtf8 : DataChannelRejectReason
}

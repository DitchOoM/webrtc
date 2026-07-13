package com.ditchoom.webrtc.sctp

import kotlin.jvm.JvmInline

/**
 * The RFC 4960 §3.2 / §3.2.1 policy encoded in the two high bits of a chunk *type* or a parameter
 * *type*, applied when a receiver does not recognize it. A genuinely dataless closed set (an enum);
 * ordinals are the 2-bit wire values, so `entries[bits]` decodes directly. Shared by
 * [SctpChunkType.unrecognizedAction] and [ParameterType.unrecognizedAction].
 */
public enum class UnrecognizedAction {
    /** `00` — stop processing this packet/parameter list and discard. */
    StopAndDiscard,

    /** `01` — stop processing and discard, and report the unrecognized type in an ERROR/ABORT. */
    StopAndReport,

    /** `10` — skip this chunk/parameter and keep processing the rest. */
    SkipAndContinue,

    /** `11` — skip and keep processing, and report the unrecognized type. */
    SkipAndReport,
    ;

    internal companion object {
        internal const val HIGH_BITS_SHIFT = 6
        internal const val HIGH_BITS_MASK = 0b11

        /** Decodes the action from a type field's [highBits] value (bits shifted into the low 2). */
        internal fun ofHighBits(highBits: Int): UnrecognizedAction = entries[highBits and HIGH_BITS_MASK]
    }
}

/**
 * An SCTP chunk type (RFC 4960 §3.2) — the 8-bit type field wrapped so it is never a bare `UByte`.
 *
 * The two most-significant bits encode what a receiver does with a chunk type it does **not**
 * recognize ([unrecognizedAction]); the lower six bits are the registry point. Modeling the action as
 * a typed [UnrecognizedAction] rather than reconstructing the bit test at each call site keeps the
 * "unknown chunk" policy (RFC 4960 §3.2) discoverable and exhaustive.
 */
@JvmInline
public value class SctpChunkType(
    public val value: UByte,
) {
    /** What RFC 4960 §3.2 says to do when a receiver does not recognize this chunk type. */
    public val unrecognizedAction: UnrecognizedAction
        get() = UnrecognizedAction.ofHighBits(value.toInt() ushr UnrecognizedAction.HIGH_BITS_SHIFT)

    public companion object {
        public val Data: SctpChunkType = SctpChunkType(0u)
        public val Init: SctpChunkType = SctpChunkType(1u)
        public val InitAck: SctpChunkType = SctpChunkType(2u)
        public val Sack: SctpChunkType = SctpChunkType(3u)
        public val Heartbeat: SctpChunkType = SctpChunkType(4u)
        public val HeartbeatAck: SctpChunkType = SctpChunkType(5u)
        public val Abort: SctpChunkType = SctpChunkType(6u)
        public val Shutdown: SctpChunkType = SctpChunkType(7u)
        public val ShutdownAck: SctpChunkType = SctpChunkType(8u)
        public val Error: SctpChunkType = SctpChunkType(9u)
        public val CookieEcho: SctpChunkType = SctpChunkType(10u)
        public val CookieAck: SctpChunkType = SctpChunkType(11u)
        public val ShutdownComplete: SctpChunkType = SctpChunkType(14u)

        /** FORWARD-TSN (RFC 3758 §3.2) — the partial-reliability skip marker; type 192 (0xC0). */
        public val ForwardTsn: SctpChunkType = SctpChunkType(192u)
    }
}

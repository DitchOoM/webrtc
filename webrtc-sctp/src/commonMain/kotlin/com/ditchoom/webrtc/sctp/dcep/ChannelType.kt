package com.ditchoom.webrtc.sctp.dcep

import kotlin.jvm.JvmInline

/**
 * The reliability kind of a data channel (RFC 8832 §5.1), decoded from the low bits of a
 * [ChannelType]. A **sealed** projection so a consumer's `when` is exhaustive: the three RFC-defined
 * kinds plus an [Unknown] escape for a value a future/foreign peer might send (the wire byte is still
 * preserved by [ChannelType], so nothing is lost). How the OPEN message's 32-bit Reliability Parameter
 * is read depends on which kind this is — hence modeling it as a type, not a boolean pair.
 */
public sealed interface Reliability {
    /** `DATA_CHANNEL_RELIABLE` — every message is delivered; the Reliability Parameter is ignored. */
    public data object Reliable : Reliability

    /**
     * `DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT` (RFC 3758 / RFC 8831 §6.4) — the Reliability Parameter is
     * the maximum number of retransmissions before a message is abandoned.
     */
    public data object PartialReliableRetransmit : Reliability

    /**
     * `DATA_CHANNEL_PARTIAL_RELIABLE_TIMED` — the Reliability Parameter is the maximum lifetime in
     * milliseconds a message may be retransmitted for before it is abandoned.
     */
    public data object PartialReliableTimed : Reliability

    /** A reliability kind this codec does not model; [lowBits] is the raw low-7-bits value. */
    public data class Unknown(
        public val lowBits: Int,
    ) : Reliability
}

/**
 * The Channel Type octet of a DCEP DATA_CHANNEL_OPEN message (RFC 8832 §5.1) — the 0x80 unordered bit
 * plus a reliability kind in the low bits, wrapped so no call site reads a bare `raw and 0x80`. The
 * full `UByte` is preserved, so a decoded OPEN re-encodes byte-for-byte even for an [Reliability.Unknown]
 * kind.
 */
@JvmInline
public value class ChannelType(
    public val raw: UByte,
) {
    /** True for ordered delivery — the unordered bit (0x80) is clear (RFC 8832 §5.1). */
    public val ordered: Boolean get() = raw.toInt() and UNORDERED_BIT == 0

    /** The reliability kind from the low bits (exhaustive; [Reliability.Unknown] for an unmodeled value). */
    public val reliability: Reliability
        get() =
            when (raw.toInt() and LOW_BITS_MASK) {
                RELIABLE -> Reliability.Reliable
                PR_REXMIT -> Reliability.PartialReliableRetransmit
                PR_TIMED -> Reliability.PartialReliableTimed
                else -> Reliability.Unknown(raw.toInt() and LOW_BITS_MASK)
            }

    public companion object {
        private const val UNORDERED_BIT = 0x80
        private const val LOW_BITS_MASK = 0x7F
        private const val RELIABLE = 0x00
        private const val PR_REXMIT = 0x01
        private const val PR_TIMED = 0x02

        /**
         * Builds a Channel Type from an [ordered] flag and a [reliability] kind. [Reliability.Unknown]'s
         * low bits are used verbatim (so a round-tripped unknown type is reproducible).
         */
        public fun of(
            ordered: Boolean,
            reliability: Reliability,
        ): ChannelType {
            val low =
                when (reliability) {
                    Reliability.Reliable -> RELIABLE
                    Reliability.PartialReliableRetransmit -> PR_REXMIT
                    Reliability.PartialReliableTimed -> PR_TIMED
                    is Reliability.Unknown -> reliability.lowBits and LOW_BITS_MASK
                }
            val hi = if (ordered) 0 else UNORDERED_BIT
            return ChannelType((hi or low).toUByte())
        }
    }
}

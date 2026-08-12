package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.StreamId
import kotlin.jvm.JvmInline

/**
 * A number of SCTP streams in one direction — the u16 an INIT/INIT ACK carries in its `OS` and `MIS`
 * fields (RFC 4960 §3.3.2), and the running value RFC 6525 §4.5 raises.
 *
 * Wrapped because the *other* u16 in every sentence about streams is a [StreamId], and the two are off
 * by one from each other: a capacity of `n` streams admits ids `0 until n`. Passing one where the other
 * belongs is an off-by-one that reads correctly at every call site — a channel that opens on an id the
 * peer will refuse, answered with an ERROR the association discards — which is precisely the class of
 * mistake the house style makes unrepresentable rather than reviewable (DESIGN_PRINCIPLES §2).
 */
@JvmInline
public value class StreamCount(
    public val value: UShort,
) : Comparable<StreamCount> {
    /** True when [id] is inside a capacity of this many streams (ids run `0 until value`). */
    public fun admits(id: StreamId): Boolean = id.value < value.toInt()

    override fun compareTo(other: StreamCount): Int = value.compareTo(other.value)

    public companion object {
        /** No streams at all — the value RFC 4960 §3.3.2 forbids an INIT or INIT ACK from advertising. */
        public val None: StreamCount = StreamCount(0u)

        /** Every stream the 16-bit count field can express. */
        public val Max: StreamCount = StreamCount(UShort.MAX_VALUE)

        /**
         * The highest stream id any capacity can ever admit. [Max] is 65535 streams, which are ids
         * `0..65534` — so 65535 is a representable [StreamId] that no negotiated capacity reaches, and
         * an allocator walking ids by parity runs out here rather than at the id type's own ceiling.
         */
        public val MaxUsableId: StreamId = StreamId(0xFFFE)
    }
}

/**
 * How many outgoing streams this association may use: `min(our OS, the peer's MIS)` (RFC 4960 §5.1.1),
 * raised later by an RFC 6525 §4.5 Add Outgoing Streams exchange.
 *
 * Sealed rather than a [StreamCount] that starts at zero, because "the handshake has not settled this
 * yet" and "the handshake settled on no streams" are different facts that a zero would merge — and only
 * the first is legal. [Negotiated] holding [StreamCount.None] is representable and illegal; it is made
 * unreachable by the zero-stream aborts on both the INIT and the INIT ACK rather than by a `require`,
 * because [SctpAssociation.handle] is documented never to throw.
 */
public sealed interface OutgoingStreamCapacity {
    /** No association: before the handshake completes, and after any teardown. */
    public data object NotNegotiated : OutgoingStreamCapacity

    /** The association settled on [streams] outgoing streams. */
    public data class Negotiated(
        public val streams: StreamCount,
    ) : OutgoingStreamCapacity
}

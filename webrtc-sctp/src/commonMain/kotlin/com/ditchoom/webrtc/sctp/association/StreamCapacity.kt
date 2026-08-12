package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.ReConfigResult
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

/** True when adding [other] would need more than the 16-bit count field can express. */
internal fun StreamCount.wouldOverflow(other: StreamCount): Boolean = value.toInt() + other.value.toInt() > StreamCount.Max.value.toInt()

/** [this] plus [other], clamped at [StreamCount.Max]. Pair with [wouldOverflow] where the clamp would lie. */
internal fun StreamCount.plusSaturating(other: StreamCount): StreamCount =
    StreamCount(minOf(value.toInt() + other.value.toInt(), StreamCount.Max.value.toInt()).toUShort())

/**
 * How an RFC 6525 §4.5 Add Outgoing Streams request this endpoint originated ended.
 *
 * Sealed rather than a bare [ReConfigResult] for the same reason [StreamResetOutcome] is: two of the
 * outcomes are **ours** rather than the peer's. A peer that never advertised RE-CONFIG answers nothing at
 * all, and a request that would take the count past what a 16-bit field can express is refused here
 * before it reaches the wire — inventing a [ReConfigResult] for either would put a value on the wire's
 * enum that the wire never carried.
 */
public sealed interface StreamAddOutcome {
    /** The peer increased its inbound streams, so this endpoint's outgoing capacity has risen. */
    public data object Performed : StreamAddOutcome

    /** The capacity did not change, and [StreamAddOutcome] says why. */
    public sealed interface NotAdded : StreamAddOutcome {
        /** The peer answered, and declined — [result] is its RFC 6525 §4.4 reason. */
        public data class Answered(
            public val result: ReConfigResult,
        ) : NotAdded

        /**
         * The peer never advertised RE-CONFIG in its INIT/INIT ACK Supported Extensions, so no request was
         * put on the wire (RFC 6525 §5.1). The stream count it agreed to at handshake time is final.
         */
        public data object Unsupported : NotAdded

        /**
         * The request would take this endpoint's outgoing count past [StreamCount.Max]. Refused locally:
         * the RFC 6525 §4.5 count field is a u16 and so is the negotiated total, so there is nothing
         * truthful to ask for.
         */
        public data object WouldOverflow : NotAdded
    }
}

/**
 * What to do when a data channel needs a stream id the association has not negotiated room for.
 *
 * Defaults to [Fixed] — the handshake's count is what the session gets — because growth is a *wire*
 * change (RFC 6525 §4.5) reachable only past 512 concurrent channels on this stack's default
 * configuration, and a knob that puts new chunk types in front of every interop peer should be chosen
 * rather than inherited. The same reasoning `IceRestartPolicy.Manual` is built on.
 */
public sealed interface StreamGrowthPolicy {
    /** Never ask for more. An open with no id left is refused with the typed reason and nothing is sent. */
    public data object Fixed : StreamGrowthPolicy

    /**
     * Ask the peer for more outgoing streams when an open runs out, in batches of at least [increment]
     * (a single request covers every open waiting on it). A batch, rather than one stream per open,
     * because each request is a round trip that RFC 6525 §5.1.2 will not overlap with another.
     */
    public data class AddStreams(
        public val increment: StreamCount,
    ) : StreamGrowthPolicy {
        init {
            require(
                increment > StreamCount.None,
            ) { "StreamGrowthPolicy.AddStreams needs a non-zero increment; RFC 6525 §4.5 forbids asking for zero" }
        }
    }
}

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.association.StreamCount

/**
 * Why a data channel could not be opened. Every variant is a fact about the **stream-id space**, which is
 * the one resource an open can run out of: RFC 8832 §6 gives each side half of a 16-bit space, an id is
 * reusable only after both directions of its close have been reset (RFC 8831 §6.7), and RFC 4960 §5.1.1
 * caps how much of that space the association negotiated.
 *
 * Typed, and delivered as [DataChannelOpenRefusedException], because the alternative is what this replaces:
 * `StreamId(nextStreamId)` threw `IllegalArgumentException` from inside the serialized drive loop the
 * moment the cursor stepped past the id space. On Kotlin/Native an uncaught throw in a launched coroutine
 * is process death rather than something a consumer can catch, and the `open()` deferred that was waiting
 * on it never completed either way — so the failure mode of running out of stream ids was "the application
 * disappears" on one target and "the call hangs forever" on the rest.
 *
 * [description] is a diagnostic. The variant is the discriminant (directive #3).
 */
public sealed interface DataChannelOpenRefusal {
    /** Human-readable detail for a log or an exception message — never matched on. */
    public val description: String

    /**
     * [id] is a legal stream identifier but sits at or above the [capacity] this association negotiated,
     * so the peer would answer data on it with an Invalid Stream Identifier ERROR (RFC 4960 §3.3.10.1).
     */
    public data class StreamIdOutsideNegotiatedRange(
        public val id: StreamId,
        public val capacity: StreamCount,
    ) : DataChannelOpenRefusal {
        override val description: String
            get() = "stream id ${id.value} is outside the ${capacity.value} streams this association negotiated"
    }

    /** [id] already backs an open data channel. */
    public data class StreamIdInUse(
        public val id: StreamId,
    ) : DataChannelOpenRefusal {
        override val description: String get() = "stream id ${id.value} already backs an open data channel"
    }

    /**
     * [id]'s channel is closing: one direction of its RFC 6525 reset has landed and the other has not.
     * Reusing it now would hand a new channel the Stream Sequence Number state of the old one.
     */
    public data class StreamIdClosing(
        public val id: StreamId,
    ) : DataChannelOpenRefusal {
        override val description: String get() = "stream id ${id.value} is mid-close and its state is not yet reset on both sides"
    }

    /**
     * [id] is spent for the life of the association: the peer refused to reset it, or cannot reset streams
     * at all, so it still holds Stream Sequence Number state we can never clear (RFC 6525 §5.1).
     */
    public data class StreamIdBurned(
        public val id: StreamId,
    ) : DataChannelOpenRefusal {
        override val description: String get() = "stream id ${id.value} was never reset by the peer and is spent for this association"
    }

    /**
     * Every id of this endpoint's parity has been handed out and none has come back — the 16-bit space
     * itself is gone, not merely the negotiated part of it, so no amount of RFC 6525 §4.5 growth helps.
     */
    public data object StreamIdSpaceExhausted : DataChannelOpenRefusal {
        override val description: String get() = "every stream id of this endpoint's parity is spent"
    }
}

/**
 * Thrown to a caller awaiting `open()` when the channel cannot be given a stream id. Carries the typed
 * [refusal]; the message is a diagnostic built from it.
 */
public class DataChannelOpenRefusedException(
    public val refusal: DataChannelOpenRefusal,
) : Exception("data channel refused: ${refusal.description}")

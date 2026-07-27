package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.ReConfigResult
import com.ditchoom.webrtc.sctp.StreamId

/**
 * Which streams a reset applies to (RFC 6525 §4.1). The wire encodes "every stream" as an **empty**
 * stream list, which is precisely the encoding a `List<StreamId>` cannot be trusted to carry: an empty
 * list reads as "reset nothing" at every call site that forgets the rule, and resetting nothing and
 * resetting everything are the two most different things this protocol can say.
 *
 * So the distinction is a type. [AllStreams] is the empty-list encoding, named; [Streams] is an explicit
 * set. A `when` over the two compiles without an `else`, and the mapping to and from the wire happens
 * exactly once (DESIGN_PRINCIPLES §3).
 */
public sealed interface StreamResetScope {
    /** Every stream in the direction being reset — RFC 6525 §4.1's empty stream list. */
    public data object AllStreams : StreamResetScope

    /**
     * The named streams. An empty [ids] is a no-op rather than an implicit [AllStreams]: the association
     * simply sends no request for it, which is the safe reading of a caller that asked for nothing.
     */
    public data class Streams(
        public val ids: Set<StreamId>,
    ) : StreamResetScope
}

/**
 * How an outgoing stream-reset request this endpoint originated ended (RFC 6525 §5.1.1) — carried by
 * [SctpOutput.OutgoingStreamsReset].
 *
 * Sealed rather than a bare [ReConfigResult] because two of the three outcomes are *ours*, not the
 * peer's: a peer that never advertised RE-CONFIG support answers nothing at all, and inventing a
 * [ReConfigResult] to describe that would put a value on the wire's enum that the wire never carried.
 */
public sealed interface StreamResetOutcome {
    /**
     * The peer reset the streams (RFC 6525 §4.4 result `SuccessPerformed` or `SuccessNothingToDo`).
     * This endpoint's outgoing SSN state for them is now reset too, so the stream ids are reusable.
     */
    public data object Performed : StreamResetOutcome

    /**
     * The peer answered, but declined — [result] is its RFC 6525 §4.4 reason. The streams keep their
     * SSN state on both sides, so a stream id in a refused request MUST NOT be recycled.
     */
    public data class Refused(
        public val result: ReConfigResult,
    ) : StreamResetOutcome

    /**
     * The peer never advertised RE-CONFIG in its INIT/INIT-ACK Supported Extensions, so no request was
     * ever put on the wire (RFC 6525 §5.1: an endpoint sends RE-CONFIG only to a peer that supports it).
     * The channel closes locally; the stream id stays spent, because the peer still holds SSN state for it.
     */
    public data object Unsupported : StreamResetOutcome
}

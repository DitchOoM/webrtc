package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId

/**
 * A side effect the driver must perform for the [SctpAssociation]. The core returns these from
 * `handle`; it never touches the transport itself. Exhaustive and sealed so a driver `when`s over it
 * with no `else` (DESIGN_PRINCIPLES §3).
 */
public sealed interface SctpOutput {
    /**
     * Send [packet] over the transport below (DTLS → the selected ICE pair). It is positioned for
     * reading with the CRC32c already placed — the driver just hands it to `AddressedDatagramChannel.send`.
     *
     * **[packet] is always a read view, and always the driver's to release once the send has gone out.**
     * Writing into it would corrupt a future retransmission; reading it — including moving this view's own
     * position/limit, or slicing it further — is fine and is what the driver does.
     *
     * ## Why this is sealed: two ownership regimes hide behind one verb
     *
     * Releasing the *view* is not the same act as releasing the *bytes under it*, and which one the driver
     * is doing depends on where the packet came from. Conflating them is not a leak either way round — it
     * is a use-after-free in one direction and an unreclaimable chunk in the other:
     *
     * - [Owned] — a control packet, encoded for this one transmission and retained by nobody. The view
     *   *is* the buffer, so the driver's release frees the bytes. Nothing else may hold it.
     * - [Retained] — a DATA packet, whose bytes the retransmission queue keeps so a retransmit re-emits
     *   them unchanged (RFC 4960 §6.1). The view is a borrow over those bytes; releasing it costs a
     *   reference on a pooled buffer and nothing at all on a plain one, and in neither case are the bytes
     *   freed. Those come back as [ReclaimRetained], and only then.
     *
     * The distinction is invisible to a driver that only *sends* — both are `send(packet)` — which is
     * exactly why it has to be in the type. It is not inferable from the buffer: a slice of a pooled chunk
     * and a pooled chunk answer every question a driver can ask identically.
     */
    public sealed interface Transmit : SctpOutput {
        /** The datagram to put on the wire, positioned for reading. */
        public val packet: PlatformBuffer

        /**
         * The driver owns these bytes outright — release [packet] once the send has completed. Every
         * control packet (INIT, COOKIE ECHO, SACK, HEARTBEAT ACK, SHUTDOWN, RE-CONFIG, ABORT, FORWARD-TSN)
         * is one of these: it is encoded for a single transmission and no part of the association keeps it.
         */
        public data class Owned(
            override val packet: PlatformBuffer,
        ) : Transmit

        /**
         * [packet] is a read view over bytes the association still owns for retransmission. Release the
         * **view** once the send has completed; never the bytes behind it — the association hands those
         * back as [ReclaimRetained] when the chunk is acked or abandoned.
         */
        public data class Retained(
            override val packet: PlatformBuffer,
        ) : Transmit
    }

    /**
     * Bytes previously lent out as one or more [Transmit.Retained] views will never be transmitted again
     * (the chunk was acked, abandoned, or discarded with the association) — the driver releases [packet].
     *
     * **It has to be the driver, and it has to be in order.** The association cannot free these itself:
     * a driver that hands sends to a writer coroutine may still have a [Transmit.Retained] view of exactly
     * these bytes queued behind it, and on a plain (non-refcounted) buffer freeing the parent invalidates
     * that view mid-send. Emitted **after** every [Transmit] it could possibly race, so a driver that
     * carries this through the same queue as its sends — the ordering it already needs to keep the wire
     * deterministic — cannot get it wrong.
     */
    public data class ReclaimRetained(
        public val packet: PlatformBuffer,
    ) : SctpOutput

    /** The association lifecycle state changed (RFC 4960 §4) — surfaced to the DataChannel/PeerConnection layer. */
    public data class StateChanged(
        public val state: SctpAssociationState,
    ) : SctpOutput

    /**
     * How many outgoing streams this endpoint may use has been settled or raised (RFC 4960 §5.1.1, and
     * RFC 6525 §4.5 when it grows). Emitted once when the handshake completes and again after every
     * successful Add Outgoing Streams exchange.
     *
     * It is an output rather than a property the driver reads because the stream-id allocator above this
     * layer has to *react* to it: an open parked for want of capacity is released by this event and by
     * nothing else, and a driver that polled would have to guess when to look.
     */
    public data class OutgoingCapacityChanged(
        public val capacity: OutgoingStreamCapacity.Negotiated,
    ) : SctpOutput

    /**
     * An [SctpEvent.RequestMoreOutgoingStreams] this endpoint originated has been resolved (RFC 6525 §4.5).
     * One is emitted for every request the association survives to resolve — including the ones it can
     * never put on the wire ([StreamAddOutcome.NotAdded.Unsupported],
     * [StreamAddOutcome.NotAdded.WouldOverflow]) — so the only way an ask goes unanswered is an association
     * that fails first, which the driver hears about as [Aborted].
     *
     * [requested] is the accumulated count that actually went out, which may exceed any single ask: several
     * requests made while one was in flight are merged into one, because §5.1.2 allows only one outstanding.
     * On [StreamAddOutcome.Performed] the new ceiling arrives beside this as [OutgoingCapacityChanged].
     */
    public data class OutgoingStreamsAdded(
        public val requested: StreamCount,
        public val outcome: StreamAddOutcome,
    ) : SctpOutput

    /**
     * A complete user message was reassembled and is ready for delivery to the upper layer, in the
     * correct order for its stream. [payload] is a fresh buffer from `SctpConfig.bufferFactory` (the
     * reassembly copy) and is **transferred**: the driver owns it and owes it a release, either by passing
     * that ownership on to the application or by freeing it. [unordered] and [payloadProtocolId] let the
     * DataChannel layer route DCEP vs. app data (RFC 8831 §6.6) — and a DCEP message is one no application
     * ever sees, so nothing but the driver can free those.
     */
    public data class MessageReceived(
        public val streamId: StreamId,
        public val payloadProtocolId: PayloadProtocolId,
        public val unordered: Boolean,
        public val payload: ReadBuffer,
    ) : SctpOutput

    /**
     * The peer reset its **outgoing** streams — this endpoint's incoming half (RFC 6525 §5.2.2). The
     * reset has already been applied to the reassembly state by the time this is emitted: partial
     * messages on those streams are discarded and their expected Stream Sequence Number is back at 0.
     *
     * RFC 8831 §6.7 makes this the peer closing a data channel. The driver closes the corresponding
     * channels and resets its own outgoing half in turn ([SctpEvent.ResetStreams]); only when both
     * directions have been reset is the channel closed and its stream id free to reuse.
     */
    public data class IncomingStreamsReset(
        public val scope: StreamResetScope,
    ) : SctpOutput

    /**
     * An [SctpEvent.ResetStreams] request this endpoint originated has been answered (RFC 6525 §5.1.1).
     * One of these is emitted for every request the association survives to resolve — including the
     * requests it can never put on the wire ([StreamResetOutcome.Unsupported]) — so the only way a close
     * goes unanswered is an association that fails first, which the driver hears about as [Aborted].
     *
     * [scope] is the request's own scope, not the peer's interpretation of it. On
     * [StreamResetOutcome.Performed] the outgoing SSN state for those streams has been reset here too;
     * on any other outcome nothing changed and the stream ids remain spent.
     */
    public data class OutgoingStreamsReset(
        public val scope: StreamResetScope,
        public val outcome: StreamResetOutcome,
    ) : SctpOutput

    /**
     * The association reached a terminal failure (RFC 4960 §8.1 error threshold, a received ABORT, or a
     * malformed handshake). Carries the typed [reason] (never a string — directive #3). The driver
     * tears down the DataChannels.
     */
    public data class Aborted(
        public val reason: SctpFailureReason,
    ) : SctpOutput

    /**
     * The peer restarted: it opened a *new* association over the same transport, and RFC 4960 §5.2.4
     * action A adopted it (the association itself is [SctpAssociationState.Established] again, on fresh
     * TSNs and streams). This is emitted **instead of** [Aborted] — the RFC's "notification of RESTART
     * SHOULD be sent to the ULP instead of a COMMUNICATION LOST notification" — because the association
     * is alive; what is gone is everything that was open on it, since the peer no longer knows about it.
     *
     * What to do about that is the driver's call, not the association's: the DataChannel layer treats it
     * as a teardown ([SctpFailureReason.PeerRestarted]), because a data-channel session whose peer has
     * forgotten every stream cannot be continued, only renegotiated. Unreachable in the WebRTC profile
     * proper — an SCTP association lives inside one DTLS session (RFC 8831 §6), so a peer that restarts
     * brings a new transport with it — which is exactly why it is surfaced rather than assumed away.
     */
    public data object PeerRestarted : SctpOutput

    /**
     * The fragmentation ceiling the **path** admits has changed — because the path was named, because a
     * probe confirmed a size, or because the size already being emitted turned out not to be carried
     * (RFC 8899 / RFC 8261 §6.1).
     *
     * [ceiling] is the path's answer, not necessarily the number the next message is fragmented at. While
     * nothing has been *measured* the association fragments at `min(ceiling, SctpConfig.maxPayloadBytes)`,
     * because an unprobed family-derived ceiling is an assumption and an assumption must not raise a size
     * the caller configured; once a probe has confirmed a size, [ceiling] is the fragmentation point
     * outright. Both rules are on `SctpConfig.pathMtu`.
     *
     * **Nothing is required of the driver.** This is an observation — the association has already applied
     * it. It exists because the alternative is invisible: a session whose MTU was black-holed and a
     * session whose peer went quiet look identical from outside, and a session that quietly halved its
     * fragment size after a network change has no other way of saying so.
     */
    public data class PathMtuChanged(
        /** What the path admits per DATA chunk of user data. */
        public val ceiling: FragmentCeilingBytes,
        /** Which of the three events this was — they call for different reactions; see the type. */
        public val cause: PathMtuChangeCause,
        /**
         * DATA chunks already encoded above the new ceiling, if any. Classic SCTP assigns a TSN at enqueue
         * and retains the encoded packet, so these cannot be re-fragmented: they are skipped via RFC 3758
         * FORWARD-TSN where the peer supports it, and where it does not they cannot be skipped at all.
         * Always [OversizedBacklog.None] when the ceiling went up.
         */
        public val backlog: OversizedBacklog,
    ) : SctpOutput
}

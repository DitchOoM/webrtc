package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.ReadBuffer

/**
 * An input to the sans-io [SctpAssociation] (ARCHITECTURE §5.1). The driver owns I/O and the clock; it feeds
 * these and applies the returned [SctpOutput]s. Every `handle(event, now)` call carries `now` — the
 * core never reads a clock — so the whole association (handshake, RTO/T3-rtx, delayed SACK, shutdown)
 * runs under `runTest` virtual time on every platform.
 */
public sealed interface SctpEvent {
    /**
     * Begin the association as the active opener (RFC 4960 §5.1): emit an INIT and enter `CookieWait`.
     * In WebRTC the DTLS client drives this (RFC 8831 §6). Idempotent-guarded: ignored unless closed.
     */
    public data object Associate : SctpEvent

    /**
     * An SCTP packet arrived from the transport below (DTLS in production, the plaintext vnet seam in
     * tests). [payload] is a borrowed view valid only for this call — the core copies anything it must
     * retain (reassembly, cookie). Non-SCTP / malformed bytes are dropped as a typed reject internally,
     * never a throw (T0 discipline).
     */
    public data class DatagramReceived(
        public val payload: ReadBuffer,
    ) : SctpEvent

    /**
     * The upper layer (a DataChannel / DCEP) wants to send [payload] as one user message, fragmented
     * as needed, per [options]. [payload] is borrowed for this call only; the association copies what it
     * queues. Rejected (no output) unless the association is `Established`.
     */
    public data class SendMessage(
        public val options: SctpSendOptions,
        public val payload: ReadBuffer,
    ) : SctpEvent

    /**
     * Reset this endpoint's **outgoing** streams (RFC 6525 §4.1) — which is how RFC 8831 §6.7 closes a
     * data channel: the closing side resets its outgoing stream, the peer sees the incoming reset and
     * resets its own outgoing half, and the channel is closed once both directions have been reset.
     *
     * Queued, not immediate: RFC 6525 §5.1.2 allows only one outstanding request at a time, so a reset
     * asked for while another is in flight is accumulated and sent when that one is answered. The result
     * arrives as an [SctpOutput.OutgoingStreamsReset] — including when the peer cannot do it at all
     * ([StreamResetOutcome.Unsupported]), so a caller waiting on the close is never left without an answer.
     *
     * The upper layer must have stopped sending on these streams before asking: the request names the
     * last TSN assigned at the moment it goes out, and data queued after that is data the peer will
     * deliver on a stream whose SSN state has already been reset out from under it.
     */
    public data class ResetStreams(
        public val scope: StreamResetScope,
    ) : SctpEvent

    /** Begin a graceful shutdown (RFC 4960 §9.2): drain outstanding data, then SHUTDOWN handshake. */
    public data object Shutdown : SctpEvent

    /** Abort the association immediately (RFC 4960 §9.1): emit ABORT and close. */
    public data object Abort : SctpEvent

    /**
     * The layer below moved, or named itself for the first time — RFC 8261 §6.1: *"If the SCTP layer is
     * notified about a path change by its lower layers, SCTP SHOULD retest the path MTU and reset the
     * congestion state to the initial state."* **Nothing could say this before**, which is the gap this
     * event closes: after an RFC 8445 §9 ICE restart moved the 5-tuple, the association carried the
     * retired path's cwnd, ssthresh and SRTT, a T3 armed from a backed-off RTO, and a
     * consecutive-error budget that a migration performed *because* the old path was failing had already
     * half spent.
     *
     * **One event, not two.** "The path was assessed for the first time" and "the path migrated" are the
     * same notification with different histories, and the association is the only party that knows which
     * it is — it holds the previous [SctpPathProfile]. Splitting them would have made every driver
     * responsible for a distinction it has to re-derive, and a driver that got it wrong would reset a
     * healthy path's congestion state on the first packet of every session.
     *
     * [SctpPathProfile.Assessed.identity] is the whole discriminant. An identity equal to the current one
     * is a re-statement — the profile is adopted and nothing is discarded — which is what lets a session
     * layer republish on every ICE event without having to filter first.
     *
     * Delivering this is **optional**: an association that never receives one stays
     * [SctpPathProfile.Unassessed] and behaves exactly as it did before the event existed.
     */
    public data class PathChanged(
        public val path: SctpPathProfile.Assessed,
    ) : SctpEvent

    /** The driver's timer reached [SctpAssociation.nextDeadline] — run every retransmit/SACK/timer due now. */
    public data object TimerFired : SctpEvent
}

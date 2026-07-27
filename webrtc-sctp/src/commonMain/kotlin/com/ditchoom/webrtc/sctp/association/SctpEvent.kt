package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.ReadBuffer

/**
 * An input to the sans-io [SctpAssociation] (RFC §5.1). The driver owns I/O and the clock; it feeds
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

    /** The driver's timer reached [SctpAssociation.nextDeadline] — run every retransmit/SACK/timer due now. */
    public data object TimerFired : SctpEvent
}

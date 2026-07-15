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

    /** Begin a graceful shutdown (RFC 4960 §9.2): drain outstanding data, then SHUTDOWN handshake. */
    public data object Shutdown : SctpEvent

    /** Abort the association immediately (RFC 4960 §9.1): emit ABORT and close. */
    public data object Abort : SctpEvent

    /** The driver's timer reached [SctpAssociation.nextDeadline] — run every retransmit/SACK/timer due now. */
    public data object TimerFired : SctpEvent
}

@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import kotlin.time.Duration
import kotlin.time.ExperimentalTime

/**
 * The reliability policy for one outbound SCTP user message (RFC 3758 partial reliability, as surfaced
 * by RFC 8831 §6.4 data-channel semantics). A **sealed** set so a `when` is exhaustive: a message is
 * either fully reliable, or abandoned after a bound on retransmissions or on elapsed time. Modeling it
 * as a type — not a `maxRetransmits: Int?` + `maxLifetime: Duration?` nullable pair, which could encode
 * the illegal "both set" (RFC 8831 forbids setting both) — makes that combination unrepresentable
 * (DESIGN_PRINCIPLES §4).
 */
public sealed interface SctpReliability {
    /** Every fragment is retransmitted until acknowledged (a `DATA_CHANNEL_RELIABLE` channel). */
    public data object Reliable : SctpReliability

    /**
     * The message is abandoned once any of its fragments has been retransmitted [maxRetransmits] times
     * without being acknowledged (RFC 3758; `DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT`).
     */
    public data class MaxRetransmits(
        public val maxRetransmits: Int,
    ) : SctpReliability

    /**
     * The message is abandoned once [maxLifetime] has elapsed since it was first handed to the
     * association, regardless of retransmission count (RFC 3758; `DATA_CHANNEL_PARTIAL_RELIABLE_TIMED`).
     */
    public data class MaxLifetime(
        public val maxLifetime: Duration,
    ) : SctpReliability
}

/**
 * How one outbound user message is delivered: its [streamId], whether it is [unordered], its
 * [reliability] policy, and the [payloadProtocolId] the peer sees (RFC 8831 §6.6 — DCEP control vs.
 * string vs. binary). The message bytes ride the [SctpEvent.SendMessage] event; this is the metadata.
 */
public data class SctpSendOptions(
    public val streamId: com.ditchoom.webrtc.sctp.StreamId,
    public val payloadProtocolId: com.ditchoom.webrtc.sctp.PayloadProtocolId,
    public val unordered: Boolean = false,
    public val reliability: SctpReliability = SctpReliability.Reliable,
)

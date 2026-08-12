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
 * Who queued a message: the application, or the data-channel protocol itself.
 *
 * It exists for one number. W3C's `bufferedAmount` is *"the number of bytes of application data that have
 * been queued using send()"*, and RFC 8832's DCEP OPEN and ACK are not application data — they are this
 * stack's own control traffic on the same stream. A gauge that counted them would tick up on a channel the
 * application has never sent a byte on, and an `awaitBufferedAmountLow(ZERO)` would then be waiting on
 * protocol chatter it cannot see, has no control over, and did not cause.
 *
 * An enum rather than a sealed hierarchy: neither case carries data, the set is closed by what can put a
 * chunk on a data channel at all, and the discriminant IS the whole fact (DESIGN_PRINCIPLES §3).
 */
public enum class SendOrigin {
    /** A message the application handed to `send()`. Counted by `bufferedAmount`. */
    Application,

    /** The stack's own RFC 8832 DCEP traffic. Queued, fragmented and retransmitted alike — just not counted. */
    Control,
}

/**
 * How one outbound user message is delivered: its [streamId], its [delivery] order, its [reliability]
 * policy, the [payloadProtocolId] the peer sees (RFC 8831 §6.6 — DCEP control vs. string vs. binary), and
 * whose message it is ([origin]). The message bytes ride the [SctpEvent.SendMessage] event; this is the
 * metadata.
 */
public data class SctpSendOptions(
    public val streamId: com.ditchoom.webrtc.sctp.StreamId,
    public val payloadProtocolId: com.ditchoom.webrtc.sctp.PayloadProtocolId,
    public val delivery: com.ditchoom.webrtc.sctp.DeliveryOrder = com.ditchoom.webrtc.sctp.DeliveryOrder.Ordered,
    public val reliability: SctpReliability = SctpReliability.Reliable,
    /**
     * Defaults to [SendOrigin.Application], so a caller driving this module directly gets its sends counted
     * — which is what a caller who has not heard of this parameter means. Only the DCEP path opts out, and
     * it is inside this module.
     */
    public val origin: SendOrigin = SendOrigin.Application,
)

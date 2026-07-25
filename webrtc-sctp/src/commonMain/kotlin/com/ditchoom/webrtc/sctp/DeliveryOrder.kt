package com.ditchoom.webrtc.sctp

/**
 * Whether a data channel's messages are delivered in send order, or as soon as they arrive.
 *
 * A two-value type rather than a boolean, for the same reason [com.ditchoom.webrtc.sctp.datachannel.SctpRole]
 * is one (DESIGN_PRINCIPLES §3): the boolean spelling of this concept existed at two layers with
 * **opposite polarity** — `DataChannelConfig.ordered` above and `SctpSendOptions.unordered` below — and
 * the bridge between them was a bare `unordered = !config.ordered`. One inverted call site is a silent
 * correctness bug that no type would have caught. There is exactly one spelling now, and it reads the
 * same at every layer.
 *
 * This is the *channel's* delivery contract, not the wire bit. The SCTP `U` flag on an individual DATA
 * chunk stays a boolean on [DataChunkFlags] — that one really is a single bit in a flags octet, and
 * `U` is its name in RFC 4960 §3.3.1.
 *
 * Note that [Ordered] is a strictly stronger guarantee than [Unordered]: sending an [Unordered]
 * channel's messages in order is always permitted, which is what lets RFC 8832 §6 require exactly that
 * before a channel has been confirmed by the peer.
 */
public enum class DeliveryOrder {
    /**
     * Messages are delivered to the peer's application in send order (SCTP `U` bit clear, DCEP channel
     * type `DATA_CHANNEL_RELIABLE` / `…_PARTIAL_RELIABLE_*`). The default: it is what a caller who has
     * not thought about ordering almost always means.
     */
    Ordered,

    /**
     * Messages are delivered as they arrive, so a later message may overtake an earlier one that is
     * still being retransmitted (SCTP `U` bit set, DCEP channel type `…_UNORDERED`). Removes
     * head-of-line blocking at the cost of any sequencing guarantee.
     */
    Unordered,
}

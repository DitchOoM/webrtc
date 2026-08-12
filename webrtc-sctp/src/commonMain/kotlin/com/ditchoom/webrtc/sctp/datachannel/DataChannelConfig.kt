package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.webrtc.sctp.DeliveryOrder
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.association.SctpReliability

/**
 * The role this endpoint plays in the SCTP association and the DCEP stream-id split (RFC 8832 §6): the
 * DTLS **client** opens the association and owns **even** stream identifiers; the DTLS **server** is
 * passive and owns **odd** ones. Modeling it as a two-value enum (not a boolean) keeps call sites
 * self-documenting (DESIGN_PRINCIPLES §3).
 */
public enum class SctpRole {
    /** DTLS client: sends the INIT, uses even DCEP stream ids (RFC 8832 §6). */
    Client,

    /** DTLS server: passive opener, uses odd DCEP stream ids (RFC 8832 §6). */
    Server,
}

/**
 * How a data channel's stream id is agreed on (RFC 8832 §5): in band, through a DATA_CHANNEL_OPEN, or
 * out of band by an application that already knows which id both peers will use.
 *
 * Sealed rather than a nullable `id: StreamId?`, because the two are not "an id or the absence of one" —
 * they are two different **protocols**. [InBand] sends a DCEP OPEN, waits for the peer to register the
 * channel, and is bound by RFC 8832 §6's rule that user data stays ordered until the channel is
 * confirmed. [Negotiated] sends nothing at all and is usable immediately, because the peer created its
 * half independently. A null standing for the first would leave the id field looking like an optional
 * hint on one code path.
 */
public sealed interface ChannelIdentity {
    /** The stream id is this endpoint's to choose, and the peer learns it from a DCEP OPEN. */
    public data object InBand : ChannelIdentity

    /**
     * The application chose [id] out of band and has created — or will create — the matching channel on
     * the peer. No DCEP OPEN is sent or expected, so nothing about the channel is negotiated on the wire.
     *
     * The id is claimed the moment the open reaches the drive loop, before anything can be dispatched, so
     * no automatically-allocated channel and no peer OPEN can take it. Whether it fits the association's
     * negotiated stream count is a separate question answered later — at open time there may be no
     * association yet, and therefore no count to check it against.
     */
    public data class Negotiated(
        public val id: StreamId,
    ) : ChannelIdentity
}

/**
 * The negotiated properties of one data channel (RFC 8832 §5.1 DATA_CHANNEL_OPEN). [delivery] and
 * [reliability] map straight onto the DCEP Channel Type + Reliability Parameter; [label] and [protocol]
 * are the UTF-8 identifiers the peer sees. This is the value carried in a DATA_CHANNEL_OPEN and
 * reconstructed from one on the receiving side.
 */
public data class DataChannelConfig(
    public val label: String = "",
    public val protocol: String = "",
    public val delivery: DeliveryOrder = DeliveryOrder.Ordered,
    public val reliability: SctpReliability = SctpReliability.Reliable,
    /** DCEP scheduling priority (RFC 8832 §5.1) — opaque to this subset; carried through verbatim. */
    public val priority: UShort = 0u,
    /**
     * Whether this channel's stream id is chosen here and announced with a DCEP OPEN, or agreed out of
     * band (RFC 8832 §5). Only [ChannelIdentity.InBand] puts anything on the wire, and only it is
     * reconstructed from a peer's OPEN — a channel arriving from the peer is by definition in band.
     */
    public val identity: ChannelIdentity = ChannelIdentity.InBand,
)

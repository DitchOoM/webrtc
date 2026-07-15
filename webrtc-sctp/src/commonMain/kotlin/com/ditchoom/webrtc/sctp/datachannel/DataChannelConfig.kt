package com.ditchoom.webrtc.sctp.datachannel

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
 * The negotiated properties of one data channel (RFC 8832 §5.1 DATA_CHANNEL_OPEN). [ordered] and
 * [reliability] map straight onto the DCEP Channel Type + Reliability Parameter; [label] and [protocol]
 * are the UTF-8 identifiers the peer sees. This is the value carried in a DATA_CHANNEL_OPEN and
 * reconstructed from one on the receiving side.
 */
public data class DataChannelConfig(
    public val label: String = "",
    public val protocol: String = "",
    public val ordered: Boolean = true,
    public val reliability: SctpReliability = SctpReliability.Reliable,
    /** DCEP scheduling priority (RFC 8832 §5.1) — opaque to this subset; carried through verbatim. */
    public val priority: UShort = 0u,
)

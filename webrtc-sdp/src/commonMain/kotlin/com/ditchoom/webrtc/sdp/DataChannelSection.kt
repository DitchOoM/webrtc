package com.ditchoom.webrtc.sdp

/**
 * Which media section of a [SessionDescription] carries the data channel, as an answer rather than a
 * nullable.
 *
 * Every SCTP attribute this stack reads — `a=sctp-port` (RFC 8841 §5.1), `a=max-message-size` (§6) — is
 * **media-level only**, so reading one means first deciding *which* `m=` section describes the SCTP
 * association. Today there is exactly one and it is first, which is why `mediaDescriptions.firstOrNull()`
 * has worked; the moment a description carries `m=audio` ahead of it, that call returns a real, plausible
 * section whose attributes belong to something else. The failure is a **wrong number**, not a visible
 * miss — `a=max-message-size` absent from an audio section reads as "the peer advertised nothing", which
 * has a defined and generous meaning (RFC 8831 §6.6's 64 KiB), so the mistake presents as a peer that
 * silently accepts less than it does.
 *
 * One helper, one answer, one place to change when Phase 2 adds media sections. It is deliberately
 * **not** a nullable [MediaDescription]: "there is no data channel in this description" is a real state a
 * caller has to handle (a peer negotiating media only), and a `?:` at each call site is where a default
 * gets invented locally and inconsistently.
 */
public sealed interface DataChannelSection {
    /** The `m=application … webrtc-datachannel` section (RFC 8841 §4) this description carries. */
    public data class Present(
        public val media: MediaDescription,
    ) : DataChannelSection

    /**
     * No section in this description is a data channel. Distinct from a data-channel section that
     * *omits* an attribute: nothing here made any statement about SCTP at all, so RFC 8831 §6.6's
     * assumed default does not apply — there is no association for it to be a default of.
     */
    public data object Absent : DataChannelSection
}

/**
 * The data-channel media section of this description (RFC 8841 §4: `m=application … UDP/DTLS/SCTP`), or
 * [DataChannelSection.Absent].
 *
 * Selected by the `m=` line's own [MediaLine.isDataChannel] — media type **and** transport protocol,
 * which is what accepts a peer still emitting the legacy `DTLS/SCTP` proto — never by position. The
 * first such section wins if a description somehow carries two, matching every other reader in this
 * module; a description with two SCTP associations is not something JSEP produces.
 */
public fun SessionDescription.dataChannelSection(): DataChannelSection {
    val media = mediaDescriptions.firstOrNull { it.mediaLine()?.isDataChannel == true }
    return if (media == null) DataChannelSection.Absent else DataChannelSection.Present(media)
}

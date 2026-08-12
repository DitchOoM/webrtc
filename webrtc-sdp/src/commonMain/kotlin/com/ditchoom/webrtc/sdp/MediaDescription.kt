package com.ditchoom.webrtc.sdp

/**
 * One media section of an SDP document (RFC 8866 §5.14): the `m=` line ([media]) plus every line up
 * to the next `m=` or end of document ([lines], which excludes the `m=` itself). Round-trip-faithful —
 * the lines are kept verbatim; the typed readers below interpret them on demand.
 *
 * For Phase 1 the only media section is the data channel (`m=application … webrtc-datachannel`); the
 * SCTP-specific readers ([sctpPort], [maxMessageSizeAttribute]) and the trickle-ICE readers
 * ([candidates], [hasEndOfCandidates]) cover the JSEP data-channel attributes (RFC 8841 / RFC 8839).
 */
public class MediaDescription internal constructor(
    /** The verbatim `m=` line (its [SdpLine.type] is always `'m'`). */
    public val media: SdpLine,
    override val lines: List<SdpLine>,
) : SdpSection {
    /** The typed `m=` line, or null if it is malformed (fewer than 4 fields). */
    public fun mediaLine(): MediaLine? = MediaLine.parse(media.value)

    /** The media-section identifier (`a=mid`, RFC 5888), or null if absent/blank. */
    public fun mid(): Mid? = firstAttributeValue("mid")?.takeIf { it.isNotBlank() }?.let(::Mid)

    /** The SCTP association port (`a=sctp-port`, RFC 8841 §5.1), or null if absent/non-numeric. */
    public fun sctpPort(): Int? = firstAttributeValue("sctp-port")?.toIntOrNull()

    /**
     * The max SCTP message size in bytes (`a=max-message-size`, RFC 8841 §6), or null.
     *
     * **Superseded by [maxMessageSizeAttribute]**, which is the same read with the answers separated.
     * This one returns a `Long?` that means four things: `null` is both "no attribute" (RFC 8831 §6.6's
     * defined 64 KiB default) and "present but unreadable", and `0` is RFC 8841 §6's *no limit* wearing
     * the numeral a caller will compare as the tightest ceiling there is. Kept — and kept working —
     * because a `Long?` cannot be widened into a sealed type source-compatibly.
     */
    @Deprecated(
        "A Long? cannot tell absent (RFC 8831 §6.6's defined default) from malformed, and returns " +
            "RFC 8841 §6's no-limit as a literal 0. Use maxMessageSizeAttribute().",
    )
    public fun maxMessageSize(): Long? = firstAttributeValue("max-message-size")?.toLongOrNull()

    /**
     * The trickle-ICE candidate lines (`a=candidate`, RFC 8839 §5.1) as **raw strings** — the ICE
     * layer owns candidate parsing; SDP only carries them. Order is preserved.
     */
    public fun candidates(): List<String> = attributeValues("candidate")

    /** True if this section declared its candidate list complete (`a=end-of-candidates`, RFC 8838 §4.1). */
    public fun hasEndOfCandidates(): Boolean = hasFlag("end-of-candidates")

    /** True if this section is BUNDLE-only (`a=bundle-only`, RFC 9143 §6) — no independent transport. */
    public fun isBundleOnly(): Boolean = hasFlag("bundle-only")
}

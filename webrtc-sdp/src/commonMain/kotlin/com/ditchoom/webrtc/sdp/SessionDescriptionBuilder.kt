package com.ditchoom.webrtc.sdp

/**
 * Assembles a [SessionDescription] programmatically (the write side of the codec). It is a thin,
 * order-preserving line builder — every convenience method appends a verbatim [SdpLine], so what you
 * add is exactly what [SessionDescription.toText] emits, and a built document round-trips through
 * [SessionDescription.parse] unchanged. Lines added before the first [media] block are session-level;
 * media-section lines are added inside a [media] block via [MediaSectionBuilder].
 *
 * This is where the JSEP layer builds offers/answers ([JsepSession] / [dataChannelOffer]); the ICE and
 * DTLS parameters it stamps (ufrag, pwd, fingerprint, setup) are supplied by those layers — SDP only
 * lays them out.
 */
public class SessionDescriptionBuilder {
    private val sessionLines = mutableListOf<SdpLine>()
    private val mediaSections = mutableListOf<MediaDescription>()

    /** Appends a raw session-level line. */
    public fun line(
        type: Char,
        value: String,
    ): SessionDescriptionBuilder {
        sessionLines += SdpLine(type, value)
        return this
    }

    /** `v=0` (RFC 8866 §5.1) — the required first line. */
    public fun version(): SessionDescriptionBuilder = line('v', Sdp.SUPPORTED_VERSION)

    /** `o=…` origin (RFC 8866 §5.2). */
    public fun origin(origin: Origin): SessionDescriptionBuilder = line('o', origin.toValue())

    /** `s=…` session name (RFC 8866 §5.3); defaults to `-`, the JSEP convention (RFC 8829 §5.2.1). */
    public fun sessionName(name: String = "-"): SessionDescriptionBuilder = line('s', name)

    /** `t=<start> <stop>` timing (RFC 8866 §5.9); defaults to `0 0`, the JSEP convention. */
    public fun timing(
        start: Long = 0,
        stop: Long = 0,
    ): SessionDescriptionBuilder = line('t', "$start $stop")

    /** A session-level attribute line `a=<name>` or `a=<name>:<value>`. */
    public fun attribute(
        name: String,
        value: String? = null,
    ): SessionDescriptionBuilder = line('a', if (value == null) name else "$name:$value")

    /** `a=group:BUNDLE <mid>…` (RFC 9143 §7). */
    public fun bundle(mids: List<Mid>): SessionDescriptionBuilder =
        attribute("group", "${Sdp.GROUP_BUNDLE} ${mids.joinToString(" ") { it.value }}")

    /** Adds a media section built by [block]. */
    public fun media(
        mediaValue: String,
        block: MediaSectionBuilder.() -> Unit,
    ): SessionDescriptionBuilder {
        mediaSections += MediaSectionBuilder(mediaValue).apply(block).build()
        return this
    }

    public fun build(): SessionDescription = SessionDescription(sessionLines.toList(), mediaSections.toList())
}

/** Builds one media section for [SessionDescriptionBuilder.media]. Lines are emitted in the order added. */
public class MediaSectionBuilder internal constructor(
    private val mediaValue: String,
) {
    private val lines = mutableListOf<SdpLine>()

    /** Appends a raw line inside this media section. */
    public fun line(
        type: Char,
        value: String,
    ): MediaSectionBuilder {
        lines += SdpLine(type, value)
        return this
    }

    /** A media-section attribute line `a=<name>` or `a=<name>:<value>`. */
    public fun attribute(
        name: String,
        value: String? = null,
    ): MediaSectionBuilder = line('a', if (value == null) name else "$name:$value")

    /** `c=<nettype> <addrtype> <address>` connection (RFC 8866 §5.7). */
    public fun connection(value: String = "IN IP4 0.0.0.0"): MediaSectionBuilder = line('c', value)

    /** `a=mid:<id>` (RFC 5888). */
    public fun mid(mid: Mid): MediaSectionBuilder = attribute("mid", mid.value)

    /** `a=ice-ufrag:<u>` (RFC 8839 §5.4). */
    public fun iceUfrag(ufrag: String): MediaSectionBuilder = attribute("ice-ufrag", ufrag)

    /** `a=ice-pwd:<p>` (RFC 8839 §5.4). */
    public fun icePwd(pwd: String): MediaSectionBuilder = attribute("ice-pwd", pwd)

    /** `a=setup:<role>` (RFC 8842). */
    public fun setup(role: SetupRole): MediaSectionBuilder = attribute("setup", role.token)

    /** `a=fingerprint:<hash-func> <hex>` (RFC 8122 §5). */
    public fun fingerprint(fingerprint: Fingerprint): MediaSectionBuilder =
        attribute("fingerprint", "${fingerprint.hashFunction} ${fingerprint.value}")

    /** `a=sctp-port:<port>` (RFC 8841 §5.1). */
    public fun sctpPort(port: Int): MediaSectionBuilder = attribute("sctp-port", port.toString())

    /** `a=max-message-size:<bytes>` (RFC 8841 §6). */
    public fun maxMessageSize(bytes: Long): MediaSectionBuilder = attribute("max-message-size", bytes.toString())

    internal fun build(): MediaDescription = MediaDescription(SdpLine('m', mediaValue), lines.toList())
}

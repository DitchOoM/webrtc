package com.ditchoom.webrtc.sdp

/**
 * A parsed media description line (`m=<media> <port> <proto> <fmt> …`, RFC 8866 §5.14). For a WebRTC
 * data channel this is `m=application 9 UDP/DTLS/SCTP webrtc-datachannel` (RFC 8841 §4).
 *
 * [port] stays a string: RFC 8866 permits a `<port>/<number-of-ports>` form, and JSEP uses port `0`
 * to reject an m-section and `9` (discard) with `a=bundle-only` — all of which a bare `Int` would
 * either lose or throw on. [formats] preserves order (for RTP the payload-type preference order is
 * significant; for a data channel it is the single `webrtc-datachannel` token). [parse] is total and
 * null-on-malformed — it never throws on a broken `m=`.
 */
public data class MediaLine(
    public val media: String,
    public val port: String,
    public val proto: String,
    public val formats: List<String>,
) {
    /** True if this is a data-channel transport (`UDP/DTLS/SCTP` or the legacy `DTLS/SCTP`). */
    public val isDataChannel: Boolean
        get() = media == APPLICATION_MEDIA && (proto == Sdp.PROTO_UDP_DTLS_SCTP || proto == LEGACY_DTLS_SCTP)

    /** Serializes back to the `m=` line value (space-joined), exactly as [parse] consumed it. */
    public fun toValue(): String = (listOf(media, port, proto) + formats).joinToString(" ")

    public companion object {
        private const val MIN_FIELDS = 4 // media, port, proto, and at least one format (RFC 8866 §5.14)

        /** The `application` media type carrying a data channel (RFC 8841 §4). */
        public const val APPLICATION_MEDIA: String = "application"

        /** Pre-RFC-8841 data-channel proto, still emitted by some peers; accepted, never emitted. */
        public const val LEGACY_DTLS_SCTP: String = "DTLS/SCTP"

        /** Parses an `m=` line value into a [MediaLine], or null if it has fewer than 4 fields. */
        public fun parse(value: String): MediaLine? {
            val f = value.split(' ')
            if (f.size < MIN_FIELDS) return null
            return MediaLine(f[0], f[1], f[2], f.subList(3, f.size).toList())
        }
    }
}

package com.ditchoom.webrtc.sdp

/**
 * SDP protocol constants (RFC 8866) and the JSEP usage tokens (RFC 8829). The line/session codecs
 * live in [SdpLine], [SessionDescription], and [MediaDescription]; the sans-io offer/answer machine
 * in [JsepSession].
 *
 * SDP is a **text** protocol, so unlike the binary [com.ditchoom.webrtc.stun] codec there is no TLV
 * framing — the wire unit is a `<type>=<value>` line (RFC 8866 §5). The parse floor holds the same
 * T0 rigor: [SessionDescription.parse] is total (a hostile datagram yields a typed
 * [SdpRejectReason], never a throw), round-trips byte-for-byte for canonical CRLF input, and every
 * typed field interpreter is null-on-malformed rather than throwing.
 */
public object Sdp {
    public const val MODULE: String = "webrtc-sdp"

    /** The line terminator SDP is serialized with (RFC 8866 §5: each line ends CRLF). */
    public const val CRLF: String = "\r\n"

    /** The only SDP version this codec emits or accepts (RFC 8866 §5.1: `v=0`). */
    public const val SUPPORTED_VERSION: String = "0"

    /**
     * The `m=application` media transport for a WebRTC data channel over DTLS/SCTP (RFC 8841 §4 /
     * the JSEP data-channel convention): `m=application <port> UDP/DTLS/SCTP webrtc-datachannel`.
     */
    public const val PROTO_UDP_DTLS_SCTP: String = "UDP/DTLS/SCTP"

    /** The data-channel format token that follows the DTLS/SCTP proto (RFC 8841 §4). */
    public const val DATA_CHANNEL_FMT: String = "webrtc-datachannel"

    /** The `a=group` semantics token for BUNDLE (RFC 9143): one 5-tuple for every m-section. */
    public const val GROUP_BUNDLE: String = "BUNDLE"
}

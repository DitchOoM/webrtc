package com.ditchoom.webrtc.sdp

/**
 * The parameters needed to lay out a data-channel `m=application` section (RFC 8841 + the JSEP
 * data-channel convention). The ICE and DTLS values ([iceUfrag], [icePwd], [fingerprint], [setup])
 * are produced by the ICE and DTLS layers — out of scope for this module; SDP only carries
 * them. The SCTP values default to the JSEP/browser norms.
 */
public data class DataChannelParameters(
    public val iceUfrag: String,
    public val icePwd: String,
    public val fingerprint: Fingerprint,
    public val setup: SetupRole,
    public val mid: Mid = Mid("0"),
    public val sctpPort: Int = DEFAULT_SCTP_PORT,
    public val maxMessageSize: Long = DEFAULT_MAX_MESSAGE_SIZE,
    public val bundle: Boolean = true,
    public val port: String = DISCARD_PORT,
    public val connection: String = DEFAULT_CONNECTION,
    public val trickle: Boolean = true,
    /**
     * This endpoint's DTLS association identifier (`a=tls-id`, RFC 8842 §5.3), or null to emit no such
     * line. Null is a genuine absence, not an error or an uninitialized field: the attribute is optional,
     * a description without one is what every peer in this stack's interop matrix sends, and a reader
     * falls back to inferring association continuity from the unchanged `a=fingerprint` (§5.5). It
     * defaults to null so that adding the attribute cannot change the bytes an existing caller emits.
     *
     * The value must be **stable for the life of the association** — the same one in a re-offer, an
     * answer, and across an ICE restart. Changing it is how an endpoint says it wants a *new* DTLS
     * association, so a caller that regenerates it per offer is unwittingly asking for a fresh handshake.
     */
    public val tlsId: TlsId? = null,
) {
    public companion object {
        /** RFC 8831 §5: the default SCTP port for a data channel. */
        public const val DEFAULT_SCTP_PORT: Int = 5000

        /** The JSEP/browser default `a=max-message-size` (256 KiB, RFC 8841 §6). */
        public const val DEFAULT_MAX_MESSAGE_SIZE: Long = 262144

        /** The `m=` port a JSEP offer uses before candidates are known (discard, RFC 8829 §5.2.1). */
        public const val DISCARD_PORT: String = "9"

        /** The dummy connection line a JSEP offer uses (RFC 8829 §5.2.1). */
        public const val DEFAULT_CONNECTION: String = "IN IP4 0.0.0.0"
    }
}

/**
 * Builds a complete data-channel [SessionDescription] (RFC 8829 §5.2.1 shape): the `v/o/s/t` session
 * block with an optional BUNDLE group, then one `m=application … webrtc-datachannel` section carrying
 * the ICE/DTLS/SCTP attributes from [params]. Pure and deterministic given its inputs — the entropy
 * (the [sessionId]) is generated upstream by the injected seam ([JsepSession.createOffer]). Round-trips
 * through [SessionDescription.parse] unchanged.
 */
public fun dataChannelDescription(
    params: DataChannelParameters,
    sessionId: String,
    sessionVersion: Long,
): SessionDescription {
    val builder =
        SessionDescriptionBuilder()
            .version()
            .origin(Origin("-", sessionId, sessionVersion.toString(), "IN", "IP4", "127.0.0.1"))
            .sessionName()
            .timing()
    if (params.bundle) builder.bundle(listOf(params.mid))
    builder.media("${MediaLine.APPLICATION_MEDIA} ${params.port} ${Sdp.PROTO_UDP_DTLS_SCTP} ${Sdp.DATA_CHANNEL_FMT}") {
        connection(params.connection)
        iceUfrag(params.iceUfrag)
        icePwd(params.icePwd)
        if (params.trickle) attribute("ice-options", "trickle")
        fingerprint(params.fingerprint)
        setup(params.setup)
        // Media level, beside the other DTLS parameters it qualifies. RFC 8842 §5.3 allows either level;
        // with BUNDLE there is one transport, and a reader here reads media-then-session (SdpSection.tlsId).
        params.tlsId?.let { tlsId(it) }
        mid(params.mid)
        sctpPort(params.sctpPort)
        maxMessageSize(params.maxMessageSize)
    }
    return builder.build()
}

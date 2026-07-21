package com.ditchoom.webrtc

/**
 * A STUN/TURN server the ICE agent may use to gather server-reflexive and relay candidates (W3C
 * `RTCIceServer`). [urls] are `stun:`/`turn:`/`turns:` URLs (one entry may carry several, per the W3C
 * shape); [username] and [credential] authenticate a TURN allocation (RFC 8656 long-term credential) and
 * are absent for a plain STUN server.
 *
 * Unlike a bare URL list, this carries the TURN credential — without it a relay candidate cannot be
 * allocated, so a peer behind a symmetric NAT (where srflx fails) has no path. Both the browser-delegated
 * `RTCPeerConnection` ([PeerConnectionSupport.BrowserDelegated.create]) and the native default factory
 * build their ICE configuration from these.
 */
public data class IceServer(
    public val urls: List<String>,
    public val username: String? = null,
    public val credential: String? = null,
) {
    /** Convenience for a single-URL server (the common case). */
    public constructor(
        url: String,
        username: String? = null,
        credential: String? = null,
    ) : this(listOf(url), username, credential)
}

package com.ditchoom.webrtc.ice

/**
 * How (or whether) a TURN allocation on an [IceServer] is authenticated.
 *
 * Sealed rather than a nullable `username`/`credential` pair, because that pair could spell states that
 * do not exist: a username with no credential, or a credential with no username, authenticates nothing.
 * The browser bridges made that concrete — each half was forwarded to `RTCIceServer` independently, so a
 * half-filled pair produced a half-filled browser configuration rather than an error. Here the two
 * halves cannot be separated (DESIGN_PRINCIPLES §3: make illegal states unrepresentable).
 */
public sealed interface IceServerCredentials {
    /** No authentication: a plain `stun:` server, or a TURN server that requires no credential. */
    public data object None : IceServerCredentials

    /** An RFC 8656 long-term credential. Both halves, or neither — never one. */
    public data class LongTerm(
        public val username: String,
        public val credential: String,
    ) : IceServerCredentials
}

/**
 * A STUN/TURN server the ICE agent may use to gather server-reflexive and relay candidates (W3C
 * `RTCIceServer`). [urls] are `stun:` / `turn:` URLs (one entry may carry several, per the W3C shape);
 * [credentials] authenticate a TURN allocation.
 *
 * Unlike a bare URL list, this carries the TURN credential — without it a relay candidate cannot be
 * allocated, so a peer behind a symmetric NAT (where srflx fails) has no path. Both the browser-delegated
 * `RTCPeerConnection` and the native `systemIceGathering()` policy build their ICE configuration from
 * these.
 *
 * **`turns:` is not supported** and is rejected with a typed reason ([IceServerUrl.Unsupported]) rather
 * than dropped: TURN over TLS needs a TCP TURN client, which this stack does not have. It used to be
 * named here as if it worked, which is the shape of promise the type system exists to prevent — a
 * consumer on a UDP-blocked network would have configured it, gathered nothing, and had no way to learn
 * why. See issue #138 for the credential half of the same surface.
 *
 * Lives in `webrtc-ice` rather than `webrtc` because it is an ICE concept and the gathering policy that
 * consumes it ([IceGatheringPolicy]) is built here; `com.ditchoom.webrtc.IceServer` remains as a
 * typealias, so existing call sites are unaffected.
 */
public data class IceServer(
    public val urls: List<String>,
    public val credentials: IceServerCredentials = IceServerCredentials.None,
) {
    /** Convenience for a single-URL server (the common case). */
    public constructor(
        url: String,
        credentials: IceServerCredentials = IceServerCredentials.None,
    ) : this(listOf(url), credentials)

    /** Convenience for a single-URL TURN server with an RFC 8656 long-term credential. */
    public constructor(
        url: String,
        username: String,
        credential: String,
    ) : this(listOf(url), IceServerCredentials.LongTerm(username, credential))
}

package com.ditchoom.webrtc.ice

/**
 * Why an [IceServer] URL cannot be gathered on. Sealed and exhaustive (directive 3): a URL we decline is
 * a *typed* outcome a caller can report, never a silent drop — the failure mode this replaces is a
 * consumer configuring `turns:` on a UDP-blocked network, gathering nothing, and having no way to learn
 * why.
 */
public sealed interface IceServerUrlRejection {
    /**
     * `turns:` / `stuns:` — TLS transport (RFC 7064 §3.2, RFC 7065 §3.2). Unsupported because this stack
     * has no TCP TURN client at all, which is a larger gap than a parser can paper over.
     */
    public data object TlsTransportUnsupported : IceServerUrlRejection

    /** `?transport=tcp` (RFC 7065 §3.1). Same reason as [TlsTransportUnsupported]: UDP only, today. */
    public data object TcpTransportUnsupported : IceServerUrlRejection

    /** A scheme that is not `stun:` / `stuns:` / `turn:` / `turns:` at all. */
    public data class UnknownScheme(
        public val scheme: String,
    ) : IceServerUrlRejection

    /** No host between the scheme and the port, or an unclosed `[` on an IPv6 literal. */
    public data object MalformedAuthority : IceServerUrlRejection

    /** A port that is absent after its `:`, non-numeric, signed, or outside 1..65535. */
    public data class InvalidPort(
        public val text: String,
    ) : IceServerUrlRejection

    /** A `?` query that is present but is not the `transport` parameter RFC 7065 §3.1 defines. */
    public data class UnknownQuery(
        public val query: String,
    ) : IceServerUrlRejection
}

/**
 * One parsed entry of [IceServer.urls] — a STUN server, a TURN server, or a typed refusal.
 *
 * The host is left **unresolved** on purpose: resolution needs a socket, and this module's `commonMain`
 * is socket-free by design (ARCHITECTURE §11.6). `systemIceGathering()` resolves it at the platform edge.
 */
public sealed interface IceServerUrl {
    /** The host as written — a literal or a name, never bracketed even when it is an IPv6 literal. */
    public val host: String

    /** The port, defaulted per RFC 7064 §3.2 / RFC 7065 §3.2 when the URL omits it. */
    public val port: Int

    /** A `stun:` server: used for server-reflexive gathering only. */
    public data class Stun(
        override val host: String,
        override val port: Int,
    ) : IceServerUrl

    /** A `turn:` server over UDP: used for relay gathering, and needs a credential to allocate. */
    public data class Turn(
        override val host: String,
        override val port: Int,
    ) : IceServerUrl

    /**
     * A URL this stack declines, with the reason. Carries [host]/[port] as the unusable defaults so the
     * type stays flat; read [reason], not them.
     */
    public data class Unsupported(
        public val url: String,
        public val reason: IceServerUrlRejection,
    ) : IceServerUrl {
        override val host: String get() = ""
        override val port: Int get() = 0
    }
}

private const val DEFAULT_STUN_TURN_PORT = 3478
private const val DEFAULT_TLS_PORT = 5349
private const val MAX_PORT = 65535

/**
 * Parse one ICE-server URL (RFC 7064 for `stun:`, RFC 7065 for `turn:`).
 *
 * These are **not** `scheme://authority` URIs — there is no `//`, no userinfo and no path, so a general
 * URL parser is the wrong tool and would accept shapes the RFCs do not define. The grammar accepted here
 * is exactly: `scheme ":" host [":" port] ["?transport=" ("udp" | "tcp")]`, with an IPv6 literal
 * bracketed per RFC 3986 §3.2.2.
 */
public fun parseIceServerUrl(url: String): IceServerUrl {
    val schemeEnd = url.indexOf(':')
    if (schemeEnd <= 0) return IceServerUrl.Unsupported(url, IceServerUrlRejection.UnknownScheme(url))
    val scheme = url.substring(0, schemeEnd).lowercase()
    val rest = url.substring(schemeEnd + 1)

    val defaultPort =
        when (scheme) {
            "stun", "turn" -> DEFAULT_STUN_TURN_PORT
            "stuns", "turns" -> DEFAULT_TLS_PORT
            else -> return IceServerUrl.Unsupported(url, IceServerUrlRejection.UnknownScheme(scheme))
        }
    if (scheme == "stuns" || scheme == "turns") {
        return IceServerUrl.Unsupported(url, IceServerUrlRejection.TlsTransportUnsupported)
    }

    // The query is split off first: `?transport=` may follow either the host or the port, and leaving it
    // attached would make it part of whichever one came last.
    val queryStart = rest.indexOf('?')
    val authority = if (queryStart < 0) rest else rest.substring(0, queryStart)
    val query = if (queryStart < 0) null else rest.substring(queryStart + 1)

    when (query?.lowercase()) {
        null, "transport=udp" -> Unit
        "transport=tcp" -> return IceServerUrl.Unsupported(url, IceServerUrlRejection.TcpTransportUnsupported)
        else -> return IceServerUrl.Unsupported(url, IceServerUrlRejection.UnknownQuery(query))
    }

    val host: String
    val portText: String?
    if (authority.startsWith('[')) {
        // RFC 3986 §3.2.2: an IPv6 literal is bracketed precisely so its own colons cannot be read as the
        // port separator. Only a colon AFTER the closing bracket introduces a port.
        val close = authority.indexOf(']')
        if (close < 0 || close == 1) return IceServerUrl.Unsupported(url, IceServerUrlRejection.MalformedAuthority)
        host = authority.substring(1, close)
        val after = authority.substring(close + 1)
        portText =
            when {
                after.isEmpty() -> null
                after.startsWith(':') -> after.substring(1)
                else -> return IceServerUrl.Unsupported(url, IceServerUrlRejection.MalformedAuthority)
            }
    } else {
        val colon = authority.indexOf(':')
        host = if (colon < 0) authority else authority.substring(0, colon)
        portText = if (colon < 0) null else authority.substring(colon + 1)
    }
    if (host.isEmpty()) return IceServerUrl.Unsupported(url, IceServerUrlRejection.MalformedAuthority)

    val port =
        if (portText == null) {
            defaultPort
        } else {
            // `toIntOrNull` accepts a leading sign, so "+80" and "-1" would both parse — the digits are
            // checked explicitly rather than trusting it (the same leniency trap PR #37 hit on candidate
            // priorities).
            val parsed = if (portText.isNotEmpty() && portText.all { it in '0'..'9' }) portText.toIntOrNull() else null
            if (parsed == null || parsed !in 1..MAX_PORT) {
                return IceServerUrl.Unsupported(url, IceServerUrlRejection.InvalidPort(portText))
            }
            parsed
        }

    return if (scheme == "stun") IceServerUrl.Stun(host, port) else IceServerUrl.Turn(host, port)
}

/** Every URL of this server, parsed — order preserved, refusals included as [IceServerUrl.Unsupported]. */
public fun IceServer.parseUrls(): List<IceServerUrl> = urls.map { parseIceServerUrl(it) }

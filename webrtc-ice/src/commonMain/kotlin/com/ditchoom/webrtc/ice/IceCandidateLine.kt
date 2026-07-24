package com.ditchoom.webrtc.ice

import com.ditchoom.webrtc.stun.IpAddress
import com.ditchoom.webrtc.stun.TransportAddress

/**
 * The RFC 8839 §5.1 `candidate` attribute codec — the one place an [IceCandidate] crosses to and from
 * the SDP/trickle wire (`candidate:<foundation> <component> <transport> <priority> <addr> <port> typ
 * <type> [raddr <addr> rport <port>]`). It is the bridge the session layer needs so the public
 * `PeerConnection` API can speak the same candidate strings a browser `RTCIceCandidate` does, while our
 * sans-io ICE core keeps its typed [IceCandidate] (the SDP module deliberately carries candidate lines
 * as raw strings and leaves parsing to ICE, per `MediaDescription.candidates`).
 *
 * [format] always emits the `candidate:` prefix (matching `RTCIceCandidate.candidate`); [parse] accepts
 * the value with or without it. Parsing is a **typed reject** — a malformed or unsupported line yields
 * `null`, never a throw (T0 discipline extended to the trickle boundary).
 *
 * Transport scope: UDP only — a non-UDP / TCP-`tcptype` line parses to `null` rather than a lossy
 * coercion. Both IPv4 and IPv6 connection-addresses (RFC 8839 §5.1, raw/unbracketed) are supported.
 */
public object IceCandidateLine {
    private const val PREFIX = "candidate:"
    private const val MIN_TOKENS = 8 // foundation component transport priority addr port "typ" type

    /** Serialize [candidate] as a full `candidate:` attribute value (RFC 8839 §5.1). */
    public fun format(candidate: IceCandidate): String {
        val a = candidate.address
        val head =
            "$PREFIX${candidate.foundation.value} ${candidate.component.value} ${candidate.transport.token} " +
                "${candidate.priority} ${a.ip} ${a.port} typ ${candidate.type.token}"
        val related =
            when (candidate) {
                is IceCandidate.ServerReflexive -> candidate.relatedAddress
                is IceCandidate.PeerReflexive -> candidate.relatedAddress
                is IceCandidate.Relayed -> candidate.relatedAddress
                is IceCandidate.Host -> null
            }
        return if (related == null) head else "$head raddr ${related.ip} rport ${related.port}"
    }

    /**
     * Parse a `candidate:` attribute value (with or without the prefix) into an [IceCandidate], or null —
     * the IP-only view of [parseLine]. An `<uuid>.local` mDNS host candidate (RFC 8838 privacy) is **not**
     * an [IceCandidate] until resolved, so it yields null here; callers that must honour it use [parseLine]
     * + the [MdnsResolver] seam.
     */
    public fun parse(line: String): IceCandidate? = (parseLine(line) as? CandidateParse.Parsed)?.candidate

    /**
     * Parse a `candidate:` attribute value into a [CandidateParse] outcome. Three states, because an
     * `<uuid>.local` mDNS host candidate parses cleanly but is not yet usable — its address must be
     * resolved via the [MdnsResolver] seam before a check can be sent to it (RFC 8838 privacy candidates).
     * Modelling that as a distinct [CandidateParse.MdnsHost] case (rather than an overloaded null) is what
     * lets the session layer `when` over the outcome and route each to the right path.
     */
    public fun parseLine(line: String): CandidateParse {
        val value = line.trim().removePrefix(PREFIX)
        val t = value.split(' ').filter { it.isNotEmpty() }
        if (t.size < MIN_TOKENS || t[6] != "typ") return CandidateParse.Reject

        val foundation = Foundation(t[0])
        val component = componentOf(t[1].toIntOrNull() ?: return CandidateParse.Reject) ?: return CandidateParse.Reject
        if (t[2].lowercase() != IceTransport.Udp.token) return CandidateParse.Reject // phase-1: UDP only
        val priority = t[3].toLongOrNull() ?: return CandidateParse.Reject
        val type = typeOf(t[7]) ?: return CandidateParse.Reject

        // RFC 8838 privacy: a browser obfuscates ONLY its host candidates as `<uuid>.local` (srflx/relay
        // carry real routable IPs). A `.local` connection-address has no IP yet, so it is surfaced as an
        // MdnsHost to be resolved — never coerced through the IP parser (which would reject it).
        if (isMdnsName(t[4])) {
            if (type != CandidateType.Host) return CandidateParse.Reject // only host candidates are obfuscated
            val port = t[5].toIntOrNull() ?: return CandidateParse.Reject
            if (port !in 0..MAX_PORT) return CandidateParse.Reject
            return CandidateParse.MdnsHost(
                hostname = t[4],
                port = port,
                component = component,
                foundation = foundation,
                priority = priority,
            )
        }

        val address = transportAddress(t[4], t[5]) ?: return CandidateParse.Reject
        val candidate = buildCandidate(type, address, component, foundation, priority, relatedAddress(t))
        return if (candidate == null) CandidateParse.Reject else CandidateParse.Parsed(candidate)
    }

    // Assemble the typed [IceCandidate] for a resolved IP address, or null if a required related-address
    // (raddr, RFC 8839 §5.1) is absent for a reflexive/relayed candidate.
    private fun buildCandidate(
        type: CandidateType,
        address: TransportAddress,
        component: ComponentId,
        foundation: Foundation,
        priority: Long,
        related: TransportAddress?,
    ): IceCandidate? =
        when (type) {
            CandidateType.Host ->
                IceCandidate.Host(address, component, IceTransport.Udp, foundation, priority)
            CandidateType.ServerReflexive ->
                IceCandidate.ServerReflexive(
                    address = address,
                    base = related ?: return null, // srflx base == raddr (RFC 8839 §5.1)
                    component = component,
                    transport = IceTransport.Udp,
                    foundation = foundation,
                    priority = priority,
                    relatedAddress = related,
                )
            CandidateType.PeerReflexive ->
                IceCandidate.PeerReflexive(
                    address = address,
                    base = related ?: return null,
                    component = component,
                    transport = IceTransport.Udp,
                    foundation = foundation,
                    priority = priority,
                    relatedAddress = related,
                )
            CandidateType.Relayed ->
                IceCandidate.Relayed(
                    address = address,
                    component = component,
                    transport = IceTransport.Udp,
                    foundation = foundation,
                    priority = priority,
                    relatedAddress = related ?: return null,
                )
        }

    // An `<uuid>.local` mDNS name (RFC 6762) — the only non-IP connection-address ICE accepts. Never
    // contains ':' (so it can't collide with a v6 literal); matched case-insensitively.
    private fun isMdnsName(host: String): Boolean = host.endsWith(".local", ignoreCase = true)

    // The optional "raddr <addr> rport <port>" tail (RFC 8839 §5.1) — null if absent or malformed.
    private fun relatedAddress(tokens: List<String>): TransportAddress? {
        val raddrIndex = tokens.indexOf("raddr")
        if (raddrIndex < 0 || raddrIndex + 3 >= tokens.size || tokens[raddrIndex + 2] != "rport") return null
        return transportAddress(tokens[raddrIndex + 1], tokens[raddrIndex + 3])
    }

    private fun componentOf(value: Int): ComponentId? = ComponentId.entries.firstOrNull { it.value == value }

    private fun typeOf(token: String): CandidateType? = CandidateType.entries.firstOrNull { it.token == token }

    // An IPv4 or IPv6 connection-address literal + port → TransportAddress (RFC 8839 §5.1 — the address
    // is raw/unbracketed for both families). A malformed literal is a typed reject (null), never a throw.
    private fun transportAddress(
        ip: String,
        port: String,
    ): TransportAddress? {
        val p = port.toIntOrNull() ?: return null
        if (p !in 0..MAX_PORT) return null
        // A v6 connection-address is the only form carrying ':'; a v4 dotted-quad never does.
        if (':' in ip) {
            val v6 = IpAddress.V6.parse(ip) ?: return null
            return TransportAddress(v6, p.toUShort())
        }
        val octets = ip.split('.')
        if (octets.size != IPV4_OCTETS) return null
        var bits = 0u
        for (octet in octets) {
            val v = octet.toUIntOrNull() ?: return null
            if (v > MAX_OCTET) return null
            bits = (bits shl Byte.SIZE_BITS) or v
        }
        return TransportAddress(IpAddress.V4(bits), p.toUShort())
    }

    private const val IPV4_OCTETS = 4
    private const val MAX_OCTET = 255u
    private const val MAX_PORT = 65535
}

/**
 * The outcome of parsing a `candidate:` line ([IceCandidateLine.parseLine]) — a sealed result, not a
 * nullable [IceCandidate], because an `<uuid>.local` mDNS host candidate is a genuine third state: it
 * parsed fine, but its address must be resolved (via the [MdnsResolver] seam) before it becomes usable.
 * A caller `when`s over it exhaustively: [Parsed] is added directly, [MdnsHost] is resolved first, and
 * [Reject] is a malformed or unsupported line (a typed reject, never a throw — T0 discipline).
 */
public sealed interface CandidateParse {
    /** A fully-parsed candidate carrying a concrete IP address (host with a real IP, or srflx/relay). */
    public data class Parsed(
        public val candidate: IceCandidate,
    ) : CandidateParse

    /**
     * An `<uuid>.local` host candidate (RFC 8838 privacy) whose [hostname] must be resolved to an IP via
     * the [MdnsResolver] seam before use. The [port], [component], [foundation], and [priority] ride the
     * candidate line unobfuscated — only the address is hidden — so the resolved IP is combined with this
     * [port] and these RFC 8445 fields to form the eventual host candidate.
     */
    public data class MdnsHost(
        public val hostname: String,
        public val port: Int,
        public val component: ComponentId,
        public val foundation: Foundation,
        public val priority: Long,
    ) : CandidateParse

    /** The line was malformed, or an unsupported/illegal candidate (e.g. non-UDP, or a `.local` non-host). */
    public data object Reject : CandidateParse
}

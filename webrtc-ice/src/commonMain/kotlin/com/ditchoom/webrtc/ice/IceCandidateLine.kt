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

    /**
     * The `ufrag` extension attribute (RFC 8839 §5.1 `*(SP extension-att-name SP extension-att-value)`)
     * — the on-the-line carrier of RFC 8838 §3.1's generation tag, and the one libwebrtc has emitted for
     * years (`… typ srflx raddr 0.0.0.0 rport 0 generation 0 ufrag 4ZcD network-cost 999`). Unknown
     * extension attributes MUST be ignored by the grammar, which is what makes stamping it safe against a
     * peer that has never heard of it.
     */
    private const val UFRAG_ATTRIBUTE = "ufrag"

    /**
     * Serialize [candidate] as a full `candidate:` attribute value (RFC 8839 §5.1), stamped with the ICE
     * generation it was gathered in when [generation] names one (RFC 8838 §3.1).
     *
     * The default is [CandidateGeneration.Untagged] — byte-for-byte the line this emitted before the tag
     * existed — so a caller that does not know the generation cannot accidentally assert one.
     */
    public fun format(
        candidate: IceCandidate,
        generation: CandidateGeneration = CandidateGeneration.Untagged,
    ): String {
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
        val withRelated = if (related == null) head else "$head raddr ${related.ip} rport ${related.port}"
        return when (generation) {
            CandidateGeneration.Untagged -> withRelated
            is CandidateGeneration.Tagged -> "$withRelated $UFRAG_ATTRIBUTE ${generation.ufrag.value}"
        }
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

        val generation = generationOf(t)
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
                generation = generation,
            )
        }

        val address = transportAddress(t[4], t[5]) ?: return CandidateParse.Reject
        val candidate = buildCandidate(type, address, component, foundation, priority, relatedAddress(t))
        return if (candidate == null) CandidateParse.Reject else CandidateParse.Parsed(candidate, generation)
    }

    /**
     * The RFC 8838 §3.1 generation tag riding the line as a `ufrag` extension attribute, or
     * [CandidateGeneration.Untagged].
     *
     * Walked in name/value **pairs** from the first token past the fixed part, rather than with a bare
     * `indexOf("ufrag")`: extension-attribute values are arbitrary text, so a line whose
     * `network-id ufrag` (or any other attribute whose value happens to be the word) would otherwise be
     * read as a tag and route a perfectly good candidate into the hold buffer. An absent, empty, or
     * value-less `ufrag` is untagged — the tag is optional and a malformed one is not a reason to reject
     * an otherwise valid candidate (T0: parse failures are typed, and this one's type is "no tag").
     */
    private fun generationOf(tokens: List<String>): CandidateGeneration {
        var i = MIN_TOKENS
        if (tokens.getOrNull(i) == "raddr") i += RELATED_TOKENS
        while (i + 1 < tokens.size) {
            if (tokens[i] == UFRAG_ATTRIBUTE) {
                val value = tokens[i + 1]
                return if (value.isEmpty()) CandidateGeneration.Untagged else CandidateGeneration.Tagged(Ufrag(value))
            }
            i += 2
        }
        return CandidateGeneration.Untagged
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

    // "raddr <addr> rport <port>" — the four tokens that sit between the fixed part and the extension
    // attributes when a reflexive/relayed candidate carries a related address (RFC 8839 §5.1).
    private const val RELATED_TOKENS = 4

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
    /**
     * A fully-parsed candidate carrying a concrete IP address (host with a real IP, or srflx/relay), and
     * the ICE generation the line claimed it belongs to (RFC 8838 §3.1) — [CandidateGeneration.Untagged]
     * for the great majority of lines, which carry no `ufrag` attribute at all.
     */
    public data class Parsed(
        public val candidate: IceCandidate,
        public val generation: CandidateGeneration = CandidateGeneration.Untagged,
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
        public val generation: CandidateGeneration = CandidateGeneration.Untagged,
    ) : CandidateParse

    /** The line was malformed, or an unsupported/illegal candidate (e.g. non-UDP, or a `.local` non-host). */
    public data object Reject : CandidateParse
}

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

    /** Parse a `candidate:` attribute value (with or without the prefix) into an [IceCandidate], or null. */
    public fun parse(line: String): IceCandidate? {
        val value = line.trim().removePrefix(PREFIX)
        val t = value.split(' ').filter { it.isNotEmpty() }
        if (t.size < MIN_TOKENS || t[6] != "typ") return null

        val foundation = Foundation(t[0])
        val component = componentOf(t[1].toIntOrNull() ?: return null) ?: return null
        if (t[2].lowercase() != IceTransport.Udp.token) return null // phase-1: UDP only
        val priority = t[3].toLongOrNull() ?: return null
        val address = transportAddress(t[4], t[5]) ?: return null
        val type = typeOf(t[7]) ?: return null
        val related = relatedAddress(t)

        return when (type) {
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
    }

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

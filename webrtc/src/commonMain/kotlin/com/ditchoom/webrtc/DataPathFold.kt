package com.ditchoom.webrtc

import com.ditchoom.webrtc.ice.CandidatePair
import com.ditchoom.webrtc.ice.DataCarrier
import com.ditchoom.webrtc.ice.IceCandidate
import com.ditchoom.webrtc.ice.IceDataPath
import com.ditchoom.webrtc.ice.localSocket
import com.ditchoom.webrtc.sctp.association.PathAddressFamily
import com.ditchoom.webrtc.sctp.association.PathIdentity
import com.ditchoom.webrtc.sctp.association.PathOverheadBytes
import com.ditchoom.webrtc.sctp.association.SctpPathProfile
import com.ditchoom.webrtc.stun.IpAddress

// Fixed lower-layer framing, in the order a datagram wears it. File-private rather than a `const val` in
// a private companion, which is still emitted as a public static field.
private const val IPV4_HEADER_BYTES = 20
private const val IPV6_HEADER_BYTES = 40
private const val UDP_HEADER_BYTES = 8

// A DTLS 1.2 AES-GCM record: the 13-byte record header, the 8-byte explicit nonce, and the 16-byte tag
// (`Dtls12RecordProtection`). DTLS 1.3 is smaller — a 2-to-5-byte unified header, the tag, and one inner
// content-type byte — so 1.2 is the worst case and the one an overhead estimate has to survive. Sizing
// for the smaller of the two would put a datagram over the path MTU on every 1.2 session, which is the
// half of the negotiation this layer does not get to choose.
private const val DTLS12_RECORD_BYTES = 37

// A TURN Send indication (RFC 8656 §11.2), which is how `TurnAllocation.send` frames relayed application
// data: the 20-byte STUN header, an XOR-PEER-ADDRESS attribute, and the DATA attribute's own TLV header.
// The attribute value is 8 bytes for an IPv4 peer and 20 for an IPv6 one (RFC 8489 §14.1/§14.3).
private const val STUN_HEADER_BYTES = 20
private const val STUN_ATTRIBUTE_HEADER_BYTES = 4
private const val XOR_ADDRESS_V4_VALUE_BYTES = 8
private const val XOR_ADDRESS_V6_VALUE_BYTES = 20

/**
 * Where this session's application data is riding — the session layer's memory between two ICE path
 * signals, and the only thing that can tell a genuine migration from a re-statement.
 *
 * Sealed rather than a nullable [IceDataPath] because [NotYet] is a real state with its own rule: the
 * first path a session rides is **adopted without a diagnostic and without a congestion reset**, since
 * learning where data goes is not the data's route changing. A `null` standing in for it would have made
 * that rule an `if` at the call site rather than an arm of the fold.
 */
internal sealed interface RidingPath {
    /** Nothing nominated yet, or nothing has been observed yet. */
    data object NotYet : RidingPath

    /** Data rides [path]; [profile] is what the association was told about it. */
    data class On(
        val path: IceDataPath,
        val profile: SctpPathProfile.Assessed,
    ) : RidingPath
}

/**
 * What one ICE path signal meant for the data path — the fold's output, and a sealed decision rather
 * than a pair of nullables, because the three cases differ in *what the caller must do* and not merely in
 * what changed.
 */
internal sealed interface PathObservation {
    /** Nothing to tell anyone: no carrier, or the same [IceDataPath] as before. */
    data object Unchanged : PathObservation

    /** The first path this session rides. Tell the association; emit **no** diagnostic. */
    data class Adopted(
        val profile: SctpPathProfile.Assessed,
    ) : PathObservation

    /** Data moved. Tell the association — which resets RFC 8261 §6.1 state — and report it. */
    data class Migrated(
        val from: IceDataPath,
        val to: IceDataPath,
        val profile: SctpPathProfile.Assessed,
    ) : PathObservation
}

/**
 * The session's fold from ICE path signals to [SctpPathProfile]s, and the sole minter of this session's
 * [PathIdentity] ordinals.
 *
 * ## Why it is a session-scoped object rather than local state in the watcher
 *
 * The path watcher is per **ICE generation** — it is started by each establishment attempt and cancelled
 * when that attempt ends — while the SCTP association is per **session** and survives an ICE restart
 * untouched (RFC 8842 §5.5). Folding inside the watcher would reset the memory at exactly the moment the
 * interesting migration happens: the first path of the next attempt would read as a first path rather
 * than as a move, so the one event this whole mechanism exists for would be the one it silently skipped.
 *
 * ## Why the discriminant is [IceDataPath]
 *
 * Because [CandidatePair] equality answers a different question, and answers this one wrongly in two
 * routine cases — an ICE restart re-gathering the same interface at a different gather ordinal, and a
 * host pair superseded by a server-reflexive one over the same socket. Both would cost a path that never
 * moved its congestion window, its RTT estimate and a fresh PMTU search. [DataCarrier.Riding] already
 * defines its own equality on the path for exactly this reason, so the comparison below is the carrier's
 * and not a second one written here.
 *
 * Not thread-safe, and does not need to be: it is read and written only from the path watcher, and the
 * establishment loop runs attempts sequentially.
 */
internal class DataPathFold {
    private var riding: RidingPath = RidingPath.NotYet
    private var nextOrdinal: UInt = 0u

    /** Fold one ICE carrier signal. Mutates the memory; returns what the caller must do about it. */
    fun observe(carrier: DataCarrier): PathObservation {
        // No carrier is not a migration to nowhere. RFC 8445 §9 keeps data on the retained pair for the
        // whole restart window, and an unnominated path means the pair is gone rather than moved — which
        // the ICE failure terminal owns. Forgetting the current path here would make the next nomination
        // read as a first path and skip the reset it needs.
        val riding = carrier as? DataCarrier.Riding ?: return PathObservation.Unchanged
        val to = riding.path
        return when (val current = this.riding) {
            RidingPath.NotYet -> adopt(riding.pair, to).let { PathObservation.Adopted(it) }
            is RidingPath.On ->
                if (current.path == to) {
                    PathObservation.Unchanged
                } else {
                    PathObservation.Migrated(from = current.path, to = to, profile = adopt(riding.pair, to))
                }
        }
    }

    private fun adopt(
        pair: CandidatePair,
        path: IceDataPath,
    ): SctpPathProfile.Assessed {
        val profile =
            SctpPathProfile.Assessed(
                identity = PathIdentity(nextOrdinal),
                family = familyOf(pair),
                overhead = overheadOf(pair),
            )
        nextOrdinal += 1u
        riding = RidingPath.On(path, profile)
        return profile
    }
}

/**
 * The address family whose MTU rules the path must obey.
 *
 * On a **direct** pair this is simply the family both ends share — RFC 8445 §6.1.2.2 pairs only
 * same-family candidates, so there is one answer. On a **relayed** pair there are two IP paths and they
 * need not agree: our socket reaches the TURN server over one family and the server reaches the peer over
 * another. A datagram has to survive both, so the more constrained wins, which for these two families
 * means IPv6 — the one whose routers refuse to fragment (RFC 8200 §5).
 */
private fun familyOf(pair: CandidatePair): PathAddressFamily {
    val ourLeg = familyOf(pair.local.localSocket.ip)
    val peerLeg = familyOf(pair.remote.address.ip)
    return if (ourLeg.unprobedPathMtu <= peerLeg.unprobedPathMtu) ourLeg else peerLeg
}

private fun familyOf(ip: IpAddress): PathAddressFamily =
    when (ip) {
        is IpAddress.V4 -> PathAddressFamily.Ipv4
        is IpAddress.V6 -> PathAddressFamily.Ipv6
    }

/**
 * Everything an SCTP packet on this pair pays below SCTP.
 *
 * The IP header is sized from `IceCandidate.localSocket` — the socket the datagram genuinely leaves the
 * host on — and **not** from the candidate's `base`. For a relayed candidate those differ: the base is an
 * address on the TURN server, which is not on any local link and whose family says nothing about the
 * header our own IP stack writes.
 *
 * A relayed pair then pays a TURN Send indication on top, sized from the **peer's** family because that
 * is what the XOR-PEER-ADDRESS attribute carries. The worst case this can produce is a relayed IPv6
 * session at 40 + 8 + 37 + 48 = 133 bytes, comfortably inside [PathOverheadBytes]'s 192-byte bound — the
 * bound that makes the derived fragment ceiling legal by construction rather than by clamping.
 */
private fun overheadOf(pair: CandidatePair): PathOverheadBytes {
    val ipHeader =
        when (pair.local.localSocket.ip) {
            is IpAddress.V4 -> IPV4_HEADER_BYTES
            is IpAddress.V6 -> IPV6_HEADER_BYTES
        }
    val relayFraming =
        when (pair.local) {
            is IceCandidate.Relayed -> sendIndicationBytes(pair.remote.address.ip)
            is IceCandidate.Host, is IceCandidate.ServerReflexive, is IceCandidate.PeerReflexive -> 0
        }
    return PathOverheadBytes(ipHeader + UDP_HEADER_BYTES + DTLS12_RECORD_BYTES + relayFraming)
}

private fun sendIndicationBytes(peer: IpAddress): Int {
    val xorPeerAddress =
        STUN_ATTRIBUTE_HEADER_BYTES +
            when (peer) {
                is IpAddress.V4 -> XOR_ADDRESS_V4_VALUE_BYTES
                is IpAddress.V6 -> XOR_ADDRESS_V6_VALUE_BYTES
            }
    return STUN_HEADER_BYTES + xorPeerAddress + STUN_ATTRIBUTE_HEADER_BYTES
}

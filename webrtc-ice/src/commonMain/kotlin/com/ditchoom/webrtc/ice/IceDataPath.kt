package com.ditchoom.webrtc.ice

import com.ditchoom.webrtc.stun.TransportAddress

/**
 * The **transmit identity** of a live ICE path: the local socket every application datagram leaves from,
 * and the address it is addressed to. It is exactly the two addresses the driver's app-data seam reads
 * per packet — `channels[pair.local.base].send(packet, to = pair.remote.address)` — reduced to a value
 * that can be compared.
 *
 * ## Why [fromBase] is the candidate's `base`
 *
 * `IceAgentDriver.channels` is keyed by `candidate.base` for **every** candidate kind: `bind(host.base,
 * channel)` for a host or server-reflexive candidate, `bind(relay.base, allocation)` for a relayed one
 * (where the allocation *is* the channel). Both readers look it back up by that key — the app-data seam
 * with `channels[pair.local.base]`, the check path with `channels[output.fromBase]`. So the base is the
 * socket identity as far as transmission is concerned, relayed candidates included, and a discriminant
 * built on anything else would be describing a map that does not exist.
 *
 * ## Why this, and not [CandidatePair], is the migration discriminant
 *
 * An upper layer that resets path state when the lower layer changes path (RFC 8261 §6.1: *"If the SCTP
 * layer is notified about a path change by its lower layers, SCTP SHOULD retest the path MTU and reset
 * the congestion state to the initial state"*) needs to be told about real moves only. Deciding that on
 * pair equality reports two changes that are not changes:
 *
 * - **A restart that re-gathers the same interface.** Gather ordinals restart with the generation, so the
 *   same socket comes back with a different `localPreference` → a different RFC 8445 §5.1.2.1 `priority` →
 *   a different [IceCandidate] → a different [CandidatePair]. The datagrams still leave the same socket
 *   for the same peer; nothing moved.
 * - **A host pair superseded by a server-reflexive one over the same socket.** `Host(X, base = X)` and
 *   `ServerReflexive(Y, base = X)` are two candidates over one socket: nominating the second changes
 *   which pair is selected and changes nothing about where a packet goes.
 *
 * Each would cost a healthy path its measured congestion window, its RTT estimate and a fresh PMTU
 * search — the reset is not free, which is why it has to be spent on a path that actually moved.
 *
 * ## What it deliberately does not answer
 *
 * Which **local interface** the path stands on. For a relayed candidate [fromBase] is an address on the
 * TURN server, which no local interface will ever match; the host's own socket is
 * [IceCandidate.localSocket]. The two are different questions and both are needed — see that property.
 *
 * Compared for equality only. There is no ordering here, and none would mean anything.
 */
public data class IceDataPath(
    public val fromBase: TransportAddress,
    public val to: TransportAddress,
)

/**
 * Whether application traffic has somewhere to go, and if so over which [IceDataPath] — the projection of
 * [IcePath] that a layer *above* ICE (DTLS, SCTP) actually consumes.
 *
 * [IcePath] has three cases because ICE has three situations to tell apart. A carrier has two, because
 * "nothing nominated yet" and "restarting" differ in which generation owns the pair, not in whether data
 * flows (RFC 8445 §9). Folding three into two here is what stops the restart *window* from presenting to
 * that consumer as a path change: see [carrier].
 *
 * Sealed rather than a nullable [IceDataPath]: [None] is not an absent path, it is the state in which
 * there is no path to be had, and a `when` over the two arms is a decision rather than an elvis
 * (DESIGN_PRINCIPLES §5).
 */
public sealed interface DataCarrier {
    /** Nothing is nominated: application data has nowhere to go (DTLS/SCTP have not started). */
    public data object None : DataCarrier

    /**
     * Application data rides [pair] — the pair the current generation nominated, or the retained one an
     * in-flight restart is still carrying data over.
     *
     * ## Equality is on [path], deliberately, and not on [pair]
     *
     * [IceDataPath] exists because pair identity is a *wrong* answer to "did the path move", and it names
     * the two false positives. A `data class` over [pair] would hand both of them straight back through
     * the carrier's own `==` — which is the comparison a consumer folding this into a migration event
     * writes first, and the one that would look right in review. So `Riding(a) == Riding(b)` exactly when
     * the two send from the same socket to the same address, with [hashCode] agreeing.
     *
     * That is sound rather than merely convenient. Two pairs sharing a `local.base` also share an
     * [IceCandidate.localSocket]: only a relayed candidate's differs from its base, and a relayed
     * transport address is minted per allocation by the TURN server, so it cannot collide with another
     * candidate's base. Equal carriers are therefore interchangeable for every question this type is
     * asked, including the address family of the local socket.
     *
     * [pair] is still carried, because the candidate *types* along it are what a path profile needs
     * (a relayed path pays a TURN header a host path does not), and it is still printed by [toString] —
     * a field excluded from equality is only a trap while nothing shows it.
     */
    public class Riding(
        public val pair: CandidatePair,
    ) : DataCarrier {
        /** The two addresses the driver transmits between for this pair. */
        public val path: IceDataPath get() = IceDataPath(fromBase = pair.local.base, to = pair.remote.address)

        override fun equals(other: Any?): Boolean = this === other || (other is Riding && other.path == path)

        override fun hashCode(): Int = path.hashCode()

        override fun toString(): String = "Riding(path=$path, pair=$pair)"
    }
}

/**
 * Where application data rides *right now*, whichever generation owns the pair (RFC 8445 §9).
 *
 * The three [IcePath] cases map onto two carriers: [IcePath.Unnominated] has none, [IcePath.Nominated]
 * rides its pair, and [IcePath.Restarting] rides the **retained** generation's pair — §9's *"data can
 * continue to be sent using existing data sessions"*, which is a property of the carrier and not merely
 * of the socket staying bound. So beginning a restart does not change the carrier; only the new
 * generation nominating a genuinely different [IceDataPath] does, which is the moment an upper layer has
 * to reset path state and not one event before.
 *
 * An extension property rather than a member: [IcePath] is the ICE core's own vocabulary, and this is the
 * projection one consumer of it wants. The `when` is exhaustive with no `else`, so a fourth [IcePath]
 * case would fail to compile here rather than silently answering [DataCarrier.None].
 */
public val IcePath.carrier: DataCarrier
    get() =
        when (this) {
            IcePath.Unnominated -> DataCarrier.None
            is IcePath.Nominated -> DataCarrier.Riding(pair)
            is IcePath.Restarting -> DataCarrier.Riding(previous)
        }

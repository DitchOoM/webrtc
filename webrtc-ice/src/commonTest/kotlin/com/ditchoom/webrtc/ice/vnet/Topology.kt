@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import kotlinx.coroutines.CoroutineScope

/**
 * Topologies as data (RFC §5.2 — "topologies as data, not lab setups"). A fixture picks a builder,
 * drives the agents, and the whole NAT/relay/impairment scenario is a value it can diff, replay, and
 * shrink. The addressing convention is fixed so fixtures read the same way everywhere:
 *
 *  - the **public segment** is `203.0.113.0/24` (TEST-NET-3) — servers and NAT external IPs;
 *  - each **private segment** is a distinct `10.x.y.0/24`, mutually unreachable except via the public
 *    segment (which is what forces a relay when both NATs are symmetric).
 */
internal object Vnets {
    val STUN_SERVER_ADDRESS: SocketAddress = vnetAddress("203.0.113.2", 3478)
    val TURN_SERVER_ADDRESS: SocketAddress = vnetAddress("203.0.113.9", 3478)

    const val TURN_USERNAME = "ice"
    const val TURN_PASSWORD = "s3cret"

    /** A flat, lossless network (no NAT) — the seam-gate default and the base for unit topologies. */
    fun flat(bufferFactory: BufferFactory = BufferFactory.Default): Vnet = Vnet(bufferFactory = bufferFactory)

    /**
     * A flat network with a seeded [Impairment] pipe (loss/reorder/dup/delay) — the fuzz-lane link that
     * stresses connectivity-check retransmission under virtual time.
     */
    fun flatImpaired(
        scope: CoroutineScope,
        impairment: ImpairmentConfig,
        seed: Long,
        bufferFactory: BufferFactory = BufferFactory.Default,
    ): Vnet = Vnet(bufferFactory = bufferFactory, fabric = Impairment(impairment, scope, seed, base = DirectFabric))

    /**
     * A single NAT box for [privatePrefix]↔[publicIp] under [profile]. Compose several with [behindNats].
     */
    fun nat(
        publicIp: String,
        privatePrefix: String,
        profile: NatProfile,
        firstPort: Int = NatBox.FIRST_EPHEMERAL_PORT,
    ): NatBox = NatBox(publicIp, privatePrefix, profile, firstPort)

    /**
     * A network of [boxes], optionally impaired. When [impairment] is non-null the pipe wraps the NAT
     * (so each datagram is impaired once end-to-end), driven on [scope] under virtual time.
     */
    fun behindNats(
        boxes: List<NatBox>,
        bufferFactory: BufferFactory = BufferFactory.Default,
        impairment: ImpairmentConfig? = null,
        scope: CoroutineScope? = null,
        impairmentSeed: Long = DEFAULT_IMPAIRMENT_SEED,
    ): Vnet {
        val nat = Nat(boxes)
        val fabric =
            if (impairment == null) {
                nat
            } else {
                Impairment(impairment, requireNotNull(scope) { "impairment needs a scope for delay()" }, impairmentSeed, base = nat)
            }
        return Vnet(bufferFactory = bufferFactory, fabric = fabric)
    }

    /**
     * The canonical **dual-symmetric-NAT → relay** meetup (RFC §5.2): Alice and Bob each behind their
     * own symmetric NAT, with a public STUN and TURN server. Direct and srflx paths cannot connect —
     * only the relay does. The two servers are already started on [scope]; the caller binds the two
     * host addresses and drives the agents. Pass [profileA]/[profileB] to reuse the wiring for the
     * other NAT profiles (e.g. two full-cone NATs that *can* meet on srflx).
     */
    fun meetup(
        scope: CoroutineScope,
        profileA: NatProfile = NatProfile.Symmetric,
        profileB: NatProfile = NatProfile.Symmetric,
        bufferFactory: BufferFactory = BufferFactory.Default,
        impairment: ImpairmentConfig? = null,
        impairmentSeed: Long = DEFAULT_IMPAIRMENT_SEED,
    ): Meetup {
        val natA = nat(publicIp = "203.0.113.10", privatePrefix = "10.0.0.", profile = profileA)
        val natB = nat(publicIp = "203.0.113.20", privatePrefix = "10.0.1.", profile = profileB)
        val vnet = behindNats(listOf(natA, natB), bufferFactory, impairment, scope, impairmentSeed)
        val stun = StunServer(STUN_SERVER_ADDRESS, vnet, scope).also { it.start() }
        val turn =
            TurnServer(
                address = TURN_SERVER_ADDRESS,
                vnet = vnet,
                scope = scope,
                keyProvider = { username -> if (username == TURN_USERNAME) utf8Buffer(TURN_PASSWORD) else null },
            ).also { it.start() }
        return Meetup(
            vnet = vnet,
            aliceHost = vnetAddress("10.0.0.2", 5000),
            bobHost = vnetAddress("10.0.1.2", 5000),
            stun = stun,
            turn = turn,
        )
    }

    private const val DEFAULT_IMPAIRMENT_SEED = 0x1CE_10551L // "ICE loss"
}

/** The landmarks of a [Vnets.meetup] topology — the vnet plus the two host addresses and the servers. */
internal class Meetup(
    val vnet: Vnet,
    val aliceHost: SocketAddress,
    val bobHost: SocketAddress,
    val stun: StunServer,
    val turn: TurnServer,
) {
    val stunAddress: SocketAddress get() = stun.address
    val turnAddress: SocketAddress get() = turn.address
}

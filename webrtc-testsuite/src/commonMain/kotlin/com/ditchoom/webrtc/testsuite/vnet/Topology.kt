@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.testsuite.vnet

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import kotlinx.coroutines.CoroutineScope

/**
 * Topologies as data (RFC §5.2 — "topologies as data, not lab setups"). The [withWebRtcHarness]
 * [com.ditchoom.webrtc.testsuite.harness.withWebRtcHarness] DSL picks a builder, drives two
 * [com.ditchoom.webrtc.NativePeerConnection]s over the resulting [Vnet], and the whole
 * NAT/relay/impairment scenario is a value it can diff, replay, and shrink. The addressing convention
 * is fixed so fixtures read the same way everywhere:
 *
 *  - the **public segment** is `203.0.113.0/24` (TEST-NET-3) — servers, NAT external IPs, and (in the
 *    flat topology) the hosts themselves;
 *  - each **private segment** is a distinct `10.x.y.0/24`, mutually unreachable except via the public
 *    segment (which is what forces a relay when both NATs are symmetric).
 */
internal object Vnets {
    val STUN_SERVER_ADDRESS: SocketAddress = vnetAddress("203.0.113.2", 3478)
    val TURN_SERVER_ADDRESS: SocketAddress = vnetAddress("203.0.113.9", 3478)

    const val TURN_USERNAME = "ice"
    const val TURN_PASSWORD = "s3cret"

    private const val DEFAULT_IMPAIRMENT_SEED = 0x1CE_10551L // "ICE loss"

    /**
     * Build the two-peer topology the harness drives.
     *
     * @param profile the NAT behavior both peers sit behind, or `null` for a flat (no-NAT) network
     *   where the hosts are directly on the public segment and connect on their host candidates.
     * @param impairment optional loss/delay/jitter pipe wrapping the base fabric (netem analogue).
     */
    fun build(
        scope: CoroutineScope,
        profile: NatProfile?,
        bufferFactory: BufferFactory = BufferFactory.Default,
        impairment: ImpairmentConfig? = null,
        impairmentSeed: Long = DEFAULT_IMPAIRMENT_SEED,
    ): Topology {
        val aliceHost: SocketAddress
        val bobHost: SocketAddress
        val base: Fabric =
            if (profile == null) {
                aliceHost = vnetAddress("203.0.113.31", 5000)
                bobHost = vnetAddress("203.0.113.32", 5000)
                DirectFabric
            } else {
                aliceHost = vnetAddress("10.0.0.2", 5000)
                bobHost = vnetAddress("10.0.1.2", 5000)
                Nat(
                    listOf(
                        NatBox(publicIp = "203.0.113.10", privatePrefix = "10.0.0.", profile = profile),
                        NatBox(publicIp = "203.0.113.20", privatePrefix = "10.0.1.", profile = profile),
                    ),
                )
            }
        val fabric =
            if (impairment == null) {
                base
            } else {
                Impairment(impairment, scope, impairmentSeed, base = base, bufferFactory = bufferFactory)
            }
        val vnet = Vnet(bufferFactory = bufferFactory, fabric = fabric)
        val stun = StunServer(STUN_SERVER_ADDRESS, vnet, scope).also { it.start() }
        val turn =
            TurnServer(
                address = TURN_SERVER_ADDRESS,
                vnet = vnet,
                scope = scope,
                keyProvider = { username -> if (username == TURN_USERNAME) utf8Buffer(TURN_PASSWORD) else null },
            ).also { it.start() }
        return Topology(
            vnet = vnet,
            aliceHost = aliceHost,
            bobHost = bobHost,
            stun = stun,
            turn = turn,
            natted = profile != null,
        )
    }
}

/** The landmarks of a [Vnets.build] topology — the vnet plus the two host addresses and the servers. */
internal class Topology(
    val vnet: Vnet,
    val aliceHost: SocketAddress,
    val bobHost: SocketAddress,
    val stun: StunServer,
    val turn: TurnServer,
    /** True when the hosts sit behind NAT boxes (so srflx/relay carry connectivity across them). */
    val natted: Boolean,
) {
    val stunAddress: SocketAddress get() = stun.address
    val turnAddress: SocketAddress get() = turn.address
}

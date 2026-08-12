package com.ditchoom.webrtc

import com.ditchoom.webrtc.ice.CandidatePair
import com.ditchoom.webrtc.ice.ComponentId
import com.ditchoom.webrtc.ice.DataCarrier
import com.ditchoom.webrtc.ice.Foundation
import com.ditchoom.webrtc.ice.IceCandidate
import com.ditchoom.webrtc.ice.IceTransport
import com.ditchoom.webrtc.sctp.association.PathAddressFamily
import com.ditchoom.webrtc.sctp.association.PathIdentity
import com.ditchoom.webrtc.sctp.association.PathOverheadBytes
import com.ditchoom.webrtc.stun.IpAddress
import com.ditchoom.webrtc.stun.TransportAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The session layer's fold from ICE path signals to [com.ditchoom.webrtc.sctp.association.SctpPathProfile]s.
 *
 * Two properties are load-bearing and neither is visible from the session integration fixture, which can
 * only reach the direct-IPv4 case its in-memory network provides:
 *
 * 1. **What counts as a move.** A migration costs a healthy association its congestion window, its RTT
 *    estimate and (once DPLPMTUD lands) a fresh probe search, so a fold that over-reports is not merely
 *    noisy — it is a throughput regression fired by ICE bookkeeping. The two false positives
 *    [com.ditchoom.webrtc.ice.IceDataPath] exists to foreclose are asserted here directly.
 * 2. **The overhead arithmetic.** It decides the fragmentation ceiling, so an under-estimate on IPv6 puts
 *    a datagram over 1280 and every full-size fragment is dropped — the defect this whole track is about,
 *    reintroduced one layer up. The relayed IPv6 case pays the most and is the one no lane exercises.
 */
class DataPathFoldTest {
    private val alice = TransportAddress(IpAddress.V4(0x0A000001u), 4000u) // 10.0.0.1
    private val bob = TransportAddress(IpAddress.V4(0x0A000002u), 5000u) // 10.0.0.2
    private val aliceV6 = TransportAddress(IpAddress.V6(0x2001_0DB8_0000_0001uL, 1uL), 4000u)
    private val bobV6 = TransportAddress(IpAddress.V6(0x2001_0DB8_0000_0002uL, 1uL), 5000u)
    private val relay = TransportAddress(IpAddress.V4(0x0A000063u), 30000u) // the TURN server's relayed address

    private fun host(
        address: TransportAddress,
        localPreference: Int = MAX_LOCAL_PREFERENCE,
    ) = IceCandidate.host(address, localPreference = localPreference)

    private fun serverReflexive(
        mapped: TransportAddress,
        base: TransportAddress,
    ) = IceCandidate.ServerReflexive(
        address = mapped,
        base = base,
        relatedAddress = base,
        component = ComponentId.Rtp,
        transport = IceTransport.Udp,
        foundation = Foundation("srflx"),
        priority = 1_000_000L,
    )

    /**
     * A relayed candidate as `IceAgentDriver.gatherRelay` builds one: `address` is the relay on the TURN
     * server, `base` is the same (which is what `channels` is keyed by), and `relatedAddress` is the
     * **local bind address** — not the RFC 8445 §5.1.1.4 mapped address the name suggests.
     */
    private fun relayed(
        relayed: TransportAddress,
        localBind: TransportAddress,
    ) = IceCandidate.Relayed(
        address = relayed,
        relatedAddress = localBind,
        component = ComponentId.Rtp,
        transport = IceTransport.Udp,
        foundation = Foundation("relay"),
        priority = 100_000L,
    )

    private fun riding(
        local: IceCandidate,
        remote: IceCandidate,
    ) = DataCarrier.Riding(CandidatePair(local, remote))

    @Test
    fun the_first_path_is_adopted_without_a_migration() {
        val fold = DataPathFold()
        val observed = fold.observe(riding(host(alice), host(bob)))
        val adopted = assertIs<PathObservation.Adopted>(observed)
        assertEquals(PathIdentity(0u), adopted.profile.identity)
    }

    @Test
    fun no_carrier_is_not_a_migration_and_does_not_forget_the_current_path() {
        val fold = DataPathFold()
        fold.observe(riding(host(alice), host(bob)))
        // RFC 8445 §9 keeps data on the retained pair for the whole restart window; an unnominated path
        // means the pair is gone rather than moved. Forgetting here would make the next nomination read
        // as a first path and skip the RFC 8261 §6.1 reset it needs.
        assertEquals(PathObservation.Unchanged, fold.observe(DataCarrier.None))
        assertEquals(PathObservation.Unchanged, fold.observe(riding(host(alice), host(bob))))
    }

    /**
     * Gather ordinals restart with the ICE generation, so the same socket comes back with a different
     * `localPreference` → a different RFC 8445 §5.1.2.1 priority → a different [IceCandidate] → a
     * different [CandidatePair]. Nothing moved: the datagrams still leave the same socket for the same
     * peer.
     */
    @Test
    fun a_re_gathered_identical_socket_is_not_a_migration() {
        val fold = DataPathFold()
        fold.observe(riding(host(alice, localPreference = 65535), host(bob)))
        val again = riding(host(alice, localPreference = 65534), host(bob))
        assertNotEquals(
            CandidatePair(host(alice, localPreference = 65535), host(bob)),
            again.pair,
            "the pairs really do differ, or this fixture proves nothing",
        )
        assertEquals(PathObservation.Unchanged, fold.observe(again))
    }

    /** `Host(X, base = X)` and `ServerReflexive(Y, base = X)` are two candidates over ONE socket. */
    @Test
    fun a_server_reflexive_candidate_over_the_same_socket_is_not_a_migration() {
        val fold = DataPathFold()
        fold.observe(riding(host(alice), host(bob)))
        val mapped = TransportAddress(IpAddress.V4(0xC0A80001u), 4000u)
        assertEquals(PathObservation.Unchanged, fold.observe(riding(serverReflexive(mapped, base = alice), host(bob))))
    }

    @Test
    fun a_new_socket_is_a_migration_and_mints_a_new_identity() {
        val fold = DataPathFold()
        val first = assertIs<PathObservation.Adopted>(fold.observe(riding(host(alice), host(bob))))
        val moved = TransportAddress(IpAddress.V4(0x0A000009u), 4100u)
        val second = assertIs<PathObservation.Migrated>(fold.observe(riding(host(moved), host(bob))))

        assertEquals(first.profile.identity, PathIdentity(0u))
        assertEquals(PathIdentity(1u), second.profile.identity, "a migration must carry an identity the association has not seen")
        assertEquals(alice, second.from.fromBase)
        assertEquals(moved, second.to.fromBase)
    }

    /** A new peer address over the same local socket is a move too — the destination is half the identity. */
    @Test
    fun a_new_remote_address_over_the_same_socket_is_a_migration() {
        val fold = DataPathFold()
        fold.observe(riding(host(alice), host(bob)))
        val otherPeer = TransportAddress(IpAddress.V4(0x0A00000Au), 5100u)
        assertIs<PathObservation.Migrated>(fold.observe(riding(host(alice), host(otherPeer))))
    }

    @Test
    fun a_direct_ipv4_path_pays_ip_udp_and_a_dtls_record() {
        val adopted = assertIs<PathObservation.Adopted>(DataPathFold().observe(riding(host(alice), host(bob))))
        assertEquals(PathAddressFamily.Ipv4, adopted.profile.family)
        assertEquals(PathOverheadBytes(20 + 8 + 37), adopted.profile.overhead)
    }

    @Test
    fun a_direct_ipv6_path_pays_the_larger_header_and_takes_the_1280_ceiling() {
        val adopted = assertIs<PathObservation.Adopted>(DataPathFold().observe(riding(host(aliceV6), host(bobV6))))
        assertEquals(PathAddressFamily.Ipv6, adopted.profile.family)
        assertEquals(PathOverheadBytes(40 + 8 + 37), adopted.profile.overhead)
        assertTrue(
            adopted.profile.unprobedFragmentCeiling.value + 28 + adopted.profile.overhead.value <= 1280,
            "a full fragment plus every header must fit RFC 8200 §5's guaranteed minimum",
        )
    }

    /**
     * The relayed case, and the reason `localSocket` exists. A relayed candidate's `base` is an address
     * **on the TURN server**: sizing the IP header from it would charge an IPv4 header to a session whose
     * own socket is IPv6, under-counting by 20 bytes on exactly the family where an under-count is a
     * silent drop.
     */
    @Test
    fun a_relayed_path_is_sized_from_the_local_bind_address_not_the_relay() {
        val overV6Socket = riding(relayed(relayed = relay, localBind = aliceV6), host(bob))
        val adopted = assertIs<PathObservation.Adopted>(DataPathFold().observe(overV6Socket))
        assertEquals(
            PathOverheadBytes(40 + 8 + 37 + 36),
            adopted.profile.overhead,
            "IPv6 header + UDP + DTLS 1.2 record + a TURN Send indication carrying an IPv4 peer address",
        )
    }

    /** The worst path this stack rides, and the one that must stay inside PathOverheadBytes' bound. */
    @Test
    fun the_worst_case_relayed_ipv6_path_stays_inside_the_overhead_bound() {
        val worst = riding(relayed(relayed = relay, localBind = aliceV6), host(bobV6))
        val adopted = assertIs<PathObservation.Adopted>(DataPathFold().observe(worst))
        assertEquals(PathOverheadBytes(40 + 8 + 37 + 48), adopted.profile.overhead)
        assertEquals(133, adopted.profile.overhead.value)
        assertEquals(PathAddressFamily.Ipv6, adopted.profile.family)
    }

    /**
     * A relay translating between families leaves two IP paths that need not agree, and a datagram has to
     * survive both. The more constrained wins — which for these two is IPv6, the family whose routers
     * refuse to fragment.
     */
    @Test
    fun a_relayed_path_whose_legs_differ_takes_the_more_constrained_family() {
        val v4SocketV6Peer = riding(relayed(relayed = relay, localBind = alice), host(bobV6))
        val adopted = assertIs<PathObservation.Adopted>(DataPathFold().observe(v4SocketV6Peer))
        assertEquals(PathAddressFamily.Ipv6, adopted.profile.family, "the IPv6 leg is the one that will not fragment")
        assertEquals(PathOverheadBytes(20 + 8 + 37 + 48), adopted.profile.overhead, "…while our own leg still writes an IPv4 header")
    }

    private companion object {
        // RFC 8445 §5.1.2.2's top local preference; the ICE core keeps its own copy private.
        private const val MAX_LOCAL_PREFERENCE = 65535
    }
}

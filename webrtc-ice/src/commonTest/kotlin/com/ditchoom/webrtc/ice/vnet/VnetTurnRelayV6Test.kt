@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.flow.AddressFamily
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.TurnAllocation
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * Regression for the routed-IPv6 TURN-relay bug the harness surfaced (v6 lanes hung at ICE
 * `AllPairsFailed`): the client's Allocate omitted `REQUESTED-ADDRESS-FAMILY`, so — per RFC 8656 §7.2 —
 * the server defaulted to an **IPv4** relay, which on a v6-only TURN server is an unusable loopback
 * address (`127.0.0.1`), a relay candidate no peer can reach.
 *
 * The [TurnServer] here is coturn-faithful: its relay is IPv6, so it refuses (440) any Allocate that does
 * not ask for an IPv6 relay. So this test fails (allocate → null) against the old client and passes only
 * once [TurnAllocation] sends `REQUESTED-ADDRESS-FAMILY=IPv6` for a v6 server. Flat vnet (no NAT — the
 * bug is in the allocation request, not traversal), all under `runTest` virtual time.
 */
class VnetTurnRelayV6Test {
    @Test
    fun turn_allocate_over_a_v6_server_obtains_a_v6_relay_not_a_loopback_fallback() =
        runTest {
            val vnet = Vnets.flat()
            val turnAddress = vnetAddress("2001:db8:30::10", 3478)
            TurnServer(
                address = turnAddress,
                vnet = vnet,
                scope = backgroundScope,
                keyProvider = { u -> if (u == Vnets.TURN_USERNAME) utf8Buffer(Vnets.TURN_PASSWORD) else null },
            ).start()

            val underlying = vnet.bind(vnetAddress("fd00:31::100", 40000))
            val allocation =
                TurnAllocation(underlying, turnAddress, Vnets.TURN_USERNAME, Vnets.TURN_PASSWORD, Random(1), backgroundScope)

            val relayed = allocation.allocate()
            assertNotNull(
                relayed,
                "the TURN client must obtain a relay over a v6 server (Allocate must carry REQUESTED-ADDRESS-FAMILY=IPv6)",
            )
            assertEquals(AddressFamily.IPv6, relayed.family, "the relayed address must be IPv6, not a defaulted v4/loopback relay")
        }
}

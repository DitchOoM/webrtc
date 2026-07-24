@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.stun.IpAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * **Dual-stack traversal over a broken v6 path** (the happy-eyeballs fallback) — the counterpart to
 * `IceDualStackTest`, which proves a dual-stack agent *prefers* IPv6 when it works. Here the v6 path is
 * administratively broken (a `RoutedFirewall` with nothing allow-listed drops every v6 datagram to a LAN
 * host) while the v4 path is two full-cone NATs with a working STUN. So the (higher-priority) v6 host
 * pair can never complete and ICE must fall back to the v4 server-reflexive path — the realistic
 * "IPv6 advertised but unusable" case that a NAT-only or v6-only fixture cannot express. One
 * [com.ditchoom.webrtc.ice.vnet.FamilyFabric] carries both stacks, under `runTest` virtual time on every
 * platform. Observable state + watchdog only (directive #4).
 */
@OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)
class IceDualStackNatTest {
    @Test
    fun a_broken_v6_path_falls_back_to_the_v4_server_reflexive_pair() =
        runTest {
            val meetup = Vnets.dualStackV6BrokenV4Works(backgroundScope)
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 71, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 72, vnet = meetup.vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()

            // Each agent advertises a (preferred) v6 host — firewall-blocked — and a v4 host+srflx that works.
            alice.bindHost("fd00:31::100", 5000) // v6: no STUN, blocked for direct — the dead path
            alice.bindHost("10.0.0.2", 5000, stunServer = meetup.stunAddress) // v4: srflx via full-cone NAT
            bob.bindHost("fd00:32::100", 5000)
            bob.bindHost("10.0.1.2", 5000, stunServer = meetup.stunAddress)
            alice.connectTo(bob)
            bob.connectTo(alice)

            assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "Alice falls back to v4 and connects")
            assertNotNull(withTimeoutOrNull(TIMEOUT) { bob.awaitConnected() }, "Bob falls back to v4 and connects")

            // Despite v6 out-ranking v4, the unusable v6 pair is abandoned for the working v4 srflx path.
            val pair = alice.selectedPair!!
            assertTrue(pair.local.address.ip is IpAddress.V4, "the selected pair is IPv4 (v6 was advertised but unreachable)")
            assertTrue(pair.remote.address.ip is IpAddress.V4, "and the remote is IPv4 too")
            // A hole-punched srflx pair reports local=Host (the srflx's base socket) + remote=ServerReflexive,
            // the same convention IceNatFixtureTest.full_cone asserts on — the working path is v4 srflx, not v6.
            assertEquals(
                CandidateType.ServerReflexive,
                pair.remote.type,
                "the working v4 path is server-reflexive through the full-cone NAT, got remote=${pair.remote.type}",
            )
        }

    private companion object {
        val TIMEOUT = 60.seconds
    }
}

@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.TurnAllocation
import com.ditchoom.webrtc.ice.TurnAllocationResult
import com.ditchoom.webrtc.ice.TurnMaintenance
import com.ditchoom.webrtc.ice.TurnPermissionRefusal
import com.ditchoom.webrtc.ice.toTransportAddress
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * **A refused permission used to be indistinguishable from a dead network.**
 *
 * `TurnAllocation.ensurePermission` installed a permission on success and did *nothing at all* on a
 * refusal — no retry decision to make, and nowhere to say what happened. So a TURN server that answered
 * "443, that peer is the wrong address family" produced exactly the same observable as a peer that never
 * replied: connectivity checks leaving, nothing coming back, and the session ending at
 * `IceFailureReason.NoCandidatePairs`, which names the symptom and points at the network. That is how a
 * dual-stack `relay-only` lane burned two investigations whose only evidence was a packet capture.
 *
 * These fixtures pin the observation, not the recovery — the client's *behaviour* on a refusal is
 * deliberately unchanged (leave the peer un-permitted, let the next send retry). What must not regress is
 * that the refusal is **reported, typed, and attributed**: which allocation, which peer, which code.
 *
 * Both emit sites are covered, because they are reachable only from opposite sides of the permission's
 * life: the **send path** refuses the first install, and the **maintenance path** (§9) refuses a
 * re-installation of one that was working — the silent, inbound-only lapse. Anti-vacuity runs the same
 * topology against a server that grants, and asserts nothing is reported.
 */
class VnetTurnPermissionRefusedTest {
    @Test
    fun a_peer_of_the_wrong_family_is_reported_443_rather_than_silently_unreachable() =
        runTest {
            // The real shape: a v6 allocation asked to permit a v4 peer. RFC 6156 §9.1 refuses it, and a
            // correct client still meets this whenever a server reports an allocation at the wrong family.
            val relay = allocateOn(relayIp = "2001:db8:30::10", clientIp = "fd00:31::100")
            val v4Peer = vnetAddress("172.30.0.50", 5000)

            relay.allocation.send(utf8Buffer("probe"), to = v4Peer)

            val refusal = assertNotNull(relay.firstRefusal(), "a refused CreatePermission must be reported, not swallowed")
            assertEquals(PEER_ADDRESS_FAMILY_MISMATCH, refusal.error.code, "the code must be the server's 443, verbatim")
            assertEquals(v4Peer.toTransportAddress(), refusal.peer, "the refusal must name the peer it was for")
            assertEquals(
                relay.relayed.toTransportAddress(),
                refusal.relay,
                "the refusal must name the allocation that refused — a dual-stack session holds more than one",
            )
            assertTrue(relay.server.permissionRefusals >= 1, "the server must actually have refused (not a vacuous pass)")
            assertEquals(0, relay.server.permissionInstalls, "and must not have granted the permission it refused")
        }

    @Test
    fun a_policy_refusal_on_the_send_path_is_reported_with_the_servers_own_code() =
        runTest {
            // Same observation, different code and no family involved: the server's policy simply says no.
            val relay = allocateOn(refusePermissionsAfter = 0)
            val peer = vnetAddress("10.0.0.50", 5000)

            relay.allocation.send(utf8Buffer("probe"), to = peer)

            val refusal = assertNotNull(relay.firstRefusal(), "a 403 must be reported exactly as a 443 is")
            assertEquals(FORBIDDEN, refusal.error.code, "the code is the discriminant and must survive the trip intact")
            assertEquals(peer.toTransportAddress(), refusal.peer)
        }

    @Test
    fun a_permission_that_lapses_because_its_re_installation_was_refused_is_reported_too() =
        runTest {
            // The inbound-only failure: the permission installs, works, and is then refused on renewal. The
            // send path never asks again — `permitted` still holds the peer — so without this the path goes
            // quiet in one direction with nothing anywhere to say why.
            val relay =
                allocateOn(
                    refusePermissionsAfter = 1,
                    maintenance = TurnMaintenance.Renewing(permissionLifetime = PERMISSION_LIFETIME),
                )
            val peer = vnetAddress("10.0.0.50", 5000)

            relay.allocation.send(utf8Buffer("probe"), to = peer)
            assertEquals(1, relay.server.permissionInstalls, "the first install must succeed, or this proves nothing about renewal")
            assertNull(relay.firstRefusal(within = BEFORE_FIRST_RENEWAL), "and must not report anything")

            // Virtual time only (directive #4): far enough for the re-installation to come due and be refused.
            val refusal =
                assertNotNull(relay.firstRefusal(within = PERMISSION_LIFETIME * 2), "the refused RE-installation must be reported")
            assertEquals(FORBIDDEN, refusal.error.code)
            assertEquals(peer.toTransportAddress(), refusal.peer, "§9 refuses the whole request, so every peer in it is named")
        }

    @Test
    fun a_granted_permission_reports_nothing() =
        runTest {
            // Anti-vacuity. The same topology against a server that grants must stay silent — a fixture that
            // reported a refusal either way would be pinning the plumbing, not the condition.
            val relay = allocateOn(maintenance = TurnMaintenance.Renewing(permissionLifetime = PERMISSION_LIFETIME))
            val peer = vnetAddress("10.0.0.50", 5000)

            relay.allocation.send(utf8Buffer("probe"), to = peer)

            assertNull(
                relay.firstRefusal(within = PERMISSION_LIFETIME * 2),
                "a granted permission — and every renewal of it — must report nothing",
            )
            assertTrue(
                relay.server.permissionInstalls >= 2,
                "the fixture must have exercised a renewal, got ${relay.server.permissionInstalls}",
            )
            assertEquals(0, relay.server.permissionRefusals, "and the server must not have refused anything")
        }

    private class Relayed(
        val allocation: TurnAllocation,
        val server: TurnServer,
        val relayed: SocketAddress,
    ) {
        /**
         * The next reported refusal, or null if none arrives within [within]. The flow is Channel-backed, so
         * a refusal emitted before this call is already buffered and returns immediately — which is why no
         * collector has to be attached in advance.
         */
        suspend fun firstRefusal(within: Duration = REPORT_WATCHDOG): TurnPermissionRefusal? =
            withTimeoutOrNull(within) { allocation.permissionRefused.first() }
    }

    private suspend fun TestScope.allocateOn(
        relayIp: String = "10.0.0.10",
        clientIp: String = "10.0.0.2",
        refusePermissionsAfter: Int = Int.MAX_VALUE,
        maintenance: TurnMaintenance = TurnMaintenance.None,
    ): Relayed {
        val vnet = Vnets.flat()
        val turnAddress = vnetAddress(relayIp, 3478)
        val server =
            TurnServer(
                address = turnAddress,
                vnet = vnet,
                scope = backgroundScope,
                keyProvider = Vnets.turnKeyProvider(),
                permissionLifetimeSeconds = PERMISSION_LIFETIME.inWholeSeconds.toUInt(),
                refusePermissionsAfter = refusePermissionsAfter,
            )
        server.start()
        val underlying = vnet.bind(vnetAddress(clientIp, 40000))
        val allocation =
            TurnAllocation(
                underlying,
                turnAddress,
                Vnets.TURN_USERNAME,
                Vnets.TURN_PASSWORD,
                Random(1),
                backgroundScope,
                maintenance = maintenance,
            )
        val relayed = assertIs<TurnAllocationResult.Allocated>(allocation.allocate(), "the fixture needs a live allocation").relayed
        return Relayed(allocation, server, relayed)
    }

    private companion object {
        const val PEER_ADDRESS_FAMILY_MISMATCH = 443
        const val FORBIDDEN = 403

        /** Compressed from coturn's 300 s so a renewal lands early in virtual time; every ratio is unchanged. */
        val PERMISSION_LIFETIME: Duration = 20.seconds

        /** Watchdog, never a budget (directive #4) — a reported refusal is already buffered when asked for. */
        val REPORT_WATCHDOG: Duration = 5.seconds

        /** Short of the first re-installation (0.75 x 20 s), so "nothing reported yet" means what it says. */
        val BEFORE_FIRST_RENEWAL: Duration = 1.seconds
    }
}

@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Datagram
import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * **W2 vnet exit criterion** (TESTING.md): each NAT type *provably filters per its definition*, and a
 * two-peer echo runs over each topology under virtual time. These are property tests over the [Nat]
 * fabric — no ICE yet, just raw datagrams — so the NAT model is trustworthy *before* the ICE agent
 * relies on its behavior. A dropped datagram is asserted with a virtual-time [receiveWithin] timeout
 * (standing directive #4: observe state, never a wall-clock budget); a real drop trips the timeout and
 * returns null at zero wall-clock.
 */
@OptIn(ExperimentalDatagramApi::class)
class VnetNatTest {
    // Two public reflectors on distinct IPs, and a third port on the first IP — enough to distinguish
    // endpoint-independent / address-dependent / address-and-port-dependent behavior.
    private val reflector1 = vnetAddress("203.0.113.2", 3478)
    private val reflector1AltPort = vnetAddress("203.0.113.2", 9999)
    private val reflector2 = vnetAddress("203.0.113.3", 3478)
    private val host = vnetAddress("10.0.0.2", 5000)

    @Test
    fun full_cone_mapping_is_endpoint_independent_and_openly_filtered() =
        runTest {
            val nat = Vnets.nat("203.0.113.10", "10.0.0.", NatProfile.FullCone)
            val vnet = Vnets.behindNats(listOf(nat))
            val hostCh = vnet.bind(host)
            val r1 = vnet.bind(reflector1)
            val r2 = vnet.bind(reflector2)

            val mappingViaR1 = probeMapping(hostCh, r1, reflector1)
            val mappingViaR2 = probeMapping(hostCh, r2, reflector2)
            assertEquals(mappingViaR1, mappingViaR2, "endpoint-independent mapping: one external port for all peers")

            // Endpoint-independent filtering: a reflector the host never contacted still reaches the mapping.
            r2.send(payload("unsolicited"), to = mappingViaR1)
            assertEquals("unsolicited", hostCh.receiveWithin(TIMEOUT)?.text(), "full cone admits any external sender")
        }

    @Test
    fun symmetric_mapping_is_per_destination() =
        runTest {
            val nat = Vnets.nat("203.0.113.10", "10.0.0.", NatProfile.Symmetric)
            val vnet = Vnets.behindNats(listOf(nat))
            val hostCh = vnet.bind(host)
            val r1 = vnet.bind(reflector1)
            val r2 = vnet.bind(reflector2)

            val mappingViaR1 = probeMapping(hostCh, r1, reflector1)
            val mappingViaR2 = probeMapping(hostCh, r2, reflector2)
            assertNotEquals(mappingViaR1, mappingViaR2, "symmetric NAT: a fresh mapping per destination — srflx is useless")

            // The mapping learned toward r1 rejects r2 (strict filtering) — no third party can use it.
            r2.send(payload("intruder"), to = mappingViaR1)
            assertNull(hostCh.receiveWithin(TIMEOUT), "symmetric filtering rejects an endpoint the host never addressed")
        }

    @Test
    fun address_restricted_admits_same_ip_rejects_other_ip() =
        runTest {
            val nat = Vnets.nat("203.0.113.10", "10.0.0.", NatProfile.AddressRestrictedCone)
            val vnet = Vnets.behindNats(listOf(nat))
            val hostCh = vnet.bind(host)
            val r1 = vnet.bind(reflector1)
            val r1Alt = vnet.bind(reflector1AltPort)
            val r2 = vnet.bind(reflector2)

            val mapping = probeMapping(hostCh, r1, reflector1)

            // Same IP, different port: admitted (filtering is per-address, not per-port).
            r1Alt.send(payload("same-ip-diff-port"), to = mapping)
            assertEquals(
                "same-ip-diff-port",
                hostCh.receiveWithin(TIMEOUT)?.text(),
                "address-dependent filtering admits any port on a contacted IP",
            )

            // Different IP: rejected.
            r2.send(payload("other-ip"), to = mapping)
            assertNull(hostCh.receiveWithin(TIMEOUT), "address-dependent filtering rejects an uncontacted IP")
        }

    @Test
    fun port_restricted_rejects_different_port_on_same_ip() =
        runTest {
            val nat = Vnets.nat("203.0.113.10", "10.0.0.", NatProfile.PortRestrictedCone)
            val vnet = Vnets.behindNats(listOf(nat))
            val hostCh = vnet.bind(host)
            val r1 = vnet.bind(reflector1)
            val r1Alt = vnet.bind(reflector1AltPort)

            val mapping = probeMapping(hostCh, r1, reflector1)

            r1Alt.send(payload("diff-port"), to = mapping)
            assertNull(hostCh.receiveWithin(TIMEOUT), "port-dependent filtering rejects a different port on a contacted IP")

            // The exact contacted transport address is still admitted.
            r1.send(payload("exact"), to = mapping)
            assertEquals("exact", hostCh.receiveWithin(TIMEOUT)?.text(), "the exact contacted IP:port is admitted")
        }

    @Test
    fun cross_private_segments_have_no_direct_route() =
        runTest {
            val natA = Vnets.nat("203.0.113.10", "10.0.0.", NatProfile.FullCone)
            val natB = Vnets.nat("203.0.113.20", "10.0.1.", NatProfile.FullCone)
            val vnet = Vnets.behindNats(listOf(natA, natB))
            val alice = vnet.bind(vnetAddress("10.0.0.2", 5000))
            val bobAddr = vnetAddress("10.0.1.2", 5000)
            val bob = vnet.bind(bobAddr)

            // A private address in another segment is unreachable — the relay-forcing drop (RFC §5.2).
            alice.send(payload("straight to your LAN"), to = bobAddr)
            assertNull(bob.receiveWithin(TIMEOUT), "two private LANs have no route except through the public segment")
        }

    @Test
    fun hole_punch_echo_over_port_restricted_nats() =
        runTest {
            val natA = Vnets.nat("203.0.113.10", "10.0.0.", NatProfile.PortRestrictedCone)
            val natB = Vnets.nat("203.0.113.20", "10.0.1.", NatProfile.PortRestrictedCone)
            val vnet = Vnets.behindNats(listOf(natA, natB))
            val alice = vnet.bind(vnetAddress("10.0.0.2", 5000))
            val bob = vnet.bind(vnetAddress("10.0.1.2", 5000))
            val reflector = vnet.bind(reflector1)

            // Each peer learns its own external mapping (as ICE would via STUN)...
            val aliceMapping = probeMapping(alice, reflector, reflector1)
            val bobMapping = probeMapping(bob, reflector, reflector1)

            // ...then both punch toward the other's mapping, opening each NAT's port-restricted filter.
            alice.send(payload("punch a→b"), to = bobMapping)
            bob.send(payload("punch b→a"), to = aliceMapping)
            // The first punches may cross in flight; drain whatever landed, then the hole is open.
            bob.receiveWithin(TIMEOUT)
            alice.receiveWithin(TIMEOUT)

            alice.send(payload("ping"), to = bobMapping)
            val atBob = bob.receiveWithin(TIMEOUT)
            assertTrue(atBob != null && atBob.text() == "ping", "the punched hole carries the ping")
            bob.send(payload("pong"), to = atBob.peer)
            assertEquals("pong", alice.receiveWithin(TIMEOUT)?.text(), "and the echo returns through the reciprocal hole")
        }

    // Send a probe to [reflectorAddress] and read back the source the reflector observed — the host's
    // external mapping for that destination (endpoint-independent NATs reuse it; symmetric NATs don't).
    private suspend fun probeMapping(
        sender: DatagramChannel,
        reflectorChannel: DatagramChannel,
        reflectorAddress: SocketAddress,
    ): SocketAddress {
        sender.send(payload("probe"), to = reflectorAddress)
        val probe = reflectorChannel.receiveWithin(TIMEOUT) ?: error("probe never reached the reflector at $reflectorAddress")
        return probe.peer
    }

    private fun payload(text: String): ReadBuffer = utf8Buffer(text)

    private fun Datagram.text(): String = payload.readString(payload.remaining(), Charset.UTF8)

    private suspend fun DatagramChannel.receiveWithin(within: Duration): Datagram? =
        withTimeoutOrNull(within) {
            when (val result = receive()) {
                is DatagramReadResult.Received -> result.datagram
                is DatagramReadResult.Closed -> null
            }
        }

    private companion object {
        val TIMEOUT = 2.seconds
    }
}

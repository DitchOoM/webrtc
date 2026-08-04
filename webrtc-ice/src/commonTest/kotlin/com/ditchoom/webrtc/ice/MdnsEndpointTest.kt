@file:OptIn(ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.flow.AddressFamily
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.vnet.CountingBufferFactory
import com.ditchoom.webrtc.ice.vnet.LeakTrackingFactory
import com.ditchoom.webrtc.ice.vnet.Vnet
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import com.ditchoom.webrtc.stun.IpAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The **whole** mDNS story end to end, deterministically: one [MdnsEndpoint] advertises a `<uuid>.local`
 * name for its host address, another — which knows only the name — resolves it over a link-local multicast
 * group, and the address comes back. Both are the production class; only [MdnsMulticastBinder] is
 * substituted, which is the single line of the design that is platform-specific.
 *
 * That substitution is the point. Everything from the RFC 1035 message bytes through the RFC 6762 §6
 * responder, the shared-socket dispatch and the resolution round trip runs here under `runTest`, on every
 * target, with no OS socket anywhere — so a wire-level mDNS regression is reproducible as a seeded fixture
 * rather than as a container lane.
 */
class MdnsEndpointTest {
    @Test
    fun a_peer_that_knows_only_the_name_resolves_the_address_behind_it() =
        runTest {
            val link = MdnsLink(this)
            val advertiser = link.endpoint(ALICE_IP, seed = 1)
            val resolver = link.endpoint(BOB_IP, seed = 2)

            val name = assertIs<MdnsAdvertisement.Advertised>(advertiser.advertise(ALICE_ADDRESS)).name

            // The resolving side is handed the NAME and nothing else — no address, which is the entire
            // point of RFC 8828: what crosses the signaling server must not identify the private network.
            val resolution = assertIs<MdnsResolution.Resolved>(resolver.resolve(name.value))
            assertEquals(ALICE_IP, resolution.address.host, "the name resolved to the address it was minted for")
        }

    @Test
    fun a_name_nobody_advertises_stays_unresolved() =
        runTest {
            // The causality proof for the fixture above: the same link, the same two endpoints, the same
            // query — and no advertisement. The resolution has to come from the responder, not from the
            // fixture's own knowledge of the address.
            val link = MdnsLink(this)
            link.endpoint(ALICE_IP, seed = 1)
            val resolver = link.endpoint(BOB_IP, seed = 2)

            assertEquals(
                MdnsResolution.Unresolved,
                resolver.resolve("bd1a3f9c-1f4e-4a1d-9c2b-5f8e0a7d3c11.local"),
                "nothing answers for a name nobody minted — the resolver gives up rather than inventing one",
            )
        }

    @Test
    fun a_second_candidate_on_the_same_address_publishes_the_same_name() =
        runTest {
            // "Stable per session, per host candidate": two names for one interface would tell an observer
            // they belong to one host just as loudly as the address would have — and a re-gather after an
            // ICE restart is exactly when a second name would appear.
            val link = MdnsLink(this)
            val endpoint = link.endpoint(ALICE_IP, seed = 1)

            val first = assertIs<MdnsAdvertisement.Advertised>(endpoint.advertise(ALICE_ADDRESS)).name
            val second = assertIs<MdnsAdvertisement.Advertised>(endpoint.advertise(ALICE_ADDRESS)).name

            assertEquals(first, second, "one address, one name, for the life of the session")
            assertEquals(setOf(first), endpoint.advertisedNames, "and one record, not two")
        }

    @Test
    fun two_addresses_get_two_unlinkable_names() =
        runTest {
            val link = MdnsLink(this)
            val endpoint = link.endpoint(ALICE_IP, seed = 1)

            val first = assertIs<MdnsAdvertisement.Advertised>(endpoint.advertise(ALICE_ADDRESS)).name
            val second = assertIs<MdnsAdvertisement.Advertised>(endpoint.advertise(SECOND_ADDRESS)).name

            assertTrue(first != second, "a second interface is a second name")
            assertEquals(2, endpoint.advertisedNames.size)
        }

    @Test
    fun a_withdrawn_name_stops_resolving() =
        runTest {
            val link = MdnsLink(this)
            val advertiser = link.endpoint(ALICE_IP, seed = 1)
            val resolver = link.endpoint(BOB_IP, seed = 2)
            val name = assertIs<MdnsAdvertisement.Advertised>(advertiser.advertise(ALICE_ADDRESS)).name
            assertIs<MdnsResolution.Resolved>(resolver.resolve(name.value), "advertised: resolvable")

            advertiser.withdraw(name)

            assertEquals(
                MdnsResolution.Unresolved,
                resolver.resolve(name.value),
                "a withdrawn name is nobody's again — answering it would leak a stale address",
            )
        }

    /**
     * …and the withdrawal is **announced**, not merely local (RFC 6762 §10.1, webrtc#105).
     *
     * Going quiet is not enough: the shared TTL is 120 s, so a peer that already resolved the name keeps
     * using it for up to two minutes. Since network reactivity landed (#98) an interface can vanish
     * mid-session and the replacement gets a *different* name, which puts that stale binding directly on
     * the path reactivity exists to make fast.
     *
     * Read off the wire on a third endpoint joined to the group — an observer, not either participant —
     * because "the retraction reached the link" is the property, and a return value cannot show it.
     */
    @Test
    fun a_withdrawal_multicasts_a_ttl_zero_goodbye_to_the_group() =
        runTest {
            val link = MdnsLink(this)
            val advertiser = link.endpoint(ALICE_IP, seed = 1)
            val observer = link.observer(OBSERVER_IP)
            val name = assertIs<MdnsAdvertisement.Advertised>(advertiser.advertise(ALICE_ADDRESS)).name

            advertiser.withdraw(name)

            val datagram =
                assertNotNull(
                    withTimeoutOrNull(TIMEOUT) {
                        when (val result = observer.receive()) {
                            is DatagramReadResult.Received -> result.datagram.payload
                            is DatagramReadResult.Closed -> null
                        }
                    },
                    "nothing reached the group: the name was dropped locally and every peer holding it was " +
                        "left resolving a dead address for the remaining 120s shared TTL",
                )

            // Header: an authoritative response with one answer and no echoed question.
            datagram.readUnsignedShort() // ID
            datagram.readUnsignedShort() // flags
            assertEquals(0, datagram.readUnsignedShort().toInt(), "unsolicited — nothing to echo")
            assertEquals(1, datagram.readUnsignedShort().toInt(), "exactly the record being retracted")
            datagram.readUnsignedShort() // NSCOUNT
            datagram.readUnsignedShort() // ARCOUNT
            while (true) {
                val length = datagram.readUnsignedByte().toInt()
                if (length == 0) break
                repeat(length) { datagram.readUnsignedByte() }
            }
            datagram.readUnsignedShort() // TYPE
            datagram.readUnsignedShort() // CLASS
            assertEquals(0u, datagram.readUnsignedInt(), "TTL 0 is the retraction; any other value is an announcement")
        }

    @Test
    fun a_family_the_endpoint_does_not_serve_is_declined_rather_than_published_unanswerable() =
        runTest {
            val link = MdnsLink(this)
            val v4Only = link.endpoint(ALICE_IP, seed = 1, families = listOf(AddressFamily.IPv4))

            val declined = assertIs<MdnsAdvertisement.Declined>(v4Only.advertise(V6_ADDRESS))
            assertEquals(
                MdnsDeclineReason.UnsupportedFamily,
                declined.reason,
                "a name nothing will answer for is worse than an address in the clear — so it is refused, typed",
            )
        }

    @Test
    fun an_endpoint_that_cannot_join_the_group_declines_instead_of_failing_the_session() =
        runTest {
            // A container without the capability, a host with no multicast route. Connectivity must survive
            // it; only privacy is lost, and the caller is told exactly that.
            val endpoint = MdnsEndpoint(backgroundScope, { MdnsGroupBinding.Unavailable }, random = Random(1))

            val declined = assertIs<MdnsAdvertisement.Declined>(endpoint.advertise(ALICE_ADDRESS))
            assertEquals(MdnsDeclineReason.GroupUnavailable, declined.reason)
            assertEquals(MdnsResolution.Unresolved, endpoint.resolve("anything.local"), "and it resolves nothing either")
        }

    @Test
    fun a_query_for_a_name_that_is_not_a_dot_local_never_reaches_the_link() =
        runTest {
            val link = MdnsLink(this)
            val resolver = link.endpoint(BOB_IP, seed = 2)
            assertEquals(MdnsResolution.Unresolved, resolver.resolve("example.com"))
            assertEquals(0, link.datagrams, "mDNS is the `.local` namespace and nothing else — no query was sent")
        }

    /**
     * Every buffer mDNS builds comes back (directive #6) — across the three things this feature actually
     * allocates for, which are the three it sends: the querier's question, the responder's answer, and the
     * goodbye that retracts a name.
     *
     * Two trackers rather than one, because each endpoint has to be answerable on its own: the resolver
     * never builds an answer and the advertiser never builds a query, so a single shared tracker would let
     * one side's diligence cover for the other's. Neither goes to the vnet, whose copy-on-receive allocates
     * from the same seam and would attribute the harness's buffers to production code.
     */
    @Test
    fun every_buffer_mdns_sends_comes_back() =
        runTest {
            val link = MdnsLink(this)
            val advertiserBuffers = LeakTrackingFactory()
            val resolverBuffers = LeakTrackingFactory()
            val advertiser = link.endpoint(ALICE_IP, seed = 1, bufferFactory = advertiserBuffers)
            val resolver = link.endpoint(BOB_IP, seed = 2, bufferFactory = resolverBuffers)

            val name = assertIs<MdnsAdvertisement.Advertised>(advertiser.advertise(ALICE_ADDRESS)).name
            assertIs<MdnsResolution.Resolved>(resolver.resolve(name.value), "the round trip happened at all")
            advertiser.withdraw(name)
            // The answer is released by the advertiser's dispatch loop, which is a background coroutine:
            // let it run before asking whether it did.
            testScheduler.advanceUntilIdle()

            advertiserBuffers.assertNoLeaks("an mDNS advertiser that answered a query and then withdrew")
            resolverBuffers.assertNoLeaks("an mDNS resolver that queried for a name")
        }

    // ---- fixture plumbing ---------------------------------------------------------------------------

    /**
     * A link-local segment with a real multicast group on it: every endpoint binds its own vnet channel at
     * `<ip>:5353` and joins the group, so a datagram sent to the group reaches all of them but its sender.
     * This is the one datagram behaviour a `.local` name depends on — the querier does not know, and must not
     * need, the responder's address.
     */
    private class MdnsLink(
        private val scope: TestScope,
    ) {
        // The vnet allocates exactly one buffer per DELIVERED datagram (its copy-on-send rule), so this
        // counts what actually crossed the segment.
        private val traffic = CountingBufferFactory(BufferFactory.Default)
        private val vnet: Vnet = Vnets.flat(traffic)

        val datagrams: Int get() = traffic.handedOut

        fun endpoint(
            ip: String,
            seed: Long,
            families: List<AddressFamily> = listOf(AddressFamily.IPv4),
            bufferFactory: BufferFactory = BufferFactory.Default,
        ): MdnsEndpoint =
            MdnsEndpoint(
                scope = scope.backgroundScope,
                binder = VnetBinder(vnet, ip),
                families = families,
                bufferFactory = bufferFactory,
                random = Random(seed),
            )

        /**
         * A bare channel joined to the group — neither advertiser nor resolver, just something on the link
         * that can read what was multicast. The only way to assert that a goodbye actually left.
         */
        fun observer(ip: String): AddressedDatagramChannel {
            val local = vnetAddress(ip, MDNS_UDP_PORT)
            val channel = vnet.bind(local)
            vnet.join(GROUP, local)
            return channel
        }

        /** Binds `<ip>:5353` on the vnet and joins the group — the [MdnsMulticastBinder] actual, in memory. */
        private class VnetBinder(
            private val vnet: Vnet,
            private val ip: String,
        ) : MdnsMulticastBinder {
            override suspend fun bind(family: AddressFamily): MdnsGroupBinding {
                val local = vnetAddress(ip, MDNS_UDP_PORT)
                val channel = vnet.bind(local)
                vnet.join(GROUP, local)
                return MdnsGroupBinding.Bound(MdnsGroupSocket(channel, GROUP))
            }
        }
    }

    private companion object {
        const val ALICE_IP = "10.0.0.1"
        const val BOB_IP = "10.0.0.2"
        const val OBSERVER_IP = "10.0.0.3"
        val TIMEOUT = 10.seconds
        val GROUP: SocketAddress = vnetAddress("224.0.0.251", MDNS_UDP_PORT)
        val ALICE_ADDRESS: IpAddress = IpAddress.V4(0x0A000001u) // 10.0.0.1
        val SECOND_ADDRESS: IpAddress = IpAddress.V4(0x0A000005u) // 10.0.0.5
        val V6_ADDRESS: IpAddress = IpAddress.V6.parse("fd00:31::100")!!
    }
}

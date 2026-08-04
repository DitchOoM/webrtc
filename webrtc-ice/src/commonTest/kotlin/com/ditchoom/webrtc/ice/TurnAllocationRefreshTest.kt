@file:OptIn(ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.vnet.NoncePolicy
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.ice.vnet.utf8Buffer
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import com.ditchoom.webrtc.stun.StunClass
import com.ditchoom.webrtc.stun.StunDecodeResult
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.StunMethod
import com.ditchoom.webrtc.stun.TransactionId
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * **A relayed session outliving the server's LIFETIME** (issue #137). A TURN allocation and its
 * permissions expire on the *server's* clock — coturn defaults to 600 s and 300 s, both shorter than an
 * ordinary call — so a client that never sends Refresh (RFC 8656 §8) and never re-installs its
 * permissions (§9) loses its relay mid-session. For a peer behind a symmetric NAT the relay is the only
 * path, so that is not a degradation, it is the call dropping.
 *
 * The topology is deliberately the smallest one that shows **both** directions failing: one production
 * [TurnAllocation] behind a symmetric NAT, and one plain public endpoint it relays to. That keeps a single
 * allocation and a single permission in play, so an assertion names exactly one thing. The server's
 * lifetimes are compressed (60 s / 20 s, from coturn's 600 / 300) purely so the interesting part starts
 * early in virtual time; every ratio the client reasons about is unchanged.
 *
 * The observable is the relayed round trip itself, probed on a cadence that is coprime with both
 * lifetimes so no probe lands on a boundary, with `withTimeoutOrNull` as the watchdog and `runTest`
 * virtual time as the clock (directive #4 — never a wall-clock budget). The server's Refresh and
 * CreatePermission counters are asserted too, so a pass means the client *did the work*, not merely that
 * nothing was observed to break.
 *
 * **Anti-vacuity is a first-class test here, not a footnote.** The same scenario runs with
 * [TurnMaintenance.None] and must **fail** — the relay dies, and it dies at the first probe after the
 * permission lifetime. A fixture that passed both ways would prove nothing about the fix.
 */
class TurnAllocationRefreshTest {
    @Test
    fun a_relayed_path_survives_several_allocation_and_permission_lifetimes() =
        runTest {
            val run = relayForSeveralLifetimes(TurnMaintenance.Renewing(permissionLifetime = SERVER_PERMISSION_LIFETIME))

            assertEquals(
                emptyList(),
                run.lostAt,
                "every relayed round trip must survive: the allocation is refreshed and the permission re-installed",
            )
            assertTrue(
                run.probes >= PROBES,
                "the fixture must actually have probed across ${SESSION / SERVER_ALLOCATION_LIFETIME} allocation " +
                    "lifetimes and ${SESSION / SERVER_PERMISSION_LIFETIME} permission lifetimes, got ${run.probes} probes",
            )
            // Not "> 0": the point is that BOTH timers ran repeatedly. Refresh fires at 0.75 x 60 s and the
            // permission re-install at 0.75 x 20 s, so over 300 s that is at least 6 and at least 19.
            assertTrue(run.refreshes >= MIN_REFRESHES, "the client must have refreshed the allocation repeatedly, got ${run.refreshes}")
            assertTrue(
                run.permissionInstalls >= MIN_PERMISSION_INSTALLS,
                "the client must have re-installed the permission repeatedly, got ${run.permissionInstalls}",
            )
        }

    @Test
    fun anti_vacuity_without_maintenance_the_same_relay_dies_at_the_permission_lifetime() =
        runTest {
            val run = relayForSeveralLifetimes(TurnMaintenance.None)

            assertTrue(run.deliveredAt.isNotEmpty(), "the relay must work at first — otherwise the fixture proves nothing about expiry")
            assertTrue(run.lostAt.isNotEmpty(), "WITHOUT refresh the relayed path MUST die; a fixture that passes both ways proves nothing")
            assertEquals(0, run.refreshes, "TurnMaintenance.None must send no Refresh at all while the session is up")
            assertEquals(
                1,
                run.permissionInstalls,
                "TurnMaintenance.None installs the permission once, on first use, and never renews it",
            )

            // And it dies exactly where RFC 8656 says it will: the first probe after the permission lapses.
            val lastGood = assertNotNull(run.deliveredAt.lastOrNull(), "expected at least one delivered probe")
            val firstLost = run.lostAt.first()
            assertTrue(
                lastGood < SERVER_PERMISSION_LIFETIME && firstLost >= SERVER_PERMISSION_LIFETIME,
                "the break must straddle the $SERVER_PERMISSION_LIFETIME permission lifetime, not the allocation's: " +
                    "last delivered at $lastGood, first lost at $firstLost",
            )
        }

    @Test
    fun a_stale_nonce_is_re_read_and_the_request_retried_once() =
        runTest {
            // The server rotates its NONCE after every granted request, so every keep-alive the client
            // sends is answered 438 the first time. RFC 8656 §8: that is a normal event in the life of a
            // long-lived allocation, and a client that cannot re-read the NONCE loses its relay at the
            // first rotation — which is exactly what the relay probes below would show.
            val run =
                relayForSeveralLifetimes(
                    TurnMaintenance.Renewing(permissionLifetime = SERVER_PERMISSION_LIFETIME),
                    noncePolicy = NoncePolicy.RotateEvery(afterRequests = 1),
                )

            assertEquals(emptyList(), run.lostAt, "a rotating NONCE must not cost the session its relay — re-read it and retry")
            assertTrue(
                run.staleNonceChallenges >= MIN_REFRESHES,
                "the fixture must actually have driven the 438 path, got ${run.staleNonceChallenges} stale-nonce challenges",
            )
        }

    @Test
    fun every_turn_request_survives_losing_its_first_transmission() =
        runTest {
            // TURN runs over UDP and every request here — Allocate, CreatePermission, Refresh — used to be
            // sent exactly once. Drop transmission #1 of each and the session must still be indistinguishable
            // from a lossless one, because transmission #2 carries it 500 ms later.
            lateinit var channel: LossyTurnRequests
            val run =
                relayForSeveralLifetimes(
                    TurnMaintenance.Renewing(permissionLifetime = SERVER_PERMISSION_LIFETIME),
                    lossy = { inner, server -> LossyTurnRequests(inner, server) { _, nth -> nth == 1 }.also { channel = it } },
                )

            assertEquals(emptyList(), run.lostAt, "losing the first transmission of every request must cost nothing — it is retransmitted")
            assertTrue(run.refreshes >= MIN_REFRESHES, "the allocation was still refreshed on schedule, got ${run.refreshes}")
            // Anti-vacuity for the fixture itself: prove the drops happened rather than that the channel was inert.
            assertTrue(channel.dropped >= MIN_REFRESHES, "the fixture must actually have dropped requests, got ${channel.dropped}")
        }

    @Test
    fun an_unanswered_refresh_does_not_end_the_keep_alive_loop() =
        runTest {
            // The regression this exists for. `refreshAllocation` used to answer null for BOTH "the server
            // refused" and "nobody answered", and the loop treated null as terminal — so one lost Refresh
            // ended maintenance for good and the allocation died at the server's LIFETIME, which is the very
            // failure #137 was filed about. Blackhole the FIRST Refresh transaction entirely (every
            // retransmission of it), then let everything through: the loop must retry and recover.
            var refreshTransactions = 0
            lateinit var channel: LossyTurnRequests
            val run =
                relayForSeveralLifetimes(
                    TurnMaintenance.Renewing(permissionLifetime = SERVER_PERMISSION_LIFETIME),
                    lossy = { inner, server ->
                        LossyTurnRequests(inner, server) { method, nth ->
                            if (method == StunMethod.Refresh && nth == 1) refreshTransactions++
                            method == StunMethod.Refresh && refreshTransactions == 1
                        }.also { channel = it }
                    },
                )

            assertTrue(channel.dropped > 0, "the fixture must actually have blackholed a Refresh, got ${channel.dropped}")
            assertEquals(
                emptyList(),
                run.lostAt,
                "an unanswered Refresh must be retried, not treated as a dead allocation — the relay survives it",
            )
            // The recovery has to be visible in the server's counters too: a loop that quietly stopped would
            // still show the one Refresh it managed before dying.
            assertTrue(
                run.refreshes >= MIN_REFRESHES - 1,
                "maintenance kept running after the unanswered Refresh, got ${run.refreshes}",
            )
        }

    @Test
    fun anti_vacuity_without_retransmission_one_lost_datagram_costs_the_whole_allocation() =
        runTest {
            // The other half of the two tests above: with retransmission disabled, the SAME single dropped
            // datagram is terminal — and it fails as "no relay candidate", the least diagnosable shape there
            // is. A fixture that passed both ways would prove nothing about the retransmit loop.
            val meetup = Vnets.meetup(backgroundScope, turnLifetimeSeconds = SERVER_ALLOCATION_LIFETIME.inWholeSeconds.toUInt())
            val alice =
                TurnAllocation(
                    underlying =
                        LossyTurnRequests(meetup.vnet.bind(meetup.aliceHost), meetup.turnAddress) { _, nth -> nth == 1 },
                    server = meetup.turnAddress,
                    username = Vnets.TURN_USERNAME,
                    password = Vnets.TURN_PASSWORD,
                    random = Random(0x137),
                    scope = backgroundScope,
                    // Longer than the request's own budget, so each request is transmitted exactly once —
                    // the pre-fix behaviour, expressed as configuration rather than as a second code path.
                    retransmitInterval = NO_RETRANSMISSION,
                )
            try {
                assertEquals(
                    TurnAllocationResult.Unavailable.NoResponse,
                    withTimeoutOrNull(WATCHDOG) { alice.allocate() },
                    "one dropped Allocate with no retransmission must lose the allocation outright",
                )
                assertEquals(0, meetup.turn.activeAllocations, "and the server never held an allocation for it")
            } finally {
                alice.close()
            }
        }

    @Test
    fun closing_deallocates_instead_of_holding_the_relay_port_for_its_remaining_lifetime() =
        runTest {
            val meetup = Vnets.meetup(backgroundScope, turnLifetimeSeconds = SERVER_ALLOCATION_LIFETIME.inWholeSeconds.toUInt())
            val alice =
                TurnAllocation(
                    underlying = meetup.vnet.bind(meetup.aliceHost),
                    server = meetup.turnAddress,
                    username = Vnets.TURN_USERNAME,
                    password = Vnets.TURN_PASSWORD,
                    random = Random(0x137),
                    scope = backgroundScope,
                )
            assertIs<TurnAllocationResult.Allocated>(withTimeoutOrNull(PROBE_TIMEOUT) { alice.allocate() }, "the relay allocated")
            assertEquals(1, meetup.turn.activeAllocations, "the server is holding the allocation")

            alice.close()
            delay(SETTLE) // let the deallocating Refresh ride its coroutine out — still far short of any lifetime

            assertEquals(0, meetup.turn.activeAllocations, "close() must Refresh with LIFETIME=0, not leave the relay port held")
            assertEquals(1, meetup.turn.refreshes, "exactly one Refresh — the deallocation — and no keep-alive after close")
            assertTrue(!alice.isOpen, "and the channel is closed")
        }

    /**
     * Hold one relayed round trip open for [SESSION] under [maintenance], probing every
     * [PROBE_INTERVAL], and report when it worked and when it did not.
     *
     * Alice is a production [TurnAllocation] behind a symmetric NAT; Bob is an ordinary endpoint on the
     * public segment. Alice relays to Bob, Bob answers to the relayed address it sees — so one probe
     * exercises the Send indication (outbound, permission-gated per RFC 8656 §11.2) *and* the Data
     * indication (inbound, permission-gated per §9) over one allocation.
     */
    private suspend fun TestScope.relayForSeveralLifetimes(
        maintenance: TurnMaintenance,
        noncePolicy: NoncePolicy = NoncePolicy.Fixed,
        // Wraps Alice's socket so a fixture can lose specific TURN requests; identity by default.
        lossy: (AddressedDatagramChannel, SocketAddress) -> AddressedDatagramChannel = { channel, _ -> channel },
        retransmitInterval: Duration = DEFAULT_GATHER_RTO,
    ): RelayRun {
        val meetup =
            Vnets.meetup(
                backgroundScope,
                turnLifetimeSeconds = SERVER_ALLOCATION_LIFETIME.inWholeSeconds.toUInt(),
                turnPermissionLifetimeSeconds = SERVER_PERMISSION_LIFETIME.inWholeSeconds.toUInt(),
                turnNoncePolicy = noncePolicy,
            )
        val bobAddress = vnetAddress("203.0.113.50", 6000)
        val bob = meetup.vnet.bind(bobAddress)
        val alice =
            TurnAllocation(
                underlying = lossy(meetup.vnet.bind(meetup.aliceHost), meetup.turnAddress),
                server = meetup.turnAddress,
                username = Vnets.TURN_USERNAME,
                password = Vnets.TURN_PASSWORD,
                random = Random(0x137),
                scope = backgroundScope,
                maintenance = maintenance,
                retransmitInterval = retransmitInterval,
            )
        try {
            assertIs<TurnAllocationResult.Allocated>(
                withTimeoutOrNull(PROBE_TIMEOUT) { alice.allocate() },
                "the relay allocated over the vnet TURN server",
            )

            val started = testScheduler.currentTime
            val deliveredAt = mutableListOf<Duration>()
            val lostAt = mutableListOf<Duration>()
            var probes = 0
            while (testScheduler.currentTime - started < SESSION.inWholeMilliseconds) {
                val elapsed = (testScheduler.currentTime - started).milliseconds
                probes++
                if (relayRoundTrip(alice, bob, bobAddress, tag = "probe#$probes")) deliveredAt += elapsed else lostAt += elapsed
                delay(PROBE_INTERVAL)
            }
            return RelayRun(
                probes = probes,
                deliveredAt = deliveredAt,
                lostAt = lostAt,
                refreshes = meetup.turn.refreshes,
                permissionInstalls = meetup.turn.permissionInstalls,
                staleNonceChallenges = meetup.turn.staleNonceChallenges,
            )
        } finally {
            alice.close()
        }
    }

    // One relayed round trip: Alice -> (TURN) -> Bob, then Bob -> (TURN) -> Alice, both legs verified by
    // payload. Returns false the moment either leg fails to arrive inside the watchdog.
    private suspend fun relayRoundTrip(
        alice: TurnAllocation,
        bob: AddressedDatagramChannel,
        bobAddress: SocketAddress,
        tag: String,
    ): Boolean {
        alice.send(utf8Buffer(tag), to = bobAddress)
        val atBob = withTimeoutOrNull(PROBE_TIMEOUT) { bob.receive() }
        if (atBob !is DatagramReadResult.Received || text(atBob) != tag) return false

        bob.send(utf8Buffer(tag), to = atBob.datagram.peer)
        val atAlice = withTimeoutOrNull(PROBE_TIMEOUT) { alice.receive() }
        return atAlice is DatagramReadResult.Received && text(atAlice) == tag
    }

    private fun text(result: DatagramReadResult.Received): String =
        result.datagram.payload.let { it.readString(it.remaining(), Charset.UTF8) }

    /**
     * Loses TURN **requests** on the way to the server, chosen by [drop] rather than by a loss rate: a
     * probability leaves the interesting packet's fate to the seed, and the packet whose loss used to be
     * terminal is exactly the one a fixture must guarantee it lost.
     *
     * Only `StunClass.Request` messages are eligible. Send indications carry the relayed payload and are
     * never retransmitted (RFC 8656 §10 — TURN has no reliability for them), so dropping one would fail a
     * probe for reasons that have nothing to do with what is under test.
     */
    private class LossyTurnRequests(
        private val inner: AddressedDatagramChannel,
        private val turnServer: SocketAddress,
        /** Given a request's method and which transmission this is (1-based), true to drop it. */
        private val drop: (StunMethod, transmission: Int) -> Boolean,
    ) : AddressedDatagramChannel by inner {
        private val transmissions = HashMap<TransactionId, Int>()

        var dropped: Int = 0
            private set

        override suspend fun send(
            payload: ReadBuffer,
            to: SocketAddress,
            options: DatagramSendOptions,
        ) {
            val request = if (to == turnServer) requestIn(payload) else null
            if (request != null) {
                val nth = (transmissions[request.transactionId] ?: 0) + 1
                transmissions[request.transactionId] = nth
                if (drop(request.messageType.method, nth)) {
                    dropped++
                    return
                }
            }
            inner.send(payload, to, options)
        }

        // Decodes a SLICE: reading the real payload would advance the position the send is about to use.
        private fun requestIn(payload: ReadBuffer): StunMessage? {
            val decoded = StunMessage.decode(payload.slice()) as? StunDecodeResult.Success ?: return null
            return decoded.message.takeIf { it.messageType.stunClass == StunClass.Request }
        }
    }

    /** What one [relayForSeveralLifetimes] run observed — times are elapsed since the allocation. */
    private class RelayRun(
        val probes: Int,
        val deliveredAt: List<Duration>,
        val lostAt: List<Duration>,
        val refreshes: Int,
        val permissionInstalls: Int,
        val staleNonceChallenges: Int,
    )

    private companion object {
        // coturn's 600 s / 300 s, compressed by 10x so the interesting part starts early in virtual time.
        val SERVER_ALLOCATION_LIFETIME = 60.seconds
        val SERVER_PERMISSION_LIFETIME = 20.seconds

        /** Five allocation lifetimes and fifteen permission lifetimes — "several multiples of both". */
        val SESSION = 300.seconds

        /** Coprime with both lifetimes, so no probe can land on an expiry boundary and read ambiguously. */
        val PROBE_INTERVAL = 7.seconds
        val PROBE_TIMEOUT = 2.seconds

        /** Long enough for close()'s deallocating Refresh to round-trip, far short of any lifetime. */
        val SETTLE = 1.seconds

        const val PROBES = 40 // floor(300 / 7) + 1 = 43; assert a floor, not the exact schedule
        const val MIN_REFRESHES = 6 // 300 / (0.75 * 60)
        const val MIN_PERMISSION_INSTALLS = 19 // 300 / (0.75 * 20), less the first install

        /** Longer than a request's own budget, so the retransmit loop gets exactly one transmission. */
        val NO_RETRANSMISSION = 10.seconds

        /** Generous virtual-time watchdog for a request expected to time out its 3 s budget. */
        val WATCHDOG = 30.seconds
    }
}

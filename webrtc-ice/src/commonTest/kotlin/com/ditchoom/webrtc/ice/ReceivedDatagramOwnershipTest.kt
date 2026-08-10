@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.use
import com.ditchoom.webrtc.ice.vnet.LeakTrackingFactory
import com.ditchoom.webrtc.ice.vnet.NatProfile
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.ice.vnet.utf8Buffer
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The **receive** half of directive 6, which nothing has ever asserted.
 *
 * `BufferLifecycleTest` points its tracker at `IceConfig.bufferFactory` and says so explicitly —
 * *"the tracker goes to the AGENTS, not to the vnet"* — because a single factory serving both would
 * attribute the harness's buffers to production code. That is the right call there, and it is precisely
 * why the receive side has never been covered: an inbound datagram is allocated by the **channel's**
 * factory, on the other side of that deliberate split, so no existing fixture can see it.
 *
 * This one crosses the split on purpose, with **two independent trackers**: the send side keeps its own,
 * and the vnet's copy-on-receive — the exact allocation socket-udp's `recvmsg`/`NWConnection` paths make
 * on a real kernel — gets a second. Nothing is conflated, and the receive side is finally answerable.
 *
 * ## Why this is a leak and not a GC's problem
 *
 * On the JVM, Android and Node the received payload comes from `BufferFactory.Default` and the collector
 * eventually takes it. **On Kotlin/Native Linux it does not.** `socket-udp`'s `defaultDatagramBufferFactory`
 * is `BufferFactory.deterministic()` there, whose buffers are `NativeBuffer.allocate` — a raw `malloc`
 * that buffer's own KDoc says "must be explicitly closed to free native memory". Every inbound
 * connectivity check, DTLS record and SCTP chunk of a long-lived session is one of those.
 *
 * Apple is **not** affected, and the difference is worth stating because it is easy to assume otherwise
 * from `deterministic()`'s name: on Apple `deterministicBufferFactory` is an alias for the *default*
 * factory, an ARC `MutableDataBuffer`. Checked in the tree rather than inferred from the name.
 */
class ReceivedDatagramOwnershipTest {
    /**
     * A session that runs to Connected and keeps running must give back every datagram it *received*,
     * exactly as `BufferLifecycleTest` requires of every datagram it sent.
     *
     * Expected **RED** until the ownership rule lands: today nothing releases an inbound datagram — not
     * the driver's forwarder loop, not TURN's demux, not the gather. The number this reports is the size
     * of the problem, per session, over a handful of consent cycles.
     */
    @Test
    fun every_received_datagram_comes_back() =
        runTest {
            val received = LeakTrackingFactory()
            val sent = LeakTrackingFactory()
            val session = establish(this, receiveFactory = received, sendFactory = sent)

            assertTrue(
                session.state.value.let { it is IceConnectionState.Connected || it is IceConnectionState.Completed },
                "still connected — the count below must be a live session's, not a dead one's",
            )
            sent.assertNoLeaks("the datagrams an ICE session sent")
            received.assertNoLeaks("the datagrams an ICE session received")
            // The stronger claim, and the only one that can see an unreleased BORROW: a decode slice costs
            // a reference on a pooled chunk however diligently its owner freed the buffer.
            sent.assertPoolDrained("the datagrams an ICE session sent")
            received.assertPoolDrained("the datagrams an ICE session received")
        }

    /**
     * Anti-vacuity, and it is not a formality here: the receive tracker is wired to a *different* seam
     * from every other fixture in this repo, so "it reported no leaks" has to be told apart from "it was
     * never wired to anything". [LeakTrackingFactory.assertNoLeaks] already fails on zero allocations;
     * this states the stronger fact the fixture depends on — that the receive path allocates a lot, so
     * the failure above is measuring a real population.
     */
    @Test
    fun the_receive_seam_is_actually_wired_to_the_thing_under_test() =
        runTest {
            val received = LeakTrackingFactory()
            establish(this, receiveFactory = received, sendFactory = LeakTrackingFactory())

            assertTrue(
                received.allocations > 1,
                "an established session receives many datagrams; got ${received.allocations}",
            )
        }

    /**
     * The **relay** path, whose ownership chain is the longest in the module: TURN's demux loop transfers
     * a control response across a `CompletableDeferred` to the awaiting `request`, which classifies it
     * into a `TurnExchange` that then travels up through `requestWithChallengeRetry` to `allocate` —
     * four hand-offs before anything reads an attribute, and every one of those attributes is a slice of
     * the original datagram.
     *
     * A whole gather runs here (Allocate, the 401 challenge, the authenticated retry, CreatePermission),
     * so the fixture covers the challenge-and-discard branch as well as the success one — the branch that
     * drops an exchange on the floor to retry is the easiest release to forget.
     */
    @Test
    fun a_relay_gather_gives_back_every_datagram_the_turn_server_sent() =
        runTest {
            val received = LeakTrackingFactory()
            val meetup =
                Vnets.meetup(backgroundScope, profileA = NatProfile.Symmetric, profileB = NatProfile.Symmetric)
            val clock: () -> Instant = { EPOCH + testScheduler.currentTime.milliseconds }
            val driver =
                IceAgentDriver(
                    role = IceRole.Controlling,
                    random = Random(7),
                    // Only the driver's own sockets are tracked. The vnet's STUN and TURN servers keep
                    // the default factory, so their inbound copies — the harness's, released by nobody —
                    // stay out of the count. Without this the assertion below reads 2 of 4 leaked, and
                    // both of the two are scenery.
                    binder = DatagramBinder { meetup.vnet.bind(it, bufferFactory = received) },
                    scope = backgroundScope,
                    clock = clock,
                    config = IceConfig(bufferFactory = LeakTrackingFactory()),
                )
            driver.start()

            val result =
                driver.gatherRelay(meetup.turnAddress, Vnets.TURN_USERNAME, Vnets.TURN_PASSWORD, "10.0.0.2", 6000)

            assertIs<RelayGatheringResult.Gathered>(result, "the vnet TURN server allocated a relay")
            received.assertNoLeaks("the datagrams a relay gather received")
            received.assertPoolDrained("the datagrams a relay gather received")
        }

    /**
     * The three arms of the relay's receive path that a *gather* never reaches, and that therefore leaked
     * in production behind a green [a_relay_gather_gives_back_every_datagram_the_turn_server_sent]:
     *
     * 1. **Every relayed datagram arrives as a Data indication.** TURN's demux released the datagram and
     *    not the views decoded out of it — so on a relayed session, which is the only path a peer behind a
     *    symmetric NAT has, one receive chunk was pinned *per inbound packet*, forever.
     * 2. **The deallocating Refresh on [TurnAllocation.close].** Nothing reads its answer, so the exchange
     *    was dropped without being released — the one hand-off with no return value, and the only reason
     *    no fixture watched it.
     * 3. **A response that settles after its awaiter has gone.** `close()` cancels the maintenance job
     *    mid-Refresh; the demux has already taken the transaction out of `pending` by the time the
     *    `finally` looks, so the map could not answer for that transfer and nobody released it.
     *
     * Each is invisible to `assertNoLeaks` — the datagram itself *is* freed in all three — and each shows
     * up in `assertPoolDrained` as a chunk that never came back. Both are asserted, in that order, so a
     * regression says which kind it is.
     */
    @Test
    fun a_relayed_session_gives_back_every_data_indication_and_its_deallocation() =
        runTest {
            val received = LeakTrackingFactory()
            val meetup = Vnets.meetup(backgroundScope, profileA = NatProfile.Symmetric, profileB = NatProfile.Symmetric)
            val bobAddress = vnetAddress("203.0.113.50", 6000)
            val bob = meetup.vnet.bind(bobAddress)
            val alice =
                TurnAllocation(
                    // Only Alice's own socket is tracked — the vnet's TURN server keeps the default
                    // factory, so its inbound copies stay scenery and out of the count.
                    underlying = meetup.vnet.bind(meetup.aliceHost, bufferFactory = received),
                    server = meetup.turnAddress,
                    username = Vnets.TURN_USERNAME,
                    password = Vnets.TURN_PASSWORD,
                    random = Random(0x0DA7A),
                    scope = backgroundScope,
                )
            assertIs<TurnAllocationResult.Allocated>(
                withTimeoutOrNull(RELAY_TIMEOUT) { alice.allocate() },
                "the vnet TURN server allocated a relay",
            )

            // Relay both ways, several times: outbound is a Send indication, and every inbound answer
            // comes back as the Data indication whose views arm 1 is about. One round trip would leave a
            // per-packet leak indistinguishable from a per-session one.
            repeat(RELAYED_ROUND_TRIPS) { round ->
                alice.send(utf8Buffer("relayed-$round"), to = bobAddress)
                val atBob = assertIs<DatagramReadResult.Received>(withTimeoutOrNull(RELAY_TIMEOUT) { bob.receive() })
                atBob.datagram.payload.use { bob.send(it, to = atBob.datagram.peer) }
                val atAlice = assertIs<DatagramReadResult.Received>(withTimeoutOrNull(RELAY_TIMEOUT) { alice.receive() })
                // The decapsulated copy is [TurnAllocation]'s, transferred to this reader — a different
                // seam from the tracked one, and still ours to give back.
                atAlice.datagram.payload.freeIfNeeded()
            }

            alice.close()
            // close() posts the deallocating Refresh to `scope` and returns; the arms above live in the
            // exchange it awaits, so the census has to be taken after that coroutine has actually run.
            advanceUntilIdle()

            received.assertNoLeaks("the datagrams a relayed session received")
            received.assertPoolDrained("the datagrams a relayed session received")
        }

    /**
     * One connected host-to-host session between two **production** [IceAgentDriver]s, with the two
     * allocation seams held apart: [receiveFactory] is the vnet's copy-on-receive (the channel's factory
     * — socket-udp's, on a real kernel), [sendFactory] is `IceConfig`'s.
     *
     * `IceAgentDriver`, deliberately, and **not** the `IceDriver` test helper that every other fixture in
     * this file's neighbourhood uses. That helper is a parallel reimplementation of the driver — its own
     * inbox, its own `channels` map, its own forwarder loop — so a receive-ownership fixture built on it
     * measures the harness's loop and reports on code that ships to nobody. The first draft of this file
     * did exactly that, and read an identical 26-of-26 before *and* after the production fix, which is
     * the failure mode worth naming: a red test that stays red for the wrong reason looks like a fix that
     * did not work.
     */
    private suspend fun establish(
        scope: TestScope,
        receiveFactory: BufferFactory,
        sendFactory: BufferFactory,
    ): IceAgentDriver {
        val vnet = Vnets.flat()
        val clock: () -> Instant = { EPOCH + scope.testScheduler.currentTime.milliseconds }
        val config = IceConfig(consentInterval = 1.seconds, consentTimeout = 1000.seconds, bufferFactory = sendFactory)
        val binder = DatagramBinder { vnet.bind(it, bufferFactory = receiveFactory) }
        val alice = IceAgentDriver(IceRole.Controlling, Random(1), binder, scope.backgroundScope, clock, config)
        val bob = IceAgentDriver(IceRole.Controlled, Random(2), binder, scope.backgroundScope, clock, config)
        alice.start()
        bob.start()
        alice.gatherHost("10.0.0.1", 4000)
        bob.gatherHost("10.0.0.2", 5000)
        connect(alice, bob)
        connect(bob, alice)
        assertNotNull(withTimeoutOrNull(30.seconds) { alice.awaitConnected() }, "alice connects")
        assertNotNull(withTimeoutOrNull(30.seconds) { bob.awaitConnected() }, "bob connects")
        delay(CONSENT_CYCLES.seconds)
        return alice
    }

    // Scripted signaling: hand [from]'s credentials + candidates to [to], as IceAgentDriverTest does.
    private fun connect(
        to: IceAgentDriver,
        from: IceAgentDriver,
    ) {
        to.setRemoteCredentials(from.localCredentials)
        from.localCandidates.forEach { to.addRemoteCandidate(it) }
    }

    private suspend fun IceAgentDriver.awaitConnected(): IceConnectionState =
        state.first {
            when (it) {
                is IceConnectionState.Connected, is IceConnectionState.Completed -> true
                is IceConnectionState.Failed -> error("expected a connection, but ICE failed: ${it.reason}")
                else -> false
            }
        }

    private companion object {
        val EPOCH: Instant = Instant.fromEpochSeconds(0)

        // Enough consent refreshes that the steady-state receive path — an inbound check per interval,
        // forever — dominates the establishment burst rather than being lost in it.
        const val CONSENT_CYCLES = 5L

        // Several, so a per-packet leak cannot pass as a per-session one.
        const val RELAYED_ROUND_TRIPS = 4
        val RELAY_TIMEOUT = 30.seconds
    }
}

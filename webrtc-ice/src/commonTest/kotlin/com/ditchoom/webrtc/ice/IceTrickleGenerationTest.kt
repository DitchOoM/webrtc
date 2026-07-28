@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.ice.vnet.CountingBufferFactory
import com.ditchoom.webrtc.stun.TransportAddress
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **Trickle generations** (RFC 8838 §3.1), against the sans-io [IceAgent] directly — no coroutines, no
 * network, no clock but the one handed in, so every claim here is a pure function of the event sequence.
 *
 * The defect these pin: a trickled candidate carried no generation, so it was applied to whichever one
 * happened to be current when it arrived. Across an ICE restart (RFC 8445 §9) that is a real window — a
 * candidate for the peer's *new* generation can overtake the offer announcing it, and a candidate for its
 * *old* one can arrive after we have moved on. Untagged, the first is naturalized into a generation that
 * is about to be abandoned and the second into one that cannot authenticate it; both survive today only
 * because signaling happens to be in order and peer-reflexive learning (RFC 8445 §7.3.1.3) rediscovers
 * the path afterwards. Neither is a guarantee we chose.
 *
 * Every fixture asserts on **observable output**: a candidate that was applied produces a connectivity
 * check addressed to it, one that was refused produces an [IceOutput.RemoteCandidateDiscarded] with a
 * typed reason, and one that is held produces neither until the generation it names is signaled.
 */
class IceTrickleGenerationTest {
    @Test
    fun a_candidate_tagged_with_the_applied_generation_is_checked() {
        val f = Fixture()
        f.signal(PEER_UFRAG_1)
        f.trickle(REMOTE_A, CandidateGeneration.Tagged(PEER_UFRAG_1))
        f.pump()

        assertTrue(f.checkedAddresses().contains(REMOTE_A), "a candidate naming the applied generation is checked")
        assertTrue(f.discards().isEmpty(), "and nothing was discarded")
    }

    @Test
    fun an_untagged_candidate_is_applied_exactly_as_it_was_before_the_tag_existed() {
        // The compatibility claim, and the one a regression would cost every foreign interop lane: Pion,
        // werift, Firefox and our own harness all trickle candidates with no ufrag anywhere. An untagged
        // candidate has no generation to be routed to, so it goes to the current one — always.
        val f = Fixture()
        f.signal(PEER_UFRAG_1)
        f.trickle(REMOTE_A, CandidateGeneration.Untagged)
        f.pump()
        assertTrue(f.checkedAddresses().contains(REMOTE_A), "an untagged candidate is checked on the current generation")

        // …including after a restart, where "current" has changed underneath it and the untagged candidate
        // must follow it rather than be held for a generation it never names.
        f.restart()
        f.signal(PEER_UFRAG_2)
        f.trickle(REMOTE_B, CandidateGeneration.Untagged)
        f.pump()
        assertTrue(f.checkedAddresses().contains(REMOTE_B), "and again on the generation current after a restart")
        assertTrue(f.discards().isEmpty(), "an untagged candidate is never discarded")
    }

    @Test
    fun a_candidate_for_a_superseded_generation_is_discarded_and_says_which() {
        val f = Fixture()
        f.signal(PEER_UFRAG_1)
        f.restart()
        f.signal(PEER_UFRAG_2) // the peer's answer to our restart: generation 1 is now history

        f.trickle(REMOTE_A, CandidateGeneration.Tagged(PEER_UFRAG_1))
        f.pump()

        assertFalse(f.checkedAddresses().contains(REMOTE_A), "a candidate of a generation we have left is not checked")
        assertEquals(
            listOf<CandidateDiscardReason>(CandidateDiscardReason.SupersededGeneration(PEER_UFRAG_1)),
            f.discards(),
            "and it is discarded deliberately, with the generation named — not dropped in silence",
        )
    }

    @Test
    fun a_candidate_for_a_generation_not_applied_yet_is_held_until_it_is() {
        // The window the issue is actually about. The peer restarts, re-gathers, and its first new-generation
        // candidate beats its own offer to us. Untagged it would join the outgoing generation and die with
        // it; tagged, it waits for the credentials that name it — and is checked the moment they land.
        val f = Fixture()
        f.signal(PEER_UFRAG_1)
        f.trickle(REMOTE_B, CandidateGeneration.Tagged(PEER_UFRAG_2))
        f.pump()

        assertFalse(f.checkedAddresses().contains(REMOTE_B), "a candidate for an unsignaled generation is not checked yet")
        assertTrue(f.discards().isEmpty(), "nor is it thrown away — it is held")

        f.restart()
        f.signal(PEER_UFRAG_2) // the offer finally arrives
        f.pump()

        assertTrue(f.checkedAddresses().contains(REMOTE_B), "the held candidate is released into the generation that names it")
        assertTrue(f.discards().isEmpty(), "and released, not discarded")
    }

    @Test
    fun holding_a_candidate_arms_no_timer() {
        // Directive #2 / the sans-io contract: a held candidate is released by an EVENT — the credentials
        // arriving — never by a clock. If holding armed a deadline, the driver would spin on a generation
        // that has nothing to do, and the core would have grown a timer it cannot justify.
        val f = Fixture()
        f.signal(PEER_UFRAG_1)
        val before = f.agent.nextDeadline(f.now)
        repeat(HOLD_FLOOD) { f.trickle(REMOTE_B, CandidateGeneration.Tagged(PEER_UFRAG_2)) }
        assertEquals(before, f.agent.nextDeadline(f.now), "holding candidates changes no deadline")
    }

    @Test
    fun the_hold_buffer_is_bounded_under_a_flood() {
        // A peer that trickles candidates tagged with generations it never signals — broken, or hostile —
        // must cost a fixed amount of memory. The bound is asserted through what comes OUT: flood well past
        // it, then signal the generation, and only the last [holdBound] candidates can still be released.
        val f = Fixture()
        f.signal(PEER_UFRAG_1)
        val flooded = (0 until HOLD_FLOOD).map { remoteAt(it) }
        for (candidate in flooded) f.trickle(candidate, CandidateGeneration.Tagged(PEER_UFRAG_2))

        val overflow = f.discards().filterIsInstance<CandidateDiscardReason.UnappliedGenerationOverflow>()
        assertEquals(HOLD_FLOOD - HOLD_BOUND, overflow.size, "everything past the bound was evicted, oldest first")

        f.restart()
        f.signal(PEER_UFRAG_2)
        f.pump(ticks = HOLD_FLOOD * 2)
        val checked = f.checkedAddresses()
        assertEquals(
            flooded.takeLast(HOLD_BOUND).toSet(),
            checked.intersect(flooded.toSet()),
            "exactly the last $HOLD_BOUND held candidates survived to be checked",
        )
        assertTrue(f.buffers.handedOut > 0, "the agent allocated through the injected factory, as every buffer path must")
    }

    @Test
    fun a_straggler_for_a_generation_left_behind_is_discarded_at_the_door_and_never_held() {
        // The invariant that makes the hold's bound the *only* thing it needs: a held candidate's
        // generation can never become superseded, because the hold is emptied in full the moment that
        // generation is applied, and anything arriving for a generation already applied-and-left is
        // discarded on the way in. So a peer that keeps trickling for a dead generation fills nothing —
        // it is refused, one candidate at a time, for as long as it cares to keep sending.
        val f = Fixture()
        f.signal(PEER_UFRAG_1)
        f.trickle(REMOTE_B, CandidateGeneration.Tagged(PEER_UFRAG_2))
        f.restart()
        f.signal(PEER_UFRAG_2) // REMOTE_B released here — the hold for generation 2 is now empty

        val stragglers = (0 until HOLD_FLOOD).map { remoteAt(it) }
        for (candidate in stragglers) f.trickle(candidate, CandidateGeneration.Tagged(PEER_UFRAG_1))
        f.restart()
        f.signal(PEER_UFRAG_3)
        f.pump()

        assertEquals(
            List(HOLD_FLOOD) { CandidateDiscardReason.SupersededGeneration(PEER_UFRAG_1) },
            f.discards(),
            "every straggler is refused as superseded — none of them ever reached the hold",
        )
        assertTrue(
            f.checkedAddresses().intersect(stragglers.toSet()).isEmpty(),
            "and none of them was checked, in this generation or the next",
        )
    }

    @Test
    fun the_first_credentials_to_arrive_release_everything_held() {
        // The conservative rule, and the one that keeps a first negotiation safe against a peer whose
        // `ufrag` attribute disagrees with its own a=ice-ufrag. Before any generation has been applied
        // there is nothing for a candidate to be late for, so an unmatched tag means only that the peer's
        // bookkeeping differs from ours — and stranding a whole session over an optional attribute would
        // turn an interop quirk into a dead call. Strictness starts once a generation genuinely exists.
        val f = Fixture()
        f.trickle(REMOTE_A, CandidateGeneration.Tagged(Ufrag("something-else-entirely")))
        f.signal(PEER_UFRAG_1)
        f.pump()

        assertTrue(f.checkedAddresses().contains(REMOTE_A), "a candidate held before any generation existed is released, not lost")
        assertTrue(f.discards().isEmpty())
    }

    // ---- fixture plumbing ---------------------------------------------------------------------------

    /**
     * One agent, driven by hand. Time only moves when a fixture moves it (to the agent's own
     * [IceAgent.nextDeadline]), and every buffer comes from the injected [CountingBufferFactory], so a
     * path that allocated behind the core's back would show up as an uncounted buffer.
     */
    private class Fixture(
        seed: Int = 1,
    ) {
        val buffers = CountingBufferFactory(BufferFactory.managed())
        val agent = IceAgent(IceRole.Controlling, Random(seed), IceConfig(bufferFactory = buffers))
        var now: Instant = Instant.fromEpochSeconds(0)
        private val outputs = mutableListOf<IceOutput>()

        private var locals = 0

        init {
            gather()
        }

        fun handle(event: IceEvent) {
            outputs += agent.handle(event, now)
        }

        /**
         * Restart the way the driver does it: swap the generation, then **re-gather**. A restart alone
         * leaves the new generation with no local candidate and therefore no pair to check, which would
         * make every assertion below vacuously true — the fixture would be asserting that nothing happens.
         */
        fun restart() {
            handle(IceEvent.Restart)
            gather()
        }

        private fun gather() {
            handle(IceEvent.AddLocalCandidate(IceCandidate.host(localAt(locals++))))
        }

        /** The peer signals the credentials of the generation named by [ufrag]. */
        fun signal(ufrag: Ufrag) {
            handle(IceEvent.SetRemoteCredentials(IceCredentials(ufrag, IcePassword("pwd-${ufrag.value}-0123456789012345"))))
        }

        fun trickle(
            address: TransportAddress,
            generation: CandidateGeneration,
        ) {
            handle(IceEvent.AddRemoteCandidate(IceCandidate.host(address), generation))
        }

        /** Run the agent's own schedule forward, so paced checks actually go out. */
        fun pump(ticks: Int = DEFAULT_TICKS) {
            repeat(ticks) {
                val deadline = agent.nextDeadline(now) ?: return
                now = maxOf(now, deadline)
                handle(IceEvent.TimerFired)
            }
        }

        /** Every remote address the agent has actually sent a connectivity check to. */
        fun checkedAddresses(): Set<TransportAddress> = outputs.filterIsInstance<IceOutput.Transmit>().map { it.to }.toSet()

        fun discards(): List<CandidateDiscardReason> = outputs.filterIsInstance<IceOutput.RemoteCandidateDiscarded>().map { it.reason }
    }

    private companion object {
        val REMOTE_A = address("10.0.0.2", 5000)
        val REMOTE_B = address("10.0.0.2", 5001)

        val PEER_UFRAG_1 = Ufrag("gen1")
        val PEER_UFRAG_2 = Ufrag("gen2")
        val PEER_UFRAG_3 = Ufrag("gen3")

        /** [IceAgent]'s hold bound. Asserted through behaviour, so a change to it fails here loudly. */
        const val HOLD_BOUND = 32
        const val HOLD_FLOOD = 200

        /** Enough pacing ticks (Ta) for every pair on a fixture's checklist to have been started. */
        const val DEFAULT_TICKS = 16

        fun address(
            ip: String,
            port: Int,
        ): TransportAddress = SocketAddress.ofLiteral(ip, port).toTransportAddress()

        fun remoteAt(index: Int): TransportAddress = address("10.0.0.3", 6000 + index)

        /** A fresh base per generation — what an interface change actually looks like. */
        fun localAt(index: Int): TransportAddress = address("10.0.0.1", 4000 + index)
    }
}

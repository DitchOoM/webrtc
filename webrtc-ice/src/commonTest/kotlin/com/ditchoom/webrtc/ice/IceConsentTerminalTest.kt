@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.vnet.ImpairmentConfig
import com.ditchoom.webrtc.ice.vnet.Vnet
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.ice.vnet.utf8Buffer
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import com.ditchoom.webrtc.stun.RawAttribute
import com.ditchoom.webrtc.stun.StunAttributeType
import com.ditchoom.webrtc.stun.StunClass
import com.ditchoom.webrtc.stun.StunDecodeResult
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.StunMessageBuilder
import com.ditchoom.webrtc.stun.StunMethod
import com.ditchoom.webrtc.stun.TransactionId
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
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
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **RFC 7675 consent revocation is terminal** (issue #75), and the fixtures that prove it.
 *
 * §5.1 is explicit about what losing consent means: *"After consent is lost, the same ICE credentials
 * MUST NOT be used on the affected 5-tuple again. That means that a new session, or an ICE restart, is
 * needed to obtain consent to send on the affected candidate pair."* Before this change the agent nulled
 * its selected pair and went `Failed(ConsentExpired)` but left the checklist entry `Succeeded`, so the
 * next inbound check walked straight back through `selectPair` — whose "first nomination wins" guard had
 * just been unlatched — and re-declared the agent `Connected` on the pair whose consent had died.
 *
 * That is worse than a wrong state, because **the resurrection erases its own evidence**: `path` runs
 * `Nominated → Unnominated → Nominated`, so any fixture that reads the pair after the fact sees a healthy
 * agent and passes. It is exactly how the `IceRelayLossTest` consent failure stayed invisible for as long
 * as that fixture existed. So these tests assert the *absence* of a later transition, not a snapshot.
 *
 * The peer here is scripted rather than a second [IceDriver] because the shape needed is adversarial and
 * asymmetric — a peer that stops answering our consent checks while still sending its own — which no
 * honest agent produces and no whole-link impairment can target.
 */
class IceConsentTerminalTest {
    @Test
    fun an_inbound_check_cannot_revive_a_pair_whose_consent_expired() =
        runTest {
            val vnet = Vnets.flat()
            val fixture = deafPeerFixture(vnet, scope = backgroundScope, clock = IceDriver.clockOf { testScheduler.currentTime })
            assertNotNull(withTimeoutOrNull(TIMEOUT) { fixture.agent.awaitConnected() }, "the agent connects to the scripted peer")

            // The peer goes deaf to our consent checks but keeps probing us — the asymmetric-loss shape the
            // issue names, and the one an honest peer produces the moment the return path alone degrades.
            fixture.peer.answerOurChecks = false

            val failure = withTimeoutOrNull(TIMEOUT) { fixture.agent.state.first { it is IceConnectionState.Failed } }
            assertTrue(
                failure is IceConnectionState.Failed && failure.reason == IceFailureReason.ConsentExpired,
                "consent expires with the typed reason, got $failure",
            )

            // The peer's probes keep arriving throughout this window (it never stopped sending). Not one of
            // them may put the agent back on the pair whose consent just died.
            val revived =
                withTimeoutOrNull(REVIVAL_WINDOW) {
                    fixture.agent.state.first { it is IceConnectionState.Connected || it is IceConnectionState.Completed }
                }
            assertNull(revived, "an inbound check must not re-nominate a revoked pair (RFC 7675 §5.1)")
            assertTrue(fixture.peer.probesSent > 1, "the peer really did keep probing (sent=${fixture.peer.probesSent})")
            assertEquals(IcePath.Unnominated, fixture.agent.path.value, "and application data has nowhere to go")
        }

    @Test
    fun a_revoked_generation_arms_no_deadline_and_answers_no_check() =
        runTest {
            // The agent-level statement of the same guarantee, asserted where the driver reads it: once
            // consent is revoked the generation is finished, so it clocks nothing (a deadline left armed on a
            // terminal generation is a driver spin) and it transmits nothing more on the dead 5-tuple.
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val fixture = deafPeerFixture(vnet, scope = backgroundScope, clock = clock)
            assertNotNull(withTimeoutOrNull(TIMEOUT) { fixture.agent.awaitConnected() }, "connect first")
            fixture.peer.answerOurChecks = false
            withTimeoutOrNull(TIMEOUT) { fixture.agent.state.first { it is IceConnectionState.Failed } }

            assertNull(fixture.agent.agent.nextDeadline(clock()), "a revoked generation clocks nothing")
            val answersBefore = fixture.peer.answersReceived
            val probesBefore = fixture.peer.probesSent
            fixture.peer.probeOnce()
            testScheduler.advanceTimeBy(SETTLE)
            assertTrue(fixture.peer.probesSent > probesBefore, "the probe really went out")
            assertEquals(
                answersBefore,
                fixture.peer.answersReceived,
                "and went unanswered — RFC 7675 §5.1 ceases transmission on the revoked 5-tuple",
            )
        }

    @Test
    fun a_candidate_trickled_in_after_revocation_neither_arms_a_clock_nor_starts_a_check() =
        runTest {
            // Trickle (RFC 8838) is asynchronous, so a remote candidate can perfectly well arrive after the
            // pair died — signaling does not stop because consent did. It must land on a generation that is
            // already finished and change nothing. This is the case the terminal guards genuinely exist for:
            // pairing a late candidate re-arms the pacing clock, and a deadline armed on a generation whose
            // timer tick is a no-op is not merely untidy, it is a driver that wakes, does nothing, recomputes
            // the same past deadline and wakes again — a spin, at full speed, forever.
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val fixture = deafPeerFixture(vnet, scope = backgroundScope, clock = clock)
            assertNotNull(withTimeoutOrNull(TIMEOUT) { fixture.agent.awaitConnected() }, "connect first")
            fixture.peer.answerOurChecks = false
            withTimeoutOrNull(TIMEOUT) { fixture.agent.state.first { it is IceConnectionState.Failed } }

            // Fed straight into the core rather than posted through the driver's inbox, and with no
            // suspension until the assertions are done. That is deliberate: this is a statement about the
            // sans-io contract, and going through the loop would mean a *failing* version of this test
            // hangs in the spin instead of reporting which invariant broke.
            val core = fixture.agent.agent
            core.handle(IceEvent.AddRemoteCandidate(IceCandidate.host(vnetAddress(LATE_IP, LATE_PORT).toTransportAddress())), clock())

            assertNull(core.nextDeadline(clock()), "a trickled candidate must not re-arm a revoked generation's clock")
            repeat(TICKS) { tick ->
                assertTrue(core.handle(IceEvent.TimerFired, clock()).isEmpty(), "and no check is ever paced onto it (tick $tick)")
            }
        }

    @Test
    fun a_revoked_generation_does_no_work_even_if_its_driver_keeps_ticking() =
        runTest {
            // A sans-io core owes its contract to *any* driver, not just this one. Ours falls silent
            // because [IceAgent.nextDeadline] returns null — but that is a property of our loop, and a
            // caller that ticks on a fixed cadence (or replays a timeline) must get the same answer, or
            // "terminal" is true only by convention. So tick it directly and require it produces nothing:
            // no retransmit, no paced check, no re-nomination, no consent refresh.
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val fixture = deafPeerFixture(vnet, scope = backgroundScope, clock = clock)
            assertNotNull(withTimeoutOrNull(TIMEOUT) { fixture.agent.awaitConnected() }, "connect first")
            fixture.peer.answerOurChecks = false
            withTimeoutOrNull(TIMEOUT) { fixture.agent.state.first { it is IceConnectionState.Failed } }

            // No suspension between these calls, so the driver loop cannot interleave with them.
            repeat(TICKS) { tick ->
                assertTrue(
                    fixture.agent.agent
                        .handle(IceEvent.TimerFired, clock())
                        .isEmpty(),
                    "a revoked generation emits nothing on tick $tick (RFC 7675 §5.1 — recovery is a restart)",
                )
            }
            assertTrue(
                fixture.agent.agent.state is IceConnectionState.Failed,
                "and stays failed, with ConsentExpired never relabelled by a later terminal",
            )
        }

    @Test
    fun an_ice_restart_is_the_recovery_from_a_revoked_generation() =
        runTest {
            // RFC 7675 §5.1's own remedy: "a new session, or an ICE restart, is needed to obtain consent to
            // send on the affected candidate pair". Terminal-for-the-generation is only a defensible design
            // if the documented way out actually works, so prove it end to end rather than asserting the
            // terminal alone. The peer starts answering again on new credentials, as a real one would after
            // renegotiation.
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val fixture = deafPeerFixture(vnet, scope = backgroundScope, clock = clock)
            assertNotNull(withTimeoutOrNull(TIMEOUT) { fixture.agent.awaitConnected() }, "connect first")
            fixture.peer.answerOurChecks = false
            withTimeoutOrNull(TIMEOUT) { fixture.agent.state.first { it is IceConnectionState.Failed } }

            // A restart installs a NEW generation with new credentials. The revoked one is not retained: RFC
            // 7675 forbids further transmission on its 5-tuple, so there is nothing for it to carry.
            fixture.agent.post(IceEvent.Restart)
            withTimeoutOrNull(TIMEOUT) { fixture.agent.state.first { it is IceConnectionState.New } }
            assertEquals(IcePath.Unnominated, fixture.agent.path.value, "a revoked pair is never carried across a restart")

            // ...and it is not *retained* either. Retention exists so the outgoing generation can keep
            // carrying data and keep answering the peer's consent checks through the restart window (RFC
            // 8445 §9); a revoked generation may do neither, so a check still keyed with its credentials
            // must go unanswered. The peer has not re-adopted yet, so this probe carries the old ones.
            val answersBefore = fixture.peer.answersReceived
            fixture.peer.probeOnce()
            testScheduler.advanceTimeBy(SETTLE)
            assertEquals(
                answersBefore,
                fixture.peer.answersReceived,
                "the revoked generation is not retained, so its old credentials answer nothing",
            )

            fixture.peer.adoptCredentialsOf(fixture.agent)
            fixture.peer.answerOurChecks = true
            fixture.agent.bindHost(AGENT_IP, AGENT_PORT + 1)
            fixture.agent.post(IceEvent.SetRemoteCredentials(fixture.peer.credentials))
            fixture.agent.post(IceEvent.AddRemoteCandidate(IceCandidate.host(vnetAddress(PEER_IP, PEER_PORT).toTransportAddress())))

            assertNotNull(
                withTimeoutOrNull(TIMEOUT) { fixture.agent.awaitConnected() },
                "an ICE restart recovers a session whose consent was revoked",
            )
        }

    // ---- RFC 7675 §4.1 pacing (issue #73) ---------------------------------------------------------------

    @Test
    fun consent_checks_are_paced_independently_not_retransmitted_into_a_backoff_chain() =
        runTest {
            // §4.1: each consent check is a fresh Binding request with a new transaction id, "transmitted
            // once only" — NOT retransmitted per RFC 8489. Running them as retransmitting transactions
            // front-loaded the probes (at the RFC defaults: 0, 0.5, 1.5, 3.5, 7.5, 15.5 s) and then left a
            // 16-second hole with no probe at all, inside the very 30-second window the probes exist to
            // defend. The observable that separates the two shapes is the GAP, not the count.
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val fixture = deafPeerFixture(vnet, scope = backgroundScope, clock = clock, config = RFC_DEFAULT_CONSENT)
            assertNotNull(withTimeoutOrNull(TIMEOUT) { fixture.agent.awaitConnected() }, "connect first")

            fixture.peer.answerOurChecks = false
            fixture.peer.recordCheckArrivals = true
            withTimeoutOrNull(TIMEOUT) { fixture.agent.state.first { it is IceConnectionState.Failed } }

            val arrivals = fixture.peer.checkArrivals
            assertTrue(arrivals.size >= MIN_PROBES_IN_WINDOW, "the revocation window gets ~6 chances, got ${arrivals.size}: $arrivals")
            val gaps = arrivals.zipWithNext { a, b -> b - a }
            val worst = gaps.maxOrNull() ?: Duration.ZERO
            assertTrue(
                worst <= RFC_DEFAULT_CONSENT.consentInterval * MAX_JITTER,
                "no probe gap may exceed the jittered interval; worst=$worst over $arrivals",
            )
            // §4.1 again: "each interval MUST be randomized from between 0.8 and 1.2 times the basic period",
            // so a fleet does not synchronize into a thundering herd. Identical gaps would mean no jitter.
            assertTrue(gaps.toSet().size > 1, "consent intervals are randomized, not a fixed cadence: $gaps")
            assertTrue(
                gaps.all { it >= RFC_DEFAULT_CONSENT.consentInterval * MIN_JITTER },
                "and never faster than 0.8x the basic period: $gaps",
            )
        }

    @Test
    fun consent_survives_a_path_whose_round_trip_exceeds_the_check_interval() =
        runTest {
            // Pacing checks independently only helps if a check paced *after* another is still outstanding
            // does not cancel it. On a slow path — a double-hopped relay, a satellite leg — the round trip
            // genuinely exceeds one interval, so every response arrives after we have already sent the next
            // one or two. Matching only the newest id would mean such a path could never refresh consent at
            // all and would revoke on a link that is working perfectly. Hence a *set* of outstanding ids,
            // bounded by the revocation window rather than by one.
            val vnet = Vnets.flatImpaired(backgroundScope, ImpairmentConfig(minDelay = ONE_WAY, maxDelay = ONE_WAY), seed = 5150)
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val config = SLOW_PATH_CONSENT
            val alice = IceDriver(IceRole.Controlling, seed = 71, vnet = vnet, scope = backgroundScope, clock = clock, config = config)
            val bob = IceDriver(IceRole.Controlled, seed = 72, vnet = vnet, scope = backgroundScope, clock = clock, config = config)
            alice.start()
            bob.start()
            alice.bindHost(AGENT_IP, AGENT_PORT)
            bob.bindHost(PEER_IP, PEER_PORT)
            alice.connectTo(bob)
            bob.connectTo(alice)
            assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "the slow path still establishes")

            // The round trip is several times the interval, so consent is permanently "in flight" — the
            // window spans several revocation timeouts, and a one-at-a-time matcher would expire in the first.
            val failed = withTimeoutOrNull(SLOW_PATH_WINDOW) { alice.state.first { it is IceConnectionState.Failed } }
            assertNull(failed, "a response that arrives after later checks were paced still refreshes consent")
        }

    @Test
    fun consent_recovers_when_the_path_heals_inside_the_revocation_window() =
        runTest {
            // The failure #73 is actually about. The peer goes deaf and then heals well inside the
            // revocation window, with a third of it still to run. Paced probes keep arriving at ~5 s
            // spacing, so one lands on the healed path and the pair survives. The retransmit chain's
            // in-window probes went out at 5, 5.5, 6.5, 8.5, 12.5 and 20.5 s and the next not until
            // 36.5 s — so across the whole healed stretch it had NOTHING in flight, and revoked anyway:
            // a recovered path declared dead by our own retransmit schedule.
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val fixture = deafPeerFixture(vnet, scope = backgroundScope, clock = clock, config = RFC_DEFAULT_CONSENT)
            assertNotNull(withTimeoutOrNull(TIMEOUT) { fixture.agent.awaitConnected() }, "connect first")

            fixture.peer.answerOurChecks = false
            backgroundScope.launch {
                delay(OUTAGE)
                fixture.peer.answerOurChecks = true
            }

            val failed = withTimeoutOrNull(OBSERVE_AFTER_HEAL) { fixture.agent.state.first { it is IceConnectionState.Failed } }
            assertNull(failed, "a path that heals inside the revocation window keeps its consent")
            assertIs<IceConnectionState.Completed>(fixture.agent.state.value, "and the session is still up")
        }

    // ---- fixture ----------------------------------------------------------------------------------------

    private class Fixture(
        val agent: IceDriver,
        val peer: ScriptedPeer,
    )

    private suspend fun deafPeerFixture(
        vnet: Vnet,
        scope: CoroutineScope,
        clock: () -> Instant,
        config: IceConfig = FAST_CONSENT,
    ): Fixture {
        // The agent under test is CONTROLLED so the peer drives nomination — the direct route into the
        // `Succeeded -> if (nominatedByPeer) selectPair` arm the resurrection walked through.
        val agent = IceDriver(IceRole.Controlled, seed = 4242, vnet = vnet, scope = scope, clock = clock, config = config)
        agent.start()
        agent.bindHost(AGENT_IP, AGENT_PORT)
        val peer = ScriptedPeer(vnetAddress(PEER_IP, PEER_PORT), vnet, scope, clock, probeEvery = config.consentInterval)
        peer.adoptCredentialsOf(agent)
        peer.start()
        agent.post(IceEvent.SetRemoteCredentials(peer.credentials))
        agent.post(IceEvent.AddRemoteCandidate(IceCandidate.host(vnetAddress(PEER_IP, PEER_PORT).toTransportAddress())))
        return Fixture(agent, peer)
    }

    /**
     * A scripted ICE peer that can be made **deaf to our checks while still sending its own** — the shape
     * a second [IceDriver] cannot produce (an honest agent always answers) and a whole-link impairment
     * cannot target (it drops both directions). It plays CONTROLLING and nominates with USE-CANDIDATE, so
     * the agent under test reaches `Connected` the ordinary way before anything adversarial begins.
     */
    private class ScriptedPeer(
        private val address: SocketAddress,
        private val vnet: Vnet,
        private val scope: CoroutineScope,
        private val clock: () -> Instant,
        private val probeEvery: Duration,
    ) {
        val credentials = IceCredentials(Ufrag("peer"), IcePassword("peerpass"))

        /** Whether to answer the agent's Binding requests. Flipping this false starves its consent clock. */
        var answerOurChecks: Boolean = true

        /** How many checks the agent has sent us — the "did it go quiet?" observable. */
        var checksReceived: Int = 0
            private set

        /** How many of our probes the agent answered — the "has it ceased transmission?" observable. */
        var answersReceived: Int = 0
            private set

        var probesSent: Int = 0
            private set

        /** Arrival instants of the agent's checks, once [recordCheckArrivals] is on — the pacing observable. */
        var recordCheckArrivals: Boolean = false
        val checkArrivals: MutableList<Instant> = mutableListOf()

        private lateinit var agentCredentials: IceCredentials
        private lateinit var channel: DatagramChannel
        private var agentAddress: SocketAddress? = null

        /** Learn the agent's *current* credentials — re-read after a restart, as a renegotiation would. */
        fun adoptCredentialsOf(agent: IceDriver) {
            agentCredentials = agent.agent.localCredentials
        }

        fun start() {
            channel = vnet.bind(address)
            scope.launch {
                while (true) {
                    val datagram =
                        when (val result = channel.receive()) {
                            is DatagramReadResult.Received -> result.datagram
                            is DatagramReadResult.Closed -> return@launch
                        }
                    agentAddress = datagram.peer
                    val message = (StunMessage.decode(datagram.payload) as? StunDecodeResult.Success)?.message ?: continue
                    if (message.messageType.stunClass != StunClass.Request) {
                        answersReceived++
                        continue
                    }
                    checksReceived++
                    if (recordCheckArrivals) checkArrivals += clock()
                    if (!answerOurChecks) continue
                    channel.send(
                        StunMessageBuilder
                            .of(StunClass.SuccessResponse, StunMethod.Binding, message.transactionId)
                            .add(RawAttribute.ofXorMappedAddress(datagram.peer.toTransportAddress(), message.transactionId))
                            .addMessageIntegrity(utf8Buffer(credentials.password.value))
                            .addFingerprint()
                            .encode(),
                        to = datagram.peer,
                    )
                }
            }
            scope.launch {
                while (true) {
                    probeOnce()
                    delay(probeEvery)
                }
            }
        }

        /** Send one nominating check to the agent, keyed with *its* password as a real peer's would be. */
        fun probeOnce() {
            val target = agentAddress ?: vnetAddress(AGENT_IP, AGENT_PORT)
            val txid = TransactionId.random(Random(PROBE_SEED + probesSent))
            probesSent++
            val request =
                StunMessageBuilder
                    .of(StunClass.Request, StunMethod.Binding, txid)
                    .add(RawAttribute.ofText(StunAttributeType.Username, "${agentCredentials.ufrag.value}:${credentials.ufrag.value}"))
                    .add(IceAttributes.priority(IceCandidate.computePriority(CandidateType.PeerReflexive, ComponentId.Rtp)))
                    .add(IceAttributes.controlling(TieBreaker(PEER_TIE_BREAKER)))
                    .add(IceAttributes.useCandidate())
                    .addMessageIntegrity(utf8Buffer(agentCredentials.password.value))
                    .addFingerprint()
                    .encode()
            scope.launch { channel.send(request, to = target) }
        }
    }

    private companion object {
        const val AGENT_IP = "10.0.0.1"
        const val AGENT_PORT = 4000
        const val PEER_IP = "10.0.0.2"
        const val PEER_PORT = 5000
        const val LATE_IP = "10.0.0.3"
        const val LATE_PORT = 6000
        const val PROBE_SEED = 9_100L
        const val PEER_TIE_BREAKER = 0x7fff_0000L

        /** Compressed consent for the terminal fixtures — the observable is state, never a wall clock (#4). */
        val FAST_CONSENT = IceConfig(consentInterval = 1.seconds, consentTimeout = 5.seconds)

        /** The RFC's own numbers, because the pacing fixtures assert against the RFC's own shape. */
        val RFC_DEFAULT_CONSENT = IceConfig()

        // A 3 s round trip against a 1 s check interval: ~3 consent checks are outstanding at all times.
        val ONE_WAY = 1500.milliseconds
        val SLOW_PATH_CONSENT = IceConfig(consentInterval = 1.seconds, consentTimeout = 10.seconds)
        val SLOW_PATH_WINDOW = 40.seconds

        const val MIN_PROBES_IN_WINDOW = 5
        const val MIN_JITTER = 0.8
        const val MAX_JITTER = 1.2

        const val TICKS = 8

        val TIMEOUT = 60.seconds
        val REVIVAL_WINDOW = 20.seconds
        val SETTLE = 2.seconds

        // Consent is fresh as of nomination (~t=0), so revocation falls at ~t=30 s and the retransmit
        // chain's blind spot runs 20.5 s → 36.5 s. Healing at 22 s sits inside that spot — the old shape
        // had nothing in flight and revoked anyway — while leaving 8 s of window, which is longer than the
        // widest jittered gap (1.2 x 5 s = 6 s). So a paced probe is *guaranteed* to land on the healed
        // path, not merely likely: the fixture does not depend on the seed.
        val OUTAGE = 22.seconds
        val OBSERVE_AFTER_HEAL = 60.seconds
    }
}

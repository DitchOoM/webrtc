@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.dtls.DtlsFailureReason
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.ice.IceAgentDriver
import com.ditchoom.webrtc.ice.IceConfig
import com.ditchoom.webrtc.ice.IceFailureReason
import com.ditchoom.webrtc.ice.LocalInterface
import com.ditchoom.webrtc.ice.NetworkId
import com.ditchoom.webrtc.ice.NetworkMonitor
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sdp.SdpType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The **ICE restart / renegotiation** fixtures for the session layer (RFC 8445 §9 through JSEP). The
 * motivating scenario is a mobile network change mid-session — Wi-Fi → cellular — and the property that
 * matters is not "ICE reconverges" but **"the SCTP association and every open data channel survive it"**.
 * §9 promises exactly that: *"during the restart, data can continue to be sent using existing data
 * sessions"*, and *"agents MUST NOT redetermine the roles as part of an ICE restart"*.
 *
 * The second half of the file is the same API used for the *other* thing RFC 8445 §9 is for: **recovery**.
 * RFC 7675 §5.1 says a pair whose consent is revoked needs *"a new session, or an ICE restart"*, and until
 * now only the first of those worked here — the agent restarted fine (`IceConsentTerminalTest`) while the
 * session above it latched [PeerConnectionState.Failed] and stayed there, so a consumer whose path died had
 * to build a whole new [NativePeerConnection]. These fixtures pin the restart as the way back, and pin the
 * limit of it: a failure ICE cannot mend does not come back.
 *
 * Each peer gathers on a **fresh port per ICE generation** ([GenerationalGathering]) because that is what
 * an interface change actually looks like, and because the in-memory network — like a real OS — refuses to
 * re-bind an address that is still open. The old socket staying open is the point, not an obstacle.
 */
class PeerConnectionRestartTest {
    private val timeout = 60.seconds
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun ice_restart_moves_to_a_new_pair_without_dropping_the_association() =
        runTest {
            val f = connectedPeers()
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/chat"))
            val streamId = channel.id
            assertEquals("before", echo(channel, "before"), "the channel works before the restart")
            val pairBefore = knownPair(f.alice.connectionState.value)
            val credentialsBefore = ufragOf(f.alice.createOffer())

            f.alice.restartIce()
            renegotiate(f.alice, f.bob)

            // The pair moved…
            val connected =
                assertNotNull(
                    withTimeoutOrNull(timeout) {
                        f.alice.connectionState.first { it is PeerConnectionState.Connected && knownPair(it) != pairBefore }
                    },
                    "alice reconverged on a new pair",
                )
            val pairAfter = knownPair(connected)
            assertNotEquals(pairBefore, pairAfter, "the restart nominated a different pair")
            assertNotEquals(credentialsBefore, ufragOf(f.alice.createOffer()), "…on fresh ICE credentials (RFC 8445 §9)")

            // …and the association did not: the SAME channel object, on the SAME stream, still round-trips.
            // A restart that quietly rebuilt DTLS/SCTP underneath would show up here as a dead channel or a
            // renumbered stream, which is precisely the failure §9 exists to prevent.
            assertEquals(streamId, channel.id, "the data channel kept its stream id across the restart")
            assertEquals("after", echo(channel, "after"), "the data channel still round-trips after the restart")
        }

    @Test
    fun data_keeps_flowing_on_the_old_pair_during_the_restart() =
        runTest {
            // The RFC 8445 §9 continuity claim, pinned. Before [IcePath] this worked only because a stale
            // field was never cleared — right behaviour, arrived at by a bug, untested and one refactor from
            // vanishing. Here the restart is applied and the peer has NOT yet seen the offer, so the only
            // thing that can be carrying this message is the retained generation's pair.
            val f = connectedPeers()
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/continuity"))
            assertEquals("before", echo(channel, "before"))

            f.alice.restartIce()
            f.alice.createOffer() // applies the restart; deliberately NOT signaled to bob yet
            val restarting =
                assertNotNull(
                    withTimeoutOrNull(timeout) { f.alice.connectionState.first { it is PeerConnectionState.Restarting } },
                    "the restart window is an observable state, not an invisible interval",
                )
            assertIs<SelectedPath.Known>((restarting as PeerConnectionState.Restarting).path)

            assertEquals("during", echo(channel, "during"), "data keeps flowing while the new generation converges")
        }

    @Test
    fun a_rolled_back_restart_offer_restores_the_previous_ice_generation() =
        runTest {
            val f = connectedPeers()
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/rollback"))
            assertEquals("before", echo(channel, "before"))
            val pairBefore = knownPair(f.alice.connectionState.value)

            f.alice.restartIce()
            val offer = f.alice.createOffer()
            f.alice.setLocalDescription(SdpType.Offer, offer)
            assertNotNull(withTimeoutOrNull(timeout) { f.alice.connectionState.first { it is PeerConnectionState.Restarting } })

            // The app abandons the round (a glare resolution, or the user cancelled). Without the ICE half of
            // rollback the agent would be left advertising credentials no peer has ever seen — reachable by
            // nobody, and not obviously broken until the next check times out.
            f.alice.setLocalDescription(SdpType.Rollback, "")

            val restored =
                assertNotNull(
                    withTimeoutOrNull(timeout) { f.alice.connectionState.first { it is PeerConnectionState.Connected } },
                    "the session returns to Connected on the generation the peer still knows",
                )
            assertEquals(pairBefore, knownPair(restored), "…on the same pair it was using before the abandoned offer")
            assertEquals("after", echo(channel, "after"), "and the channel never noticed")
        }

    @Test
    fun a_peer_initiated_restart_is_detected_from_new_remote_credentials() =
        runTest {
            // Bob never calls restartIce(). The only evidence he gets is an offer whose ufrag AND pwd both
            // changed (RFC 8445 §9 requires both) — and if he did not act on it his checklist would stay
            // bound to the old password and every check he sent would be discarded by an agent that no
            // longer knows it.
            val f = connectedPeers()
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/peer"))
            assertEquals("before", echo(channel, "before"))
            val bobPairBefore = knownPair(f.bob.connectionState.value)

            f.alice.restartIce()
            renegotiate(f.alice, f.bob)

            val bobAfter =
                assertNotNull(
                    withTimeoutOrNull(timeout) {
                        f.bob.connectionState.first { it is PeerConnectionState.Connected && knownPair(it) != bobPairBefore }
                    },
                    "bob restarted his own side off the peer's new credentials alone",
                )
            assertNotEquals(bobPairBefore, knownPair(bobAfter))
            assertEquals("after", echo(channel, "after"), "and the channel survived on both sides")
        }

    @Test
    fun the_old_interface_going_away_mid_restart_still_converges() =
        runTest {
            // The realistic mobile case: Wi-Fi does not politely wait for the new path to come up. Continuity
            // is lost here — that is what losing the interface *means* — but the session must still reconverge
            // on the new one rather than wedging on a pair whose socket has evaporated.
            val f = connectedPeers()
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/flap"))
            assertEquals("before", echo(channel, "before"))
            val pairBefore = knownPair(f.alice.connectionState.value)

            f.alice.restartIce()
            val offer = f.alice.createOffer()
            f.alice.setLocalDescription(SdpType.Offer, offer)
            f.bob.setRemoteDescription(SdpType.Offer, offer)
            f.net.tearDown(SocketAddress.ofLiteral(ALICE_IP, ALICE_FIRST_PORT))

            val answer = f.bob.createAnswer()
            f.bob.setLocalDescription(SdpType.Answer, answer)
            f.alice.setRemoteDescription(SdpType.Answer, answer)

            val connected =
                assertNotNull(
                    withTimeoutOrNull(timeout) {
                        f.alice.connectionState.first { it is PeerConnectionState.Connected && knownPair(it) != pairBefore }
                    },
                    "alice reconverges even though the outgoing interface vanished mid-restart",
                )
            assertNotEquals(pairBefore, knownPair(connected))
            assertEquals("after", echo(channel, "after"), "the association rode out the interface change")
        }

    @Test
    fun losing_the_selected_pairs_interface_restarts_automatically() =
        runTest {
            // No explicit restartIce() anywhere in this fixture: the policy notices, and tells the app a
            // round is owed. It cannot renegotiate by itself — it does not own the signaling channel — so
            // "restarts automatically" means exactly this handshake, and the signal is the load-bearing half.
            val monitor = ScriptedMonitor(listOf(iface("wifi", ALICE_IP)))
            val f = connectedPeers(aliceRestartPolicy = IceRestartPolicy.OnNetworkChange(monitor))
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/auto"))
            assertEquals("before", echo(channel, "before"))
            val pairBefore = knownPair(f.alice.connectionState.value)

            monitor.emit(listOf(iface("cellular", "10.0.0.9")))

            assertNotNull(
                withTimeoutOrNull(timeout) { f.alice.renegotiationNeeded.first() },
                "losing the selected pair's interface asks the app for a new offer/answer round",
            )
            renegotiate(f.alice, f.bob)

            val connected =
                assertNotNull(
                    withTimeoutOrNull(timeout) {
                        f.alice.connectionState.first { it is PeerConnectionState.Connected && knownPair(it) != pairBefore }
                    },
                    "and the round the policy asked for carries a genuine ICE restart",
                )
            assertNotEquals(pairBefore, knownPair(connected))
            assertEquals("after", echo(channel, "after"))
        }

    @Test
    fun an_unrelated_interface_appearing_does_not_restart() =
        runTest {
            // The guard against restart churn. A VPN or virtual adapter coming up changes the interface set
            // on a perfectly healthy session; a policy that restarted on *any* change would tear a working
            // path down for it, repeatedly, on exactly the mobile devices this feature exists to serve.
            val monitor = ScriptedMonitor(listOf(iface("wifi", ALICE_IP)))
            val f = connectedPeers(aliceRestartPolicy = IceRestartPolicy.OnNetworkChange(monitor))
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/churn"))
            assertEquals("before", echo(channel, "before"))
            val pairBefore = knownPair(f.alice.connectionState.value)

            monitor.emit(listOf(iface("wifi", ALICE_IP), iface("vpn", "10.0.0.77")))

            assertNull(
                withTimeoutOrNull(QUIET) { f.alice.renegotiationNeeded.first() },
                "an interface set that still carries the selected pair is not a reason to renegotiate",
            )
            assertEquals(pairBefore, knownPair(f.alice.connectionState.value), "the healthy session is untouched")
            assertEquals("after", echo(channel, "after"))
        }

    @Test
    fun we_answer_the_peers_restart_offer_without_re_deciding_our_dtls_role() =
        runTest {
            // The direction the fixtures above never ran: the ROUND-0 OFFERER answering a restart offer.
            // Bob (round-0 answerer, DTLS client) restarts and re-offers `a=setup:actpass`, which RFC 8842
            // §5.5 is explicit is what an endpoint keeping its association offers — continuity is signalled
            // by the unchanged fingerprint, not by the setup value. Alice must answer it keeping the SERVER
            // role she resolved in round 0; re-running the initial-offer rule (actpass ⇒ we are active)
            // would have her claim the client role the association already gave away, and RFC 8445 §9's
            // "agents MUST NOT redetermine the roles as part of an ICE restart" is exactly that prohibition.
            val f = connectedPeers()
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "restart/foreign"))
            val streamId = channel.id
            assertEquals("before", echo(channel, "before"))
            val alicePairBefore = knownPair(f.alice.connectionState.value)
            val aliceUfragBefore = ufragOf(f.alice.createAnswer())

            f.bob.restartIce()
            renegotiate(f.bob, f.alice)

            val connected =
                assertNotNull(
                    withTimeoutOrNull(timeout) {
                        f.alice.connectionState.first { it is PeerConnectionState.Connected && knownPair(it) != alicePairBefore }
                    },
                    "alice detected the peer's restart, restarted her own side and reconverged",
                )
            assertNotEquals(alicePairBefore, knownPair(connected))
            assertNotEquals(aliceUfragBefore, ufragOf(f.alice.createAnswer()), "…on fresh local credentials (RFC 8445 §9)")
            assertEquals(streamId, channel.id, "the data channel kept its stream id across the peer's restart")
            assertEquals("after", echo(channel, "after"), "and the association survived on both sides")
        }

    @Test
    fun a_re_answer_that_flips_the_dtls_role_is_refused() =
        runTest {
            // RFC 8842 §5.5: an endpoint that wants to keep its DTLS association re-offers `a=setup:actpass`
            // and keeps its fingerprint — the roles are fixed for the association's lifetime. A re-answer
            // implying the opposite role is asking for a NEW association, which we do not do underneath an
            // ICE restart. Refuse it with a typed reason; silently ignoring it would leave the peer
            // handshaking against a role we never adopted, and the session hanging with no explanation.
            val f = connectedPeers()

            f.alice.restartIce()
            val offer = f.alice.createOffer()
            f.alice.setLocalDescription(SdpType.Offer, offer)
            f.bob.setRemoteDescription(SdpType.Offer, offer)
            val answer = f.bob.createAnswer()
            f.alice.setRemoteDescription(SdpType.Answer, answer.replace("a=setup:active", "a=setup:passive"))

            val failed =
                assertNotNull(
                    withTimeoutOrNull(timeout) { f.alice.connectionState.first { it is PeerConnectionState.Failed } },
                    "a role flip on renegotiation is refused, not ignored",
                )
            assertEquals(
                PeerConnectionFailureReason.Dtls(DtlsFailureReason.RoleChangeOnRenegotiation),
                (failed as PeerConnectionState.Failed).reason,
            )
        }

    // ---- recovery from a terminal ICE failure (RFC 7675 §5.1, issue #81) ----------------------------

    @Test
    fun a_consent_revoked_session_fails_and_nothing_but_a_restart_brings_it_back() =
        runTest {
            // The premise every fixture below rests on, asserted first so the rest cannot be vacuous: when
            // the path dies, the session really does reach a TERMINAL failure and really does stay there.
            // (`IceConsentTerminalTest` proves the same at the agent; this is the session's own statement,
            // and it is what makes "did not revoke" a meaningful assertion out on the interop lanes.)
            val f = connectedPeers(iceConfig = FAST_CONSENT)
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "consent/terminal"))
            assertEquals("before", echo(channel, "before"))

            f.net.tearDown(SocketAddress.ofLiteral(ALICE_IP, ALICE_FIRST_PORT))

            assertEquals(
                PeerConnectionFailureReason.Ice(IceFailureReason.ConsentExpired),
                (awaitFailed(f.alice) as PeerConnectionState.Failed).reason,
                "the selected pair going silent revokes consent and fails the session (RFC 7675 §4.1)",
            )
            assertNull(
                withTimeoutOrNull(QUIET) { f.alice.connectionState.first { it !is PeerConnectionState.Failed } },
                "and nothing self-heals it — a revoked generation may never be used again (RFC 7675 §5.1)",
            )
        }

    @Test
    fun restart_ice_recovers_a_consent_revoked_session_with_the_association_intact() =
        runTest {
            // The issue itself (#81): RFC 7675 §5.1's remedy, reachable from the session API. The sharp part
            // is not that ICE reconverges — that was already true at the agent — but that the association
            // comes back with it. A restart renegotiates ICE and NOTHING else (RFC 8842 §5.5), so a stack
            // that quietly rebuilt DTLS/SCTP under the recovery would show up here as a renumbered stream.
            val f = connectedPeers(iceConfig = FAST_CONSENT)
            val states = mutableListOf<PeerConnectionState>()
            backgroundScope.launch { f.alice.connectionState.collect { states += it } }
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "consent/recovery"))
            val streamId = channel.id
            assertEquals("before", echo(channel, "before"))
            val pairBefore = knownPair(f.alice.connectionState.value)

            f.net.tearDown(SocketAddress.ofLiteral(ALICE_IP, ALICE_FIRST_PORT))
            awaitFailed(f.alice)
            awaitFailed(f.bob)

            f.alice.restartIce()
            renegotiate(f.alice, f.bob)

            val connected =
                assertNotNull(
                    withTimeoutOrNull(timeout) { f.alice.connectionState.first { it is PeerConnectionState.Connected } },
                    "restartIce() is the way out of a terminal ICE failure, not a new PeerConnection",
                )
            assertNotEquals(pairBefore, knownPair(connected), "…on a pair the revoked credentials never touched")
            assertEquals(streamId, channel.id, "the data channel kept its stream id across the outage")
            assertEquals("after", echo(channel, "after"), "and still round-trips — the association was never rebuilt")

            // …and it went the W3C way round: `failed` → `connecting` → `connected`, not straight back to a
            // live state. Not decoration — republishing Connecting is what un-latches `fail`, so a session
            // that fails AGAIN on the new generation can say so instead of still reporting the old cause.
            // `Restarting` would be the other wrong answer: it promises data still flowing on a retained
            // pair, and a revoked generation is never retained (RFC 7675 §5.1).
            val recovery = states.subList(states.indexOfLast { it is PeerConnectionState.Failed }, states.size)
            assertEquals(
                listOf(PeerConnectionState.Failed(PeerConnectionFailureReason.Ice(IceFailureReason.ConsentExpired))) +
                    PeerConnectionState.Connecting + connected,
                recovery,
                "the recovery is failed → connecting → connected, with nothing else in between",
            )
        }

    @Test
    fun the_peers_restart_alone_revives_a_session_whose_own_consent_died() =
        runTest {
            // Bob never calls restartIce(): his side is revived by the offer alone. That matters because the
            // two peers revoke independently — whoever notices first restarts, and the other must come back
            // off new remote credentials rather than sitting terminal until its own app happens to act.
            val f = connectedPeers(iceConfig = FAST_CONSENT)
            val channel = f.alice.createDataChannel(DataChannelConfig(label = "consent/peer"))
            assertEquals("before", echo(channel, "before"))
            val bobPairBefore = knownPair(f.bob.connectionState.value)

            f.net.tearDown(SocketAddress.ofLiteral(ALICE_IP, ALICE_FIRST_PORT))
            awaitFailed(f.alice)
            // Waiting for BOB's terminal too is load-bearing: restarting while he is still Connected would
            // exercise the ordinary restart path and prove nothing about recovery.
            awaitFailed(f.bob)

            f.alice.restartIce()
            renegotiate(f.alice, f.bob)

            val bobAfter =
                assertNotNull(
                    withTimeoutOrNull(timeout) { f.bob.connectionState.first { it is PeerConnectionState.Connected } },
                    "bob left his own terminal failure on the strength of the peer's new credentials",
                )
            assertNotEquals(bobPairBefore, knownPair(bobAfter))
            assertEquals("after", echo(channel, "after"), "and the channel survived on both sides")
        }

    @Test
    fun a_failure_an_ice_restart_cannot_mend_stays_failed() =
        runTest {
            // The limit, and the reason recovery discriminates on the typed reason instead of just leaving
            // Failed on any restart. A re-answer that flips the DTLS role is REFUSED on purpose (RFC 8842
            // §5.5) — and the association underneath is still perfectly up, so a recovery that did not ask
            // *why* the session failed would walk it straight back to Connected and undo the refusal.
            val f = connectedPeers()
            f.alice.restartIce()
            val offer = f.alice.createOffer()
            f.alice.setLocalDescription(SdpType.Offer, offer)
            f.bob.setRemoteDescription(SdpType.Offer, offer)
            val answer = f.bob.createAnswer()
            f.alice.setRemoteDescription(SdpType.Answer, answer.replace("a=setup:active", "a=setup:passive"))
            val refused = assertNotNull(withTimeoutOrNull(timeout) { f.alice.connectionState.first { it is PeerConnectionState.Failed } })

            // Ask for a restart anyway. The ICE generation is genuinely swapped — the app asked for one and
            // the next offer must not lie about it — but the session does not come back.
            f.alice.restartIce()
            val credentialsBefore = ufragOf(offer)
            val restartOffer = f.alice.createOffer()
            assertNotEquals(credentialsBefore, ufragOf(restartOffer), "the restart itself is honoured")

            assertNull(
                withTimeoutOrNull(QUIET) { f.alice.connectionState.first { it != refused } },
                "but a DTLS refusal is not something a fresh candidate pair can mend, so the session stays failed",
            )
            assertEquals(
                PeerConnectionFailureReason.Dtls(DtlsFailureReason.RoleChangeOnRenegotiation),
                (f.alice.connectionState.value as PeerConnectionState.Failed).reason,
                "…with the cause it already had, un-relabelled",
            )
        }

    @Test
    fun an_ice_failure_before_the_association_exists_is_recoverable_too() =
        runTest {
            // Recovery is not only for sessions that once worked. A first negotiation whose candidates never
            // reached the peer fails with a typed ICE reason before DTLS is ever attempted; the restart then
            // has to run the WHOLE establishment — handshake and association included — rather than re-ride
            // one. Both halves of that branch are worth a fixture, because only one of them is on the path a
            // healthy session takes.
            val net = TestNet()
            val binder = DatagramBinder { net.bind(it) }
            val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
            val alice = peer(Random(1), binder, clock, GenerationalGathering(ALICE_IP, ALICE_FIRST_PORT))
            val bob = peer(Random(2), binder, clock, GenerationalGathering(BOB_IP, BOB_FIRST_PORT))
            // Trickle is WITHHELD for the first round — a signaling path that carries the offer/answer and
            // then drops the candidates. It has to be withheld in BOTH directions: one-way is not enough,
            // because the peer that does receive candidates checks against them, and the first such check
            // teaches the other side a peer-reflexive candidate (RFC 8445 §7.3.1.3) and the session simply
            // establishes. From the restart on, candidates flow normally.
            var delivering = false
            backgroundScope.launch { alice.localIceCandidates.collect { if (delivering) bob.addIceCandidate(it) } }
            backgroundScope.launch { bob.localIceCandidates.collect { if (delivering) alice.addIceCandidate(it) } }
            backgroundScope.launch {
                bob.incomingDataChannels.collect { channel -> launch { channel.receive().collect { channel.send(it) } } }
            }
            val channel = alice.createDataChannel(DataChannelConfig(label = "consent/cold"))
            renegotiate(alice, bob)

            val failed = assertNotNull(withTimeoutOrNull(timeout) { awaitFailed(alice) }) as PeerConnectionState.Failed
            assertIs<PeerConnectionFailureReason.Ice>(failed.reason, "a session with nothing to pair fails at ICE, before DTLS")

            delivering = true
            alice.restartIce()
            renegotiate(alice, bob)

            assertNotNull(
                withTimeoutOrNull(timeout) { alice.connectionState.first { it is PeerConnectionState.Connected } },
                "the restart ran a full establishment — DTLS handshake and SCTP association included",
            )
            assertEquals("after", echo(channel, "after"), "and the channel queued before any of it opened for real")
        }

    @Test
    fun losing_an_interface_restarts_a_consent_dead_session_automatically() =
        runTest {
            // The automatic policy's blind spot, closed. `pathRidesOneOf` answers true whenever nothing is
            // nominated — right for a session still converging, exactly wrong for one whose pair was revoked,
            // and the two are the same unnominated path. So the policy never fired on the failure mode it is
            // most obviously for: the interface went away, consent died with it, and here comes the next one.
            val monitor = ScriptedMonitor(listOf(iface("wifi", ALICE_IP)))
            val f = connectedPeers(aliceRestartPolicy = IceRestartPolicy.OnNetworkChange(monitor), iceConfig = FAST_CONSENT)
            assertEquals("before", echo(f.alice.createDataChannel(DataChannelConfig(label = "consent/auto")), "before"))

            f.net.tearDown(SocketAddress.ofLiteral(ALICE_IP, ALICE_FIRST_PORT))
            awaitFailed(f.alice)

            // Deliberately an interface set that still CONTAINS alice's address: `pathRidesOneOf` would say
            // "nothing to do" on its own, so the only reason left to restart is the failure itself.
            monitor.emit(listOf(iface("wifi", ALICE_IP), iface("cellular", "10.0.0.9")))

            assertNotNull(
                withTimeoutOrNull(timeout) { f.alice.renegotiationNeeded.first() },
                "an interface change on a consent-dead session asks the app for the round that recovers it",
            )
            renegotiate(f.alice, f.bob)
            assertNotNull(
                withTimeoutOrNull(timeout) { f.alice.connectionState.first { it is PeerConnectionState.Connected } },
                "and the round the policy asked for carries the recovery",
            )
        }

    // ---- fixture plumbing ---------------------------------------------------------------------------

    private class Peers(
        val net: TestNet,
        val alice: NativePeerConnection,
        val bob: NativePeerConnection,
    )

    /**
     * Gathers one host candidate per ICE generation, on a **fresh port each time**. That is what a real
     * interface change looks like, and it is forced anyway: the network — like an OS — refuses to re-bind an
     * address that is still open, and across a restart the outgoing generation's socket deliberately is.
     */
    private class GenerationalGathering(
        private val ip: String,
        firstPort: Int,
    ) : IceGatheringPolicy {
        private var nextPort = firstPort

        override suspend fun gather(driver: IceAgentDriver) {
            driver.gatherHost(ip, nextPort++)
        }
    }

    /** A [NetworkMonitor] whose interface set is driven by the fixture — a scripted Wi-Fi↔cellular flip. */
    private class ScriptedMonitor(
        initial: List<LocalInterface>,
    ) : NetworkMonitor {
        private val state = MutableStateFlow(initial)

        override fun interfaces(): List<LocalInterface> = state.value

        override val changes: Flow<List<LocalInterface>> get() = state

        fun emit(interfaces: List<LocalInterface>) {
            state.value = interfaces
        }
    }

    /**
     * An interface as a real [NetworkMonitor] would report it: an address with **no meaningful port**.
     * Enumerating interfaces tells you nothing about which ephemeral port ICE bound on one, so a fixture
     * that helpfully supplies the matching port would prove the policy works only for a monitor that
     * cannot exist.
     */
    private fun iface(
        id: String,
        ip: String,
    ) = LocalInterface(NetworkId(id), SocketAddress.ofLiteral(ip, NO_PORT))

    private suspend fun TestScope.connectedPeers(
        aliceRestartPolicy: IceRestartPolicy = IceRestartPolicy.Manual,
        iceConfig: IceConfig = IceConfig(),
    ): Peers {
        val net = TestNet()
        val binder = DatagramBinder { net.bind(it) }
        val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
        val alice =
            peer(
                Random(1),
                binder,
                clock,
                GenerationalGathering(ALICE_IP, ALICE_FIRST_PORT),
                PeerConnectionConfig(iceConfig = iceConfig, iceRestartPolicy = aliceRestartPolicy),
            )
        val bob = peer(Random(2), binder, clock, GenerationalGathering(BOB_IP, BOB_FIRST_PORT), PeerConnectionConfig(iceConfig = iceConfig))
        trickle(backgroundScope, from = alice, to = bob)
        trickle(backgroundScope, from = bob, to = alice)

        // Bob is the universal reflector every interop answerer runs: echo whatever arrives, on the channel
        // it arrived on. It has no idea a restart is coming, which is the point.
        backgroundScope.launch {
            bob.incomingDataChannels.collect { channel ->
                launch { channel.receive().collect { channel.send(it) } }
            }
        }

        renegotiate(alice, bob)
        assertNotNull(withTimeoutOrNull(timeout) { alice.awaitConnected() }, "alice connected")
        assertNotNull(withTimeoutOrNull(timeout) { bob.awaitConnected() }, "bob connected")
        return Peers(net, alice, bob)
    }

    /** One peer of the pair — the production composition, with only the seams (clock/entropy/net) injected. */
    private fun TestScope.peer(
        random: Random,
        binder: DatagramBinder,
        clock: () -> Instant,
        gathering: IceGatheringPolicy,
        config: PeerConnectionConfig = PeerConnectionConfig(),
    ) = NativePeerConnection(
        scope = backgroundScope,
        clock = clock,
        random = random,
        binder = binder,
        gathering = gathering,
        dtls = PlaintextDtls,
        config = config,
    )

    /** Suspend until [pc] reports a terminal failure, and return it. */
    private suspend fun awaitFailed(pc: NativePeerConnection): PeerConnectionState =
        pc.connectionState.first { it is PeerConnectionState.Failed }

    /** One full offer/answer round over the app's signaling seam — the round a restart needs to be carried. */
    private suspend fun renegotiate(
        offerer: NativePeerConnection,
        answerer: NativePeerConnection,
    ) {
        val offer = offerer.createOffer()
        offerer.setLocalDescription(SdpType.Offer, offer)
        answerer.setRemoteDescription(SdpType.Offer, offer)
        val answer = answerer.createAnswer()
        answerer.setLocalDescription(SdpType.Answer, answer)
        offerer.setRemoteDescription(SdpType.Answer, answer)
    }

    /** The pair a live state is riding. A state that carries no known pair is a fixture bug, not a case. */
    private fun knownPair(state: PeerConnectionState) =
        when (state) {
            is PeerConnectionState.Connected -> assertIs<SelectedPath.Known>(state.path).pair
            is PeerConnectionState.Restarting -> assertIs<SelectedPath.Known>(state.path).pair
            else -> error("not a live state: $state")
        }

    private fun ufragOf(sdp: String): String =
        sdp
            .lineSequence()
            .first { it.startsWith("a=ice-ufrag:") }
            .substringAfter(':')

    private suspend fun echo(
        channel: Connection<ReadBuffer>,
        text: String,
    ): String? {
        channel.send(textBuffer(text))
        return withTimeoutOrNull(timeout) { channel.receive().first().text() }
    }

    private fun trickle(
        scope: CoroutineScope,
        from: NativePeerConnection,
        to: NativePeerConnection,
    ) {
        scope.launch {
            from.localIceCandidates.collect { to.addIceCandidate(it) }
        }
    }

    private suspend fun NativePeerConnection.awaitConnected(): PeerConnectionState =
        connectionState.first {
            when (it) {
                is PeerConnectionState.Connected -> true
                is PeerConnectionState.Failed -> error("expected a connection, but PeerConnection failed: ${it.reason}")
                else -> false
            }
        }

    private fun textBuffer(s: String): ReadBuffer {
        val bytes = s.encodeToByteArray()
        val buf = BufferFactory.managed().allocate(maxOf(1, bytes.size), ByteOrder.BIG_ENDIAN)
        for (b in bytes) buf.writeByte(b)
        buf.resetForRead()
        buf.setLimit(bytes.size)
        return buf
    }

    private fun ReadBuffer.text(): String {
        val out = StringBuilder()
        for (i in position() until limit()) out.append((get(i).toInt() and 0xFF).toChar())
        return out.toString()
    }

    private companion object {
        const val ALICE_IP = "10.0.0.1"
        const val BOB_IP = "10.0.0.2"
        const val ALICE_FIRST_PORT = 4000

        /** What an interface enumeration reports for a port: nothing. */
        const val NO_PORT = 0
        const val BOB_FIRST_PORT = 5000

        /**
         * How long a "nothing should happen" assertion waits before believing it. Virtual time, so it costs
         * nothing; it is long enough that any restart the policy *was* going to request has been requested.
         */
        val QUIET = 30.seconds

        /**
         * Compressed RFC 7675 consent for the recovery fixtures — the RFC's own shape (checks paced at the
         * interval, revocation measured from the last response), an order of magnitude quicker. The clock is
         * virtual, so this buys nothing in wall time; it buys headroom under [QUIET] and [timeout], which
         * would otherwise have to be stretched past the RFC's 30 s window for every "nothing happens" wait.
         */
        val FAST_CONSENT = IceConfig(consentInterval = 1.seconds, consentTimeout = 5.seconds)
    }
}

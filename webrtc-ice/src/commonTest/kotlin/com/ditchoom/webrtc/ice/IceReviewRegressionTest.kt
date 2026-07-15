@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
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
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * Regression fixtures for the defects the adversarial review gate (EXECUTION_PLAN §1) confirmed — each
 * ships with the fix (directive #5). They cover the role-conflict inversion, the MESSAGE-INTEGRITY
 * splice, the typed-`NoCandidatePairs` liveness backstop, and the "nomination can't complete → terminal,
 * never hang" invariant.
 */
@OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)
class IceReviewRegressionTest {
    @Test
    fun controlled_vs_controlled_glare_converges_to_one_controlling_agent() =
        runTest {
            // Both agents start CONTROLLED (reachable on restart / non-JSEP). RFC 8445 §7.3.1.1: the larger
            // tie-breaker ends up controlling. The pre-fix inverted comparison thrashed and never converged.
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlled, seed = 10, vnet = vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 20, vnet = vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()
            alice.bindHost("10.0.0.1", 4000)
            bob.bindHost("10.0.0.2", 5000)
            alice.connectTo(bob)
            bob.connectTo(alice)

            assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "Alice connects out of the controlled-vs-controlled glare")
            assertNotNull(withTimeoutOrNull(TIMEOUT) { bob.awaitConnected() }, "Bob connects")
            assertTrue(
                alice.agent.role != bob.agent.role,
                "exactly one agent ends up controlling (aRole=${alice.agent.role} bRole=${bob.agent.role})",
            )
        }

    @Test
    fun a_use_candidate_spliced_after_message_integrity_is_not_trusted() {
        // Simulate a MITM splice (RFC 8489 §14.5): a legitimately-keyed check with USE-CANDIDATE appended
        // AFTER MESSAGE-INTEGRITY and a recomputed (unkeyed) FINGERPRINT. Both MI and FINGERPRINT verify,
        // but the agent reads only the MI-covered prefix, so the spliced USE-CANDIDATE must be invisible.
        val key = utf8Buffer("s3cret")
        val txid = TransactionId.random(Random(1))
        val spliced =
            StunMessageBuilder
                .of(StunClass.Request, StunMethod.Binding, txid)
                .add(RawAttribute.ofText(StunAttributeType.Username, "bob:alice"))
                .add(IceAttributes.priority(IceCandidate.computePriority(CandidateType.PeerReflexive, ComponentId.Rtp)))
                .add(IceAttributes.controlling(TieBreaker(1)))
                .addMessageIntegrity(key) // MI covers everything ABOVE this line
                .add(IceAttributes.useCandidate()) // spliced AFTER MI — the MITM's injection
                .addFingerprint()
                .encode()

        val message = (StunMessage.decode(spliced) as StunDecodeResult.Success).message
        assertTrue(message.verifyMessageIntegrity(utf8Buffer("s3cret")), "the spliced message still has a valid MI")
        assertTrue(message.verifyFingerprint(), "and a valid (unkeyed) FINGERPRINT")
        // The full attribute list contains USE-CANDIDATE, but the MI-covered prefix — what the agent trusts — does not.
        assertTrue(message.attributes.any { it.type == IceAttributes.USE_CANDIDATE }, "USE-CANDIDATE is on the wire")
        val covered = message.attributesCoveredByMessageIntegrity()!!
        assertFalse(covered.any { it.type == IceAttributes.USE_CANDIDATE }, "but is NOT in the MI-covered prefix the agent reads")
    }

    @Test
    fun zero_compatible_candidates_fails_with_NoCandidatePairs_not_a_hang() =
        runTest {
            // Remote credentials + a remote candidate the agent can never pair with (IPv6 vs our IPv4):
            // the checklist stays empty, so the agent must fail with the typed NoCandidatePairs, not hang.
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val config = IceConfig(establishmentTimeout = 5.seconds)
            val alice = IceDriver(IceRole.Controlling, seed = 1, vnet = vnet, scope = backgroundScope, clock = clock, config = config)
            alice.start()
            alice.bindHost("10.0.0.1", 4000)
            alice.post(IceEvent.SetRemoteCredentials(IceCredentials.random(Random(99))))
            alice.post(IceEvent.AddRemoteCandidate(ipv6Candidate()))

            val failure = withTimeoutOrNull(TIMEOUT) { alice.state.first { it is IceConnectionState.Failed } }
            assertTrue(
                failure is IceConnectionState.Failed && failure.reason == IceFailureReason.NoCandidatePairs,
                "an empty checklist fails with NoCandidatePairs, got $failure",
            )
        }

    @Test
    fun nomination_that_can_never_complete_reaches_a_terminal_state() =
        runTest {
            // A peer that answers ordinary checks (so the pair validates) but never confirms nomination:
            // the controlling agent must not wedge on `nominationInFlight` — it reaches a typed terminal.
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val config = IceConfig(establishmentTimeout = 8.seconds)
            val alice = IceDriver(IceRole.Controlling, seed = 1, vnet = vnet, scope = backgroundScope, clock = clock, config = config)
            alice.start()
            alice.bindHost("10.0.0.1", 4000)

            val peerAddress = vnetAddress("10.0.0.2", 5000)
            val peer = DropNominationPeer(peerAddress, vnet, backgroundScope, password = "peerpass")
            peer.start()

            // Wire the agent to the scripted peer (creds + host candidate) as trickle would.
            alice.post(IceEvent.SetRemoteCredentials(IceCredentials(Ufrag("peer"), IcePassword("peerpass"))))
            alice.post(IceEvent.AddRemoteCandidate(IceCandidate.host(peerAddress.toTransportAddress())))

            val terminal =
                withTimeoutOrNull(TIMEOUT) {
                    alice.state.first { it is IceConnectionState.Failed || it is IceConnectionState.Completed }
                }
            assertNotNull(terminal, "the agent reaches a terminal state instead of hanging on an un-completable nomination")
        }

    /**
     * A scripted ICE peer that answers ordinary connectivity checks with a valid success response (so the
     * agent's pair validates) but **drops any check carrying USE-CANDIDATE** — modeling a peer that never
     * confirms nomination, the shape that exposed the `nominationInFlight` wedge.
     */
    private class DropNominationPeer(
        private val address: SocketAddress,
        private val vnet: Vnet,
        private val scope: CoroutineScope,
        private val password: String,
    ) {
        fun start() {
            val channel = vnet.bind(address)
            scope.launch {
                while (true) {
                    val datagram =
                        when (val result = channel.receive()) {
                            is DatagramReadResult.Received -> result.datagram
                            is DatagramReadResult.Closed -> return@launch
                        }
                    val message = (StunMessage.decode(datagram.payload) as? StunDecodeResult.Success)?.message ?: continue
                    if (message.messageType.stunClass != StunClass.Request || message.messageType.method != StunMethod.Binding) continue
                    if (message.firstOrNull(IceAttributes.USE_CANDIDATE) != null) continue // never confirm nomination
                    val response =
                        StunMessageBuilder
                            .of(StunClass.SuccessResponse, StunMethod.Binding, message.transactionId)
                            .add(RawAttribute.ofXorMappedAddress(datagram.peer.toTransportAddress(), message.transactionId))
                            .addMessageIntegrity(utf8Buffer(password))
                            .addFingerprint()
                            .encode()
                    channel.send(response, to = datagram.peer)
                }
            }
        }
    }

    private fun ipv6Candidate(): IceCandidate {
        val address =
            com.ditchoom.webrtc.stun
                .TransportAddress(
                    com.ditchoom.webrtc.stun.IpAddress
                        .V6(0uL, 1uL),
                    5000u,
                )
        return IceCandidate.Host(
            address = address,
            component = ComponentId.Rtp,
            transport = IceTransport.Udp,
            foundation = Foundation.of(CandidateType.Host, "::1", serverIp = null, transport = IceTransport.Udp),
            priority = IceCandidate.computePriority(CandidateType.Host, ComponentId.Rtp),
        )
    }

    private companion object {
        val TIMEOUT = 60.seconds
    }
}

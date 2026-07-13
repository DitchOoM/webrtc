@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sdp

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The sans-io JSEP offer/answer machine ([JsepSession]) driven with no I/O and no wall clock — the
 * offer/answer values arrive through a scripted "signaling seam" (just method calls here). Because the
 * core arms no timers and reads no ambient clock, the whole exchange is a synchronous, deterministic
 * fold over injected time (`t0`) that runs identically on every platform (RFC §5.1). Asserts observable
 * state: the RFC 8829 §3.5.1 transition table, rollback, and that illegal edges are typed rejects that
 * leave the state untouched (directive #3/#4), never throws.
 */
class JsepSessionTest {
    private val t0 = Instant.fromEpochMilliseconds(0)

    private fun offerer() = JsepSession(Random(1))

    private fun answerer() = JsepSession(Random(2))

    private fun params(setup: SetupRole) =
        DataChannelParameters(
            iceUfrag = "ufrag",
            icePwd = "0123456789abcdef0123456789abcdef",
            fingerprint =
                Fingerprint(
                    "sha-256",
                    "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
                ),
            setup = setup,
        )

    @Test
    fun nextDeadlineIsAlwaysNull() {
        // JSEP arms no timers of its own — the honest single meaning of a null deadline.
        assertNull(offerer().nextDeadline())
    }

    @Test
    fun fullOfferAnswerReachesStable() {
        val local = offerer()
        val remote = answerer()

        // Offerer: createOffer → setLocal(offer). Signaling seam ships it to the remote (setRemote).
        val offer = local.createOffer(params(SetupRole.ActPass))
        assertStateChange(
            local.handle(JsepEvent.SetLocalDescription(SdpType.Offer, offer), t0),
            SignalingState.Stable,
            SignalingState.HaveLocalOffer,
        )
        assertEquals(SignalingState.HaveLocalOffer, local.signalingState)

        assertStateChange(
            remote.handle(JsepEvent.SetRemoteDescription(SdpType.Offer, offer), t0),
            SignalingState.Stable,
            SignalingState.HaveRemoteOffer,
        )

        // Answerer: createAnswer(active) → setLocal(answer); seam ships it back (setRemote(answer)).
        val answer = remote.createAnswer(params(SetupRole.Active))
        assertStateChange(
            remote.handle(JsepEvent.SetLocalDescription(SdpType.Answer, answer), t0),
            SignalingState.HaveRemoteOffer,
            SignalingState.Stable,
        )
        assertStateChange(
            local.handle(JsepEvent.SetRemoteDescription(SdpType.Answer, answer), t0),
            SignalingState.HaveLocalOffer,
            SignalingState.Stable,
        )

        // Both stable; descriptions retained on both sides.
        assertEquals(SignalingState.Stable, local.signalingState)
        assertEquals(SignalingState.Stable, remote.signalingState)
        assertEquals(offer.toText(), local.localDescription?.toText())
        assertEquals(answer.toText(), local.remoteDescription?.toText())
    }

    @Test
    fun generatedOfferIsAWellFormedRoundTrippingDataChannel() {
        val offer = offerer().createOffer(params(SetupRole.ActPass))
        val r = SessionDescription.parse(sdpBufferOf(offer.toText()))
        assertIs<SdpParseResult.Success>(r)
        val m = r.description.mediaDescriptions.single()
        assertTrue(m.mediaLine()!!.isDataChannel)
        assertEquals(SetupRole.ActPass, m.setup())
        assertEquals(5000, m.sctpPort())
        assertEquals(Mid("0"), m.mid())
        assertEquals(listOf(listOf(Mid("0"))), r.description.bundleGroups())
    }

    @Test
    fun sessionIdIsStableAndVersionIncrements() {
        val s = offerer()
        val o1 = s.createOffer(params(SetupRole.ActPass))
        val o2 = s.createOffer(params(SetupRole.ActPass))
        assertEquals(o1.origin()!!.sessionId, o2.origin()!!.sessionId, "session id is stable within a session")
        assertEquals("0", o1.origin()!!.sessionVersion)
        assertEquals("1", o2.origin()!!.sessionVersion)
    }

    @Test
    fun seededEntropyMakesSessionIdReplayable() {
        assertEquals(JsepSession(Random(42)).sessionId, JsepSession(Random(42)).sessionId)
    }

    @Test
    fun answerBeforeRemoteOfferIsInvalidTransition() {
        val s = offerer()
        val out = s.handle(JsepEvent.SetLocalDescription(SdpType.Answer, offerer().createOffer(params(SetupRole.Active))), t0)
        val rejected = assertIs<JsepOutput.Rejected>(out.single())
        val err = assertIs<JsepError.InvalidTransition>(rejected.error)
        assertEquals(SignalingState.Stable, err.from)
        assertEquals(SignalingState.Stable, s.signalingState, "a rejected event leaves the state untouched")
    }

    @Test
    fun glareRollbackReturnsToStable() {
        val s = offerer()
        val offer = s.createOffer(params(SetupRole.ActPass))
        s.handle(JsepEvent.SetLocalDescription(SdpType.Offer, offer), t0)
        assertEquals(SignalingState.HaveLocalOffer, s.signalingState)

        // Rollback (glare resolution): discard the pending local offer, back to stable, description cleared.
        assertStateChange(
            s.handle(JsepEvent.SetLocalDescription(SdpType.Rollback, null), t0),
            SignalingState.HaveLocalOffer,
            SignalingState.Stable,
        )
        assertNull(s.localDescription)
    }

    @Test
    fun rollbackAfterRenegotiationRestoresThePreviousStableDescriptions() {
        // Regression (review finding #1): a rollback must restore the LAST STABLE descriptions, not
        // null. Establish a stable session, start a second offer, then roll it back — the effective
        // descriptions must revert to the first negotiation's pair (RFC 8829 §4.1.8.2), not be lost.
        val local = offerer()
        val remote = answerer()
        val offer1 = local.createOffer(params(SetupRole.ActPass))
        local.handle(JsepEvent.SetLocalDescription(SdpType.Offer, offer1), t0)
        remote.handle(JsepEvent.SetRemoteDescription(SdpType.Offer, offer1), t0)
        val answer1 = remote.createAnswer(params(SetupRole.Active))
        local.handle(JsepEvent.SetRemoteDescription(SdpType.Answer, answer1), t0)
        assertEquals(SignalingState.Stable, local.signalingState)

        // Second offer begins renegotiation; effective local description is now offer2.
        val offer2 = local.createOffer(params(SetupRole.ActPass))
        local.handle(JsepEvent.SetLocalDescription(SdpType.Offer, offer2), t0)
        assertEquals(offer2.toText(), local.localDescription?.toText())

        // Roll it back — both effective descriptions snap back to the last stable pair, not null.
        local.handle(JsepEvent.SetLocalDescription(SdpType.Rollback, null), t0)
        assertEquals(SignalingState.Stable, local.signalingState)
        assertEquals(offer1.toText(), local.localDescription?.toText(), "rollback restores the previous stable local description")
        assertEquals(answer1.toText(), local.remoteDescription?.toText(), "rollback preserves the stable remote description")
    }

    @Test
    fun rollbackInStableIsInvalid() {
        val out = offerer().handle(JsepEvent.SetLocalDescription(SdpType.Rollback, null), t0)
        assertIs<JsepError.InvalidTransition>(assertIs<JsepOutput.Rejected>(out.single()).error)
    }

    @Test
    fun provisionalAnswerFlow() {
        val remote = answerer()
        val offer = offerer().createOffer(params(SetupRole.ActPass))
        remote.handle(JsepEvent.SetRemoteDescription(SdpType.Offer, offer), t0)
        // Local pranswer keeps us out of stable, then the final answer settles it.
        assertStateChange(
            remote.handle(JsepEvent.SetLocalDescription(SdpType.PrAnswer, remote.createAnswer(params(SetupRole.Passive))), t0),
            SignalingState.HaveRemoteOffer,
            SignalingState.HaveLocalPrAnswer,
        )
        assertStateChange(
            remote.handle(JsepEvent.SetLocalDescription(SdpType.Answer, remote.createAnswer(params(SetupRole.Passive))), t0),
            SignalingState.HaveLocalPrAnswer,
            SignalingState.Stable,
        )
    }

    @Test
    fun missingDescriptionForNonRollbackIsRejected() {
        val out = offerer().handle(JsepEvent.SetLocalDescription(SdpType.Offer, null), t0)
        assertIs<JsepError.MissingDescription>(assertIs<JsepOutput.Rejected>(out.single()).error)
    }

    @Test
    fun closeIsTerminalAndRejectsFurtherDescriptions() {
        val s = offerer()
        assertStateChange(s.handle(JsepEvent.Close, t0), SignalingState.Stable, SignalingState.Closed)
        assertTrue(s.handle(JsepEvent.Close, t0).isEmpty(), "closing an already-closed session is a no-op")
        val out = s.handle(JsepEvent.SetLocalDescription(SdpType.Offer, s.createOffer(params(SetupRole.ActPass))), t0)
        assertIs<JsepError.SessionClosed>(assertIs<JsepOutput.Rejected>(out.single()).error)
    }

    @Test
    fun resettingSameSideOfferStaysInSameStateWithoutStateChangeEvent() {
        val s = offerer()
        s.handle(JsepEvent.SetLocalDescription(SdpType.Offer, s.createOffer(params(SetupRole.ActPass))), t0)
        val out = s.handle(JsepEvent.SetLocalDescription(SdpType.Offer, s.createOffer(params(SetupRole.ActPass))), t0)
        // Still have-local-offer; a re-offer applies a description but emits no signaling-state change.
        assertEquals(SignalingState.HaveLocalOffer, s.signalingState)
        assertTrue(out.none { it is JsepOutput.SignalingStateChanged })
        assertTrue(out.any { it is JsepOutput.DescriptionApplied })
    }

    private fun assertStateChange(
        outputs: List<JsepOutput>,
        from: SignalingState,
        to: SignalingState,
    ) {
        val change = outputs.filterIsInstance<JsepOutput.SignalingStateChanged>().single()
        assertEquals(from, change.from)
        assertEquals(to, change.to)
    }
}

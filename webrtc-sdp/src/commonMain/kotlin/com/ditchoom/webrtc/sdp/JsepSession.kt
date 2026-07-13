@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sdp

import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/** Which side of the exchange a description came from (`setLocalDescription` vs `setRemoteDescription`). */
public enum class DescriptionEndpoint {
    Local,
    Remote,
}

/** An event fed to a [JsepSession] (sans-io: the app/signaling seam owns I/O; the core owns truth). */
public sealed interface JsepEvent {
    /**
     * Apply a local description ([SdpType.Offer]/[SdpType.Answer]/[SdpType.PrAnswer]), or roll the
     * pending local offer back ([SdpType.Rollback], with a null [description]).
     */
    public data class SetLocalDescription(
        public val type: SdpType,
        public val description: SessionDescription?,
    ) : JsepEvent

    /** Apply a remote description, or roll the pending remote offer back ([SdpType.Rollback]). */
    public data class SetRemoteDescription(
        public val type: SdpType,
        public val description: SessionDescription?,
    ) : JsepEvent

    /** Close the session — every subsequent description event is rejected [JsepError.SessionClosed]. */
    public data object Close : JsepEvent
}

/** A side effect / observation emitted from [JsepSession.handle]. */
public sealed interface JsepOutput {
    /** A description was accepted and is now the effective local/remote description. */
    public data class DescriptionApplied(
        public val endpoint: DescriptionEndpoint,
        public val type: SdpType,
    ) : JsepOutput

    /** The signaling state changed (emitted only on an actual change, W3C `signalingstatechange`). */
    public data class SignalingStateChanged(
        public val from: SignalingState,
        public val to: SignalingState,
    ) : JsepOutput

    /** The event was rejected; the state is unchanged. The reason is typed, never a string (directive #3). */
    public data class Rejected(
        public val error: JsepError,
    ) : JsepOutput
}

/** Why a JSEP event was rejected — a sealed, exhaustive vocabulary (DESIGN_PRINCIPLES §6). */
public sealed interface JsepError {
    /** The (endpoint, type) is not a legal edge out of [from] in the offer/answer table (RFC 8829 §3.5.1). */
    public data class InvalidTransition(
        public val from: SignalingState,
        public val endpoint: DescriptionEndpoint,
        public val type: SdpType,
    ) : JsepError

    /** A non-rollback event carried a null description. */
    public data object MissingDescription : JsepError

    /** The session is [SignalingState.Closed]. */
    public data object SessionClosed : JsepError
}

/**
 * The sans-io JSEP offer/answer state machine (RFC 8829). It owns **truth, not I/O**: a pure
 * `handle(event, now): List<Output>` plus [nextDeadline] — no dispatcher, no clock, no socket, no
 * coroutine (DESIGN_PRINCIPLES §6). The app drives it from its signaling seam (the offer/answer values
 * arrive however the app ships them — HTTP, WebSocket, a test script), so the whole exchange replays
 * deterministically under `runTest` virtual time.
 *
 * The offer/answer transition table (RFC 8829 §3.5.1) is enforced in [transitionTo]; an illegal edge
 * is a typed [JsepError.InvalidTransition] output with the state left untouched, never a throw or a
 * silent no-op. Entropy is injected ([random], standing directive #2): the session id in a generated
 * offer's `o=` line comes from it, so ids are `CryptoRandom` in production and replayable in tests.
 *
 * [nextDeadline] is always null: JSEP arms no timers of its own (that is the honest single meaning of
 * a null deadline, DESIGN_PRINCIPLES §5). The `now` parameter is part of the uniform core contract and
 * reserved for future time-based signaling (e.g. an ICE-restart backstop).
 */
public class JsepSession(
    private val random: kotlin.random.Random,
    initialState: SignalingState = SignalingState.Stable,
) {
    public var signalingState: SignalingState = initialState
        private set

    /** The effective local description (the pending one if mid-negotiation, else the stable one), or null. */
    public var localDescription: SessionDescription? = null
        private set

    /** The effective remote description, or null. */
    public var remoteDescription: SessionDescription? = null
        private set

    // The last-stable descriptions (JSEP's `current*Description`, RFC 8829 §4.1.3): the snapshot a
    // rollback restores the effective pair to. Distinct from the effective pair so a re-offer that is
    // then rolled back reverts to the previous stable description, not to null.
    private var currentLocal: SessionDescription? = null
    private var currentRemote: SessionDescription? = null

    /** The stable session id for this session's `o=` lines (RFC 8829 §5.2.1) — from injected entropy. */
    public val sessionId: String = (random.nextLong() and Long.MAX_VALUE).toString()

    private var offerVersion = 0L

    /** JSEP arms no timers — always null (no deadline pending). */
    public fun nextDeadline(): Instant? = null

    public fun handle(
        event: JsepEvent,
        @Suppress("UNUSED_PARAMETER") now: Instant,
    ): List<JsepOutput> =
        when (event) {
            is JsepEvent.SetLocalDescription -> applyDescription(DescriptionEndpoint.Local, event.type, event.description)
            is JsepEvent.SetRemoteDescription -> applyDescription(DescriptionEndpoint.Remote, event.type, event.description)
            JsepEvent.Close -> close()
        }

    private fun applyDescription(
        endpoint: DescriptionEndpoint,
        type: SdpType,
        description: SessionDescription?,
    ): List<JsepOutput> {
        if (signalingState is SignalingState.Closed) return listOf(JsepOutput.Rejected(JsepError.SessionClosed))
        if (type != SdpType.Rollback && description == null) {
            return listOf(JsepOutput.Rejected(JsepError.MissingDescription))
        }
        val from = signalingState
        val to =
            transitionTo(from, endpoint, type)
                ?: return listOf(JsepOutput.Rejected(JsepError.InvalidTransition(from, endpoint, type)))

        // Commit the description effect before announcing the transition.
        when (type) {
            // Rollback discards ALL pending changes, restoring both effective descriptions to the last
            // stable snapshot (RFC 8829 §4.1.8.2) — not just the rolled-back side, and not to null.
            SdpType.Rollback -> {
                localDescription = currentLocal
                remoteDescription = currentRemote
            }
            else -> if (endpoint == DescriptionEndpoint.Local) localDescription = description else remoteDescription = description
        }
        signalingState = to
        // Reaching stable makes the now-applied effective pair the new stable baseline.
        if (to is SignalingState.Stable) {
            currentLocal = localDescription
            currentRemote = remoteDescription
        }

        val outputs = mutableListOf<JsepOutput>()
        if (type != SdpType.Rollback) outputs += JsepOutput.DescriptionApplied(endpoint, type)
        if (to != from) outputs += JsepOutput.SignalingStateChanged(from, to)
        return outputs
    }

    private fun close(): List<JsepOutput> {
        val from = signalingState
        if (from is SignalingState.Closed) return emptyList()
        signalingState = SignalingState.Closed
        return listOf(JsepOutput.SignalingStateChanged(from, SignalingState.Closed))
    }

    /**
     * Builds a data-channel offer (RFC 8829 + RFC 8841) stamped with this session's stable [sessionId]
     * and a monotonically increasing session version. This is a **pure generator** — it does not touch
     * signaling state; the caller applies it via [JsepEvent.SetLocalDescription]. The ICE/DTLS
     * parameters in [params] come from those layers (out of scope here); SDP only lays them out.
     */
    public fun createOffer(params: DataChannelParameters): SessionDescription = dataChannelDescription(params, sessionId, offerVersion++)

    /**
     * Builds a data-channel answer to the current [remoteDescription]. The answerer's resolved DTLS
     * role (active/passive) must already be set in [params]; JSEP does not invent it.
     */
    public fun createAnswer(params: DataChannelParameters): SessionDescription = dataChannelDescription(params, sessionId, offerVersion++)

    private companion object {
        /** The RFC 8829 §3.5.1 offer/answer transition table; null = not a legal edge. */
        fun transitionTo(
            from: SignalingState,
            endpoint: DescriptionEndpoint,
            type: SdpType,
        ): SignalingState? =
            when (endpoint) {
                DescriptionEndpoint.Local -> localTransition(from, type)
                DescriptionEndpoint.Remote -> remoteTransition(from, type)
            }

        fun localTransition(
            from: SignalingState,
            type: SdpType,
        ): SignalingState? =
            when (type) {
                SdpType.Offer ->
                    when (from) {
                        SignalingState.Stable, SignalingState.HaveLocalOffer -> SignalingState.HaveLocalOffer
                        else -> null
                    }
                SdpType.Answer ->
                    when (from) {
                        SignalingState.HaveRemoteOffer, SignalingState.HaveLocalPrAnswer -> SignalingState.Stable
                        else -> null
                    }
                SdpType.PrAnswer ->
                    when (from) {
                        SignalingState.HaveRemoteOffer, SignalingState.HaveLocalPrAnswer -> SignalingState.HaveLocalPrAnswer
                        else -> null
                    }
                SdpType.Rollback ->
                    when (from) {
                        SignalingState.HaveLocalOffer, SignalingState.HaveLocalPrAnswer -> SignalingState.Stable
                        else -> null
                    }
            }

        fun remoteTransition(
            from: SignalingState,
            type: SdpType,
        ): SignalingState? =
            when (type) {
                SdpType.Offer ->
                    when (from) {
                        SignalingState.Stable, SignalingState.HaveRemoteOffer -> SignalingState.HaveRemoteOffer
                        else -> null
                    }
                SdpType.Answer ->
                    when (from) {
                        SignalingState.HaveLocalOffer, SignalingState.HaveRemotePrAnswer -> SignalingState.Stable
                        else -> null
                    }
                SdpType.PrAnswer ->
                    when (from) {
                        SignalingState.HaveLocalOffer, SignalingState.HaveRemotePrAnswer -> SignalingState.HaveRemotePrAnswer
                        else -> null
                    }
                SdpType.Rollback ->
                    when (from) {
                        SignalingState.HaveRemoteOffer, SignalingState.HaveRemotePrAnswer -> SignalingState.Stable
                        else -> null
                    }
            }
    }
}

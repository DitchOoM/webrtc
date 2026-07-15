@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.stun.TransportAddress
import kotlin.time.ExperimentalTime

/**
 * An input to the sans-io [IceAgent] (RFC §5.1). The driver owns I/O and the clock; it feeds these and
 * applies the returned [IceOutput]s. Every event carries `now` at the call site — the core never reads
 * a clock — so the whole agent runs under `runTest` virtual time.
 */
public sealed interface IceEvent {
    /** A gathering driver produced a local candidate (host / srflx / relay). */
    public data class AddLocalCandidate(
        public val candidate: IceCandidate,
    ) : IceEvent

    /** Trickle (RFC 8838) delivered a remote candidate from signaling. */
    public data class AddRemoteCandidate(
        public val candidate: IceCandidate,
    ) : IceEvent

    /** The remote agent's ufrag/pwd arrived (from the SDP offer/answer). Pairing can begin. */
    public data class SetRemoteCredentials(
        public val credentials: IceCredentials,
    ) : IceEvent

    /**
     * A datagram arrived on the socket bound to [localBase], from [source]. The agent decodes it as a
     * STUN connectivity check (request/response); anything else is ignored (the driver routes DTLS/app
     * data elsewhere). [data] is a borrowed view valid only for this call.
     */
    public data class DatagramReceived(
        public val localBase: TransportAddress,
        public val source: TransportAddress,
        public val data: ReadBuffer,
    ) : IceEvent

    /** The driver's timer reached [IceAgent.nextDeadline] — run all checks/retransmits/consent due now. */
    public data object TimerFired : IceEvent

    /**
     * Begin an ICE restart (RFC 8445 §9): regenerate local credentials + tie-breaker, flush the
     * checklist and remote state. The driver then re-gathers and re-signals; the peer's new credentials
     * arrive via [SetRemoteCredentials].
     */
    public data object Restart : IceEvent
}

/**
 * A side effect the driver must perform for the [IceAgent]. The core returns these from `handle`; it
 * never touches a socket itself. Exhaustive and sealed so a driver `when`s over it with no `else`.
 */
public sealed interface IceOutput {
    /**
     * Send [data] from the socket bound to [fromBase] to [to] — a connectivity check, its response, or a
     * consent refresh. The driver maps [fromBase] to the [DatagramChannel][com.ditchoom.buffer.flow.DatagramChannel]
     * it gathered that candidate on. [data] is a fresh caller-owned buffer.
     */
    public data class Transmit(
        public val fromBase: TransportAddress,
        public val to: TransportAddress,
        public val data: ReadBuffer,
    ) : IceOutput

    /** The ICE connection state changed (RFC 8445 §6.1.2.6, JSEP `iceConnectionState`). */
    public data class ConnectionStateChanged(
        public val state: IceConnectionState,
    ) : IceOutput

    /**
     * The pair application traffic should now use changed to [pair] (its nominated valid pair). The
     * DTLS/SCTP layer sends over `pair.local.base → pair.remote.address`.
     */
    public data class SelectedPairChanged(
        public val pair: CandidatePair,
    ) : IceOutput
}

/**
 * The ICE connection state (RFC 8445 §6.1.2.6 checklist state, surfaced as JSEP `iceConnectionState`).
 * A sealed hierarchy where each state carries exactly the data valid in it — no `connected: Boolean`
 * plus a nullable pair (which could encode "connected but no pair"); the illegal combinations are
 * simply unrepresentable (DESIGN_PRINCIPLES §2).
 */
public sealed interface IceConnectionState {
    /** No checks started yet — awaiting candidates and remote credentials. */
    public data object New : IceConnectionState

    /** At least one pair is being checked; no nominated pair yet. */
    public data object Checking : IceConnectionState

    /** A valid pair has been nominated and is usable for data — [selected] is that pair. */
    public data class Connected(
        public val selected: CandidatePair,
    ) : IceConnectionState

    /** Connected **and** the checklist is finished (nothing left to check) — the steady state. */
    public data class Completed(
        public val selected: CandidatePair,
    ) : IceConnectionState

    /** Consent to a previously selected pair was lost (RFC 7675); may recover if a check succeeds again. */
    public data object Disconnected : IceConnectionState

    /** ICE gave up — the typed reason (no pairs, all failed, consent expired). */
    public data class Failed(
        public val reason: IceFailureReason,
    ) : IceConnectionState
}

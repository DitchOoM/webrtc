package com.ditchoom.webrtc

import com.ditchoom.webrtc.ice.CandidateDiscardReason
import com.ditchoom.webrtc.ice.InterfaceEnumerationFailure
import com.ditchoom.webrtc.stun.StunErrorCode
import com.ditchoom.webrtc.stun.TransportAddress

/**
 * Something a session decided that a caller cannot otherwise see — **non-fatal by construction**
 * (webrtc#106).
 *
 * **Why this is not a [PeerConnectionState].** Every case here leaves the session genuinely working. A
 * watcher that stopped, a candidate refused, an interface table that could not be read: in all three the
 * session is still `Connected` and still carrying data. Folding them into the lifecycle would make
 * "connected" mean two things, which is exactly the boolean-plus-nullable soup the state model exists to
 * forbid. They are *observations*, so they ride their own flow.
 *
 * **Why a flow at all, rather than logging.** Each of these was already computed, typed, and then
 * dropped on the floor because there was nowhere to put it. `IceAgentDriver` even said so in a comment —
 * "an output rather than a silent return so a fixture — and a future diagnostics surface — can see the
 * difference between a candidate discarded and a candidate that never arrived". This is that surface. A
 * consumer that wants none of it collects nothing and pays nothing.
 *
 * **The discriminant is the variant.** Where a case carries a payload it is an already-typed reason
 * ([CandidateDiscardReason], [InterfaceEnumerationFailure]) — never a string, per standing directive 3.
 * The single exception is [NetworkWatcherStopped.cause], and it is deliberate: that `Throwable` crosses
 * an API boundary from a [NetworkMonitor][com.ditchoom.webrtc.ice.NetworkMonitor] the **app** supplied,
 * so its type is the app's to know and ours to pass through intact. Branch on the variant; read the
 * `cause` to diagnose, never to decide.
 *
 * Delivery is **lossy on purpose** — see [RtcPeerConnection.diagnostics]. A diagnostic channel that can
 * stall the session it describes is worse than no diagnostic channel.
 */
public sealed interface SessionDiagnostic {
    /**
     * [IceRestartPolicy.OnNetworkChange] is no longer armed: collecting the app's
     * [NetworkMonitor][com.ditchoom.webrtc.ice.NetworkMonitor] raised, so the session has fallen back to
     * exactly what [IceRestartPolicy.Manual] would have given it.
     *
     * **The session is fine and stays fine** — that is the whole design, and it was not free. Before the
     * guard existed this throw escaped into the app's own `CoroutineScope` and cancelled everything it
     * held, so a one-line Android manifest mistake (`ACCESS_NETWORK_STATE` stripped, socket raising
     * `NetworkMonitorPermissionException`) killed a healthy data channel. What the guard could not do is
     * *say* so, which is why this variant exists: an app that opted into automatic restart and silently
     * stopped getting it had no way to find out short of registering a second collector on a monitor the
     * session already holds.
     *
     * Not retried, and there is no backoff worth writing: the causes are permanent by nature — a missing
     * install-time permission, a platform API that is simply absent. Fix the cause and build a new
     * session.
     */
    public data class NetworkWatcherStopped(
        /** What collection raised. Diagnostic payload — never a discriminant; see the type KDoc. */
        public val cause: Throwable,
    ) : SessionDiagnostic

    /**
     * A trickled remote candidate was deliberately not added to the checklist (RFC 8838 §3.1).
     *
     * Worth surfacing because "the candidate never arrived", "the candidate was malformed" and "the
     * candidate named a generation we have left" present identically — connectivity that should have
     * worked and did not — and only [reason] tells them apart. Routine during an ICE restart: a peer that
     * trickles candidates for the outgoing generation while the new one is being signaled produces these
     * by design, and they are not a fault.
     */
    public data class RemoteCandidateDiscarded(
        /** The `candidate:` line as signaled, verbatim, so it can be matched against the wire. */
        public val candidate: String,
        /** Why the core refused it — exhaustively matchable. */
        public val reason: CandidateDiscardReason,
    ) : SessionDiagnostic

    /**
     * The OS interface table could not be read, so automatic restart is running on a **stale** view of
     * the local addresses.
     *
     * Deliberately not treated as "every interface went away": that input is precisely what
     * `pathRidesOneOf` reads as *"the interface carrying our selected pair is gone"*, so reporting a
     * failed probe as an empty set would restart a healthy session on every signal. The last good set
     * stands instead — correct, and invisible, which is what this reports. A single occurrence is
     * usually transient; a persistent one means automatic restart is effectively disarmed while still
     * appearing armed.
     */
    public data class InterfaceProbeFailed(
        /** Why the enumeration failed — `NoPlatformApi` is permanent, `EnumerationFailed` may not be. */
        public val reason: InterfaceEnumerationFailure,
    ) : SessionDiagnostic

    /**
     * The **local socket** refused an outgoing ICE datagram — a connectivity check, a nomination, a
     * keep-alive, or relayed data.
     *
     * Non-fatal, and deliberately so: ICE is built to survive lost datagrams, so a refused transmit is
     * dropped and retransmitted exactly as a dropped one would be, and if the path is genuinely dead the
     * establishment and RFC 7675 consent backstops still reach a typed terminal on their own schedule.
     * The session is not in a distinct state and is not being lied to.
     *
     * **What this exists to make visible is the silent case.** Without it, a socket refusing every send
     * presents identically to a peer that stopped answering — the session ends at
     * `IceFailureReason.NoCandidatePairs` or `.ConsentExpired`, both of which name the symptom and point
     * outward, while the cause was local and already known inside the driver. A run of these against a
     * checklist that otherwise looks healthy is the tell, and it is not recoverable from any other
     * surface.
     *
     * A single occurrence is usually transient. A sustained stream means the local send path is broken —
     * a closed or unbound socket, a payload past the interface MTU, a route that went away.
     */
    public data class TransmitFailed(
        /**
         * What the socket raised. Diagnostic payload — never a discriminant; see the type KDoc.
         *
         * It stays a `Throwable` for the same reason [NetworkWatcherStopped.cause] does: it crosses an
         * API boundary from socket, so its type is socket's to define. Once DitchOoM/socket#278 releases
         * a sealed `DatagramSendError`, this is the field that gains a typed sibling — `TooLarge` is
         * permanent for that payload, where a transport failure is worth another attempt.
         */
        public val cause: Throwable,
    ) : SessionDiagnostic

    /**
     * A **TURN server refused a permission** (RFC 8656 §9), so that relay allocation will not carry
     * traffic to that peer.
     *
     * Non-fatal for the same reason the rest of this type is: a permission is per-peer and a session
     * normally has several pairs, so one refusal leaves the others working. Where it is *not* survivable —
     * a relay-only session, or a peer behind a symmetric NAT where the relay is the only path — the
     * existing ICE terminals still fire on their own schedule; this is what makes them explicable rather
     * than what reports them.
     *
     * **The silent case it exists to end.** A refused permission and a peer that never answered present
     * identically: checks go out, nothing comes back, and the session ends at
     * `IceFailureReason.NoCandidatePairs` — a symptom that points at the network while the server had
     * already said, in as many words, that it would not relay this. That cost a dual-stack `relay-only`
     * lane a full investigation whose only evidence was a packet capture, twice.
     *
     * The refusal that matters most is **443 Peer Address Family Mismatch** (RFC 6156 §9.1) and it is
     * reachable without any client fault: a server that reports an allocation at an address of the wrong
     * family hands out a relay candidate whose own permissions it then refuses. **403 Forbidden** is the
     * other — a policy or quota decision, and permanent for that peer.
     */
    public data class RelayPermissionRefused(
        /** Which allocation refused — its relayed address; a dual-stack session holds more than one. */
        public val relay: TransportAddress,
        /** The peer the permission was for. */
        public val peer: TransportAddress,
        /**
         * What the server answered. Unlike the `Throwable` payloads here this **is** a discriminant — it
         * is a protocol code, not a foreign type — so branch on [StunErrorCode.code]; the reason text is
         * the server's own and is diagnostic only.
         */
        public val error: StunErrorCode,
    ) : SessionDiagnostic
}

package com.ditchoom.webrtc.ice

import com.ditchoom.webrtc.stun.StunErrorCode
import com.ditchoom.webrtc.stun.TransportAddress

/**
 * A TURN server **answered** a CreatePermission (RFC 8656 §9) and refused it — the payload of
 * [TurnAllocation.permissionRefused].
 *
 * Distinct from silence, and the distinction is the whole point: an unanswered CreatePermission is a lost
 * datagram that [TurnAllocation]'s retransmit loop is built to absorb, whereas a refusal is the server
 * stating that this permission will never exist. Without one of these the two present identically — as a
 * relay path that carries nothing — and the session ends at [IceFailureReason.NoCandidatePairs], which
 * names the symptom while pointing away from the cause.
 *
 * **Why it is a diagnostic and not a failure state.** A permission is per-peer, and a session normally has
 * several candidate pairs: one refused peer leaves the others untouched, so the session is not in a
 * distinct state and nothing is being lied to. Where every pair rides refused permissions the existing ICE
 * terminals still fire on their own schedule — this only makes them explicable.
 *
 * The two refusals worth recognising, both of which cost a whole relay lane here before this existed:
 *
 * - **443 Peer Address Family Mismatch** (RFC 6156 §9.1) — the peer's family differs from the relayed
 *   address's. A correct client can still meet this: a server that reports an allocation at an address of
 *   the *wrong family* (a misconfigured `external-ip` will do it) hands out a relay candidate whose family
 *   its own permissions then refuse. That is exactly how a dual-stack `relay-only` lane failed with two
 *   unreachable candidates and no other evidence.
 * - **403 Forbidden** — the server's policy refuses that peer outright (a quota, a denied range).
 *
 * [error] is a protocol code, so it *is* a discriminant — unlike the `Throwable` payloads elsewhere in the
 * diagnostics, which cross an API boundary and are only ever read to diagnose. Branch on
 * [StunErrorCode.code]; [StunErrorCode.reason] is the server's own text and is diagnostic only.
 */
public data class TurnPermissionRefusal(
    /**
     * The allocation whose permission was refused — its relayed transport address, i.e. the base of the
     * relay candidate this affects.
     *
     * Carried because a dual-stack session holds **more than one** allocation, and which one refused is
     * precisely what identifies the fault: a v6 allocation refusing a v4 peer says something a v4
     * allocation refusing the same peer does not.
     */
    public val relay: TransportAddress,
    /** The peer the permission was for — the remote candidate's transport address. */
    public val peer: TransportAddress,
    /** What the server answered. A discriminant, not merely a payload; see the type KDoc. */
    public val error: StunErrorCode,
)

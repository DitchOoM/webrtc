package com.ditchoom.webrtc.testsuite.harness

/**
 * The resolved description of a [withWebRtcHarness] scenario topology — the deterministic-vnet analogue
 * of socket's container `/describe` manifest. Where socket's manifest is fetched over HTTP from a
 * running docker control plane, this one is **computed** from the typed scenario config (there is no
 * network to reach: the whole topology is in-memory and replays under `runTest`). It names the two
 * peers' host endpoints, the virtual STUN/TURN servers, and the impairment/policy in force, so a
 * scenario can assert *what it asked for* was actually provisioned.
 *
 * A consumer never constructs one; it is handed the resolved manifest by
 * [WebRtcHarnessScope.establish] / [WebRtcHarnessConnection.manifest].
 */
public data class HarnessManifest(
    /** The NAT behavior both peers sit behind. */
    public val natType: NatType,
    /** Whether ICE was constrained to TURN-relay candidates only (no host/srflx offered). */
    public val relayOnly: Boolean,
    /** The link impairment in force, or `null` for a clean link. */
    public val impairment: NetworkImpairment?,
    /** The ICE-controlling peer's host socket (the offerer). */
    public val offerer: HarnessEndpoint,
    /** The ICE-controlled peer's host socket (the answerer). */
    public val answerer: HarnessEndpoint,
    /** The virtual STUN (RFC 8489 Binding) server. */
    public val stun: HarnessEndpoint,
    /** The virtual TURN (RFC 8656) relay. */
    public val turn: HarnessEndpoint,
)

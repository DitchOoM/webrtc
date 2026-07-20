package com.ditchoom.webrtc.testsuite.harness

import com.ditchoom.webrtc.testsuite.vnet.NatProfile

/**
 * The RFC 4787 NAT behavior a [withWebRtcHarness] scenario places **both** peers behind — a sealed,
 * exhaustive taxonomy so a `when` over it needs no `else` and adding a variant is a compile error at
 * every call site. These are the same four canonical profiles the `webrtc-ice` vnet and the L2
 * `test-harness/nat/` profiles model (RFC 3489 cone/symmetric expressed in RFC 4787's two-axis mapping
 * × filtering vocabulary), plus [None] for a flat, direct (no-NAT) link.
 *
 * The determinant of ICE outcome: a **cone** NAT reuses one external port across destinations, so a
 * server-reflexive (srflx) candidate learned via STUN is usable by a peer; a **symmetric** NAT
 * allocates a fresh port per destination, so srflx is useless to the peer and only a TURN **relay**
 * connects — which is why [Symmetric]↔[Symmetric] needs [WebRtcHarnessScope.relayOnly]-grade paths.
 */
public sealed interface NatType {
    /** No NAT: hosts sit directly on the routable segment and connect on their host candidates. */
    public data object None : NatType

    /** Endpoint-independent mapping + filtering — the most permissive NAT (RFC 3489 "full cone"). */
    public data object FullCone : NatType

    /** EIM + address-dependent filtering (RFC 3489 "address-restricted cone"). */
    public data object AddressRestrictedCone : NatType

    /** EIM + address-and-port-dependent filtering (RFC 3489 "port-restricted cone"). */
    public data object PortRestrictedCone : NatType

    /** Per-destination mapping + strict filtering (RFC 3489 "symmetric") — defeats srflx, forces relay. */
    public data object Symmetric : NatType
}

/** The internal vnet [NatProfile] for this [NatType], or `null` for [NatType.None] (flat network). */
internal fun NatType.toProfileOrNull(): NatProfile? =
    when (this) {
        NatType.None -> null
        NatType.FullCone -> NatProfile.FullCone
        NatType.AddressRestrictedCone -> NatProfile.AddressRestrictedCone
        NatType.PortRestrictedCone -> NatProfile.PortRestrictedCone
        NatType.Symmetric -> NatProfile.Symmetric
    }

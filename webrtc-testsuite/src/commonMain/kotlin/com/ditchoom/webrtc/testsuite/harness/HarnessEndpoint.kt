package com.ditchoom.webrtc.testsuite.harness

/**
 * A resolved virtual transport address in a [withWebRtcHarness] topology — the datagram analogue of
 * socket's `HarnessEndpoint` (which is a container `host:port`). Here it is a vnet literal address:
 * one of the two peers' host sockets, or the virtual STUN / TURN server. Values come from the
 * [HarnessManifest] the harness resolves, never from build-time constants, so a consumer's scenario
 * code stays free of the vnet's fixed addressing plan.
 */
public data class HarnessEndpoint(
    public val ip: String,
    public val port: Int,
) {
    override fun toString(): String = "$ip:$port"
}

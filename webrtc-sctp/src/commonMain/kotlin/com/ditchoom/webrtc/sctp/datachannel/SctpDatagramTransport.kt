package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.ReadBuffer

/**
 * The point-to-point datagram seam beneath the SCTP association — **the boundary where DTLS slots in**
 * (W4). It is deliberately `DatagramChannel`-shaped but connected (one peer, no `to` address): in
 * production it is a DTLS record layer over the selected ICE pair; in tests it is a plaintext
 * pass-through over the vnet / an in-memory pipe. Because the association above is sans-io and this
 * boundary is one small interface, real DTLS drops in as a swap, not a rewrite (HANDOFF W5 decision).
 *
 * Implementations are single-consumer for [receive] and single-producer for [send] (the driver
 * confines each to its own coroutine), mirroring buffer-flow's `Connection` contract.
 */
public interface SctpDatagramTransport {
    /** Send one encoded SCTP packet to the peer. Ownership of [packet] is not transferred. */
    public suspend fun send(packet: ReadBuffer)

    /** Receive the next SCTP packet from the peer, or null when the transport has closed. */
    public suspend fun receive(): ReadBuffer?

    /** Tear the transport down; a pending/next [receive] returns null. Idempotent. */
    public fun close()
}

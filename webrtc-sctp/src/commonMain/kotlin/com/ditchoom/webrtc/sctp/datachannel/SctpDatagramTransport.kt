package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.freeIfNeeded

/**
 * The point-to-point datagram seam beneath the SCTP association — **the boundary where DTLS slots in**
 * It is deliberately `AddressedDatagramChannel`-shaped but connected (one peer, no `to` address): in
 * production it is a DTLS record layer over the selected ICE pair; in tests it is a plaintext
 * pass-through over the vnet / an in-memory pipe. Because the association above is sans-io and this
 * boundary is one small interface, real DTLS drops in as a swap, not a rewrite.
 *
 * Implementations are single-consumer for [receive] and single-producer for [send] (the driver
 * confines each to its own coroutine), mirroring buffer-flow's `Connection` contract.
 */
public interface SctpDatagramTransport {
    /** Send one encoded SCTP packet to the peer. Ownership of [packet] is not transferred. */
    public suspend fun send(packet: ReadBuffer)

    /**
     * Receive the next SCTP packet from the peer, or null when the transport has closed.
     *
     * **Ownership of the returned buffer transfers to the caller**, which releases it once it has
     * finished reading — see [releaseReceived]. This mirrors `IceDataReadResult.Received` one layer down,
     * and it is a real obligation on both sides rather than a formality: in production the buffer under a
     * plaintext seam *is* the socket's receive buffer, which on Kotlin/Native Linux is a raw `malloc`
     * nobody else will ever free.
     *
     * The corollary binds implementors. A transport must hand over a buffer it no longer shares — never a
     * `slice()` of one it keeps, because a slice takes a reference on the same chunk and the caller's
     * release would pull it out from under whatever still holds the original.
     */
    public suspend fun receive(): ReadBuffer?

    /** Tear the transport down; a pending/next [receive] returns null. Idempotent. */
    public fun close()
}

/**
 * Release a packet received from an [SctpDatagramTransport] whose last reader has finished with it.
 *
 * ## The rule, and why the association can satisfy it
 *
 * A received packet has exactly one owner at a time; [SctpDataChannelStack]'s drive loop is that owner
 * from the moment [SctpDatagramTransport.receive] hands it over. It may release after
 * `association.handle` returns because **nothing the association keeps is a view of the packet**: every
 * chunk it decodes is a zero-copy slice, but the two things that must outlive the call are copied out
 * explicitly — inbound user data in `ReassemblyQueue` ("its payload copied out of the borrowed datagram")
 * and the state cookie an INIT-ACK carries, echoed back through `copyOf`. Everything else — a HEARTBEAT's
 * info, a SACK's gap blocks, a RE-CONFIG's parameters — is consumed inside `handle`.
 *
 * That is what keeps this a leak fix rather than a use-after-free: the message a data channel finally
 * delivers to the application is reassembly's *copy*, allocated from `SctpConfig.bufferFactory`, and is
 * untouched by this.
 *
 * ## Why it is not [ReadBuffer.slice]-safe to do earlier
 *
 * Released after `handle`, deliberately, not before: outbound packets are built during the call and a
 * chunk being encoded may still be reading the inbound view it was echoed from.
 */
internal fun ReadBuffer.releaseReceived() {
    freeIfNeeded()
}

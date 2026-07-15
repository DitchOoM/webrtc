@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Datagram
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.Ecn
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import kotlinx.coroutines.channels.Channel

/**
 * The **WebRTC virtual network** (RFC_KMP_WEBRTC.md §5.2) — an in-memory implementation of the
 * buffer-flow [DatagramChannel] seam, the datagram analogue of a UDP socket with **no OS sockets**.
 * ICE / DTLS / SCTP run end-to-end over this under `runTest` virtual time on every platform, exactly
 * as production runs them over `socket-udp`'s real `DatagramChannel` actuals — the cores never know
 * the difference (they are caller-clocked and sans-io, RFC §5.1).
 *
 * This is deliberately **ours**, not consumed from socket: socket's deterministic simulation (#225) is
 * QUIC-specific, unpublished test code that drives the internal quiche `UdpChannel`, not the public
 * `DatagramChannel`; and it models no NAT. RFC §5.2 calls the vnet "the WebRTC-specific addition" — so
 * NAT profiles, a virtual TURN server, and the impairment pipe are layered on this router in later
 * commits. This first cut is the **flat router** that clears the seam gate (a two-peer datagram echo
 * under virtual time); the [Router] seam is where NAT/impairment slot in without touching the channels.
 *
 * Datagram semantics are honored faithfully (mirroring buffer-flow's own `MemoryDatagramNetwork`
 * conformance double): message boundaries preserved (one [DatagramChannel.send] → exactly one delivered
 * [Datagram]), per-packet source ([Datagram.peer] is the sender's local address), copy-on-send (the
 * payload is copied into a receiver-owned buffer so the caller may pool its own), and unreliable
 * (a datagram to an unbound address is silently dropped, like a packet into the void).
 */
internal class Vnet(
    /** Buffer allocator for received copies — inject a [CountingBufferFactory] to assert accounting. */
    private val bufferFactory: BufferFactory = BufferFactory.Default,
    /** The forwarding policy. [DirectRouter] is flat (no NAT); NAT/impairment subtype this later. */
    private val router: Router = DirectRouter,
    private val capabilities: DatagramCapabilities = FullVnetCapabilities,
) {
    private val endpoints = HashMap<SocketAddress, Channel<Datagram>>()

    /** Bind an **unconnected** endpoint at [local]; datagrams addressed to [local] arrive here. */
    fun bind(local: SocketAddress): DatagramChannel {
        require(local !in endpoints) { "address already bound: $local" }
        val inbound = Channel<Datagram>(Channel.UNLIMITED)
        endpoints[local] = inbound
        return VnetChannel(local, inbound, this, bufferFactory, capabilities)
    }

    /**
     * Deliver [datagram] toward [to] as decided by [router]. Called by [VnetChannel.send]; the router
     * may drop, rewrite the destination (NAT), or (later) delay/duplicate. Unbound destination → drop.
     */
    internal fun route(
        from: SocketAddress,
        to: SocketAddress,
        datagram: Datagram,
    ) {
        val dest = router.route(from, to) ?: return
        endpoints[dest]?.trySend(datagram)
    }
}

/**
 * The forwarding policy of a [Vnet]. Pure and synchronous for now (drop or rewrite the destination);
 * the NAT profiles and the seeded impairment pipe (loss/reorder/dup/delay on virtual time) implement
 * this in later commits. Returning `null` drops the datagram.
 */
internal fun interface Router {
    fun route(
        from: SocketAddress,
        to: SocketAddress,
    ): SocketAddress?
}

/** The flat, lossless router: every datagram reaches its stated destination. */
internal val DirectRouter = Router { _, to -> to }

private class VnetChannel(
    override val localAddress: SocketAddress,
    private val inbound: Channel<Datagram>,
    private val vnet: Vnet,
    private val bufferFactory: BufferFactory,
    override val capabilities: DatagramCapabilities,
) : DatagramChannel {
    private var closed = false

    override val isOpen: Boolean get() = !closed

    /** The classic UDP payload ceiling (65535 − 8 UDP − 20 IP), matching buffer-flow's memory double. */
    override val maxWritableSize: Int = MAX_UDP_PAYLOAD

    override suspend fun receive(): DatagramReadResult {
        val datagram = inbound.receiveCatching().getOrNull()
        return if (datagram != null) DatagramReadResult.Received(datagram) else DatagramReadResult.Closed()
    }

    override suspend fun send(
        payload: ReadBuffer,
        to: SocketAddress?,
        options: DatagramSendOptions,
    ) {
        check(!closed) { "channel is closed" }
        val dest = requireNotNull(to) { "the vnet binds unconnected endpoints; `to` is required" }

        // Copy the payload into a receiver-owned buffer (a real socket copies into the kernel), so the
        // caller keeps ownership of — and may pool — its own buffer. Read from a slice to leave the
        // caller's position untouched, matching the DatagramSink contract ("ownership is not transferred").
        val slice = payload.slice()
        val len = slice.remaining()
        val copy: PlatformBuffer = bufferFactory.allocate(maxOf(1, len))
        copy.write(slice)
        copy.resetForRead()
        copy.setLimit(len)

        vnet.route(
            from = localAddress,
            to = dest,
            datagram = Datagram(payload = copy, peer = localAddress, ecn = Ecn.Unknown),
        )
    }

    override fun close() {
        closed = true
        inbound.close()
    }
}

/** Payload ceiling of the virtual link. */
private const val MAX_UDP_PAYLOAD = 65507

/** A full-capability virtual endpoint — every control-plane field round-trips through memory. */
internal val FullVnetCapabilities =
    DatagramCapabilities(
        ecnSend = true,
        ecnReceive = true,
        dscpSend = true,
        dontFragment = true,
        hopLimitSend = true,
        hopLimitReceive = true,
        localAddressReceive = true,
        sourceAddressSelect = true,
        multicast = false,
    )

/** Build a literal IPv4/IPv6 [SocketAddress] for a virtual host — the ICE literal-candidate fast path. */
internal fun vnetAddress(
    ip: String,
    port: Int,
): SocketAddress = SocketAddress.ofLiteral(ip, port)

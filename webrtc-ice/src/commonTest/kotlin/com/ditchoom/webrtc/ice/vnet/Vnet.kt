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
 * `DatagramChannel`, and models no NAT. RFC §5.2 calls the vnet "the WebRTC-specific addition" — so
 * NAT profiles ([Nat]), a virtual TURN server ([TurnServer]), and the impairment pipe ([Impairment])
 * are layered on the [Fabric] seam. The flat [DirectFabric] keeps the seam gate honest.
 *
 * Datagram semantics are honored faithfully (mirroring buffer-flow's own `MemoryDatagramNetwork`):
 * message boundaries preserved (one [DatagramChannel.send] → the [Fabric] decides zero-or-more
 * delivered [Datagram]s), per-packet source ([Datagram.peer] is the source **as the receiver observes
 * it** — the sender's private address on a LAN, or its NAT-mapped external address across a NAT), a
 * copy per delivery so senders may pool their own buffers, and unreliable (an unroutable datagram is
 * silently dropped, like a packet into the void).
 */
internal class Vnet(
    /** Buffer allocator for received copies — inject a [CountingBufferFactory] to assert accounting. */
    private val bufferFactory: BufferFactory = BufferFactory.Default,
    /** The forwarding policy. [DirectFabric] is flat (no NAT); [Nat]/[Impairment] wrap it. */
    private val fabric: Fabric = DirectFabric,
    private val capabilities: DatagramCapabilities = FullVnetCapabilities,
) {
    private val endpoints = HashMap<SocketAddress, Channel<Datagram>>()

    /** The addresses currently bound in the vnet — the fabric consults this to decide reachability. */
    val boundAddresses: Set<SocketAddress> get() = endpoints.keys.toSet()

    /** Bind an **unconnected** endpoint at [local]; datagrams delivered toward [local] arrive here. */
    fun bind(local: SocketAddress): DatagramChannel {
        require(local !in endpoints) { "address already bound: $local" }
        val inbound = Channel<Datagram>(Channel.UNLIMITED)
        endpoints[local] = inbound
        return VnetChannel(local, inbound, this, capabilities)
    }

    /**
     * Tear down the endpoint at [local] (a link/interface going away). A subsequent delivery toward
     * [local] finds no endpoint and is dropped — the mechanism behind the candidate-flap fixture.
     */
    fun unbind(local: SocketAddress) {
        endpoints.remove(local)?.close()
    }

    /** True iff an endpoint is currently bound at [local]. */
    fun isBound(local: SocketAddress): Boolean = local in endpoints

    /**
     * Hand a datagram sent [from]→[to] to the [fabric]; [payload] is valid only for the duration of
     * this call, so a fabric that defers delivery must snapshot it (see [Impairment]).
     */
    internal fun route(
        from: SocketAddress,
        to: SocketAddress,
        payload: ReadBuffer,
    ) {
        fabric.forward(from, to, payload, this)
    }

    /**
     * Deliver exactly one copy of [payload] to the endpoint at [dest], the receiver observing the
     * source as [observedSource]. Returns true iff the datagram was actually queued — false if nothing
     * is bound at [dest] OR the bound channel is closed (a datagram into the void). No buffer is
     * allocated on the drop path, so a `TrackingBufferFactory` sees exactly one allocation per *delivered*
     * datagram — the copy-on-send invariant, and no spurious leak when a peer's socket has gone away.
     */
    internal fun deliver(
        dest: SocketAddress,
        observedSource: SocketAddress,
        payload: ReadBuffer,
    ): Boolean {
        val inbound = endpoints[dest] ?: return false
        if (inbound.isClosedForSend) return false
        val copy = copyOf(payload)
        return inbound.trySend(Datagram(payload = copy, peer = observedSource, ecn = Ecn.Unknown)).isSuccess
    }

    // Copy [payload] into a receiver-owned buffer (a real socket copies into the kernel), reading from a
    // slice so the caller's position is untouched (the DatagramSink "ownership is not transferred" rule).
    private fun copyOf(payload: ReadBuffer): PlatformBuffer {
        val slice = payload.slice()
        val len = slice.remaining()
        val copy = bufferFactory.allocate(maxOf(1, len))
        copy.write(slice)
        copy.resetForRead()
        copy.setLimit(len)
        return copy
    }
}

/**
 * The forwarding policy of a [Vnet] — the datagram analogue of "the internet between two sockets".
 * An implementation delivers a datagram zero times (drop / unreachable), once (the common case, with
 * an optionally rewritten observed source for NAT), or several times (duplication), and may defer
 * delivery onto virtual time (impairment delay) by snapshotting the payload and scheduling. Kept
 * deliberately small so [Nat] and [Impairment] compose by wrapping it.
 */
internal fun interface Fabric {
    /**
     * Forward one datagram sent [from]→[to] carrying [payload] (valid only for this call). Deliver it
     * through [net] — [Vnet.deliver] performs the copy and honors message boundaries.
     */
    fun forward(
        from: SocketAddress,
        to: SocketAddress,
        payload: ReadBuffer,
        net: Vnet,
    )
}

/** The flat, lossless internetwork: every datagram reaches its stated destination, source unchanged. */
internal val DirectFabric = Fabric { from, to, payload, net -> net.deliver(to, from, payload) }

private class VnetChannel(
    override val localAddress: SocketAddress,
    private val inbound: Channel<Datagram>,
    private val vnet: Vnet,
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
        vnet.route(from = localAddress, to = dest, payload = payload)
    }

    override fun close() {
        closed = true
        vnet.unbind(localAddress) // remove the endpoint too (not just close the channel), so a flap frees it
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

/** The IP literal of a [SocketAddress] (the vnet works entirely in literals — no resolution). */
internal val SocketAddress.ip: String get() = host

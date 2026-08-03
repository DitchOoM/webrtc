@file:OptIn(ExperimentalDatagramApi::class, DelicateCoroutinesApi::class)

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.Datagram
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.Ecn
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.channels.Channel

/**
 * The **WebRTC virtual network** (RFC_KMP_WEBRTC.md §5.2) — an in-memory implementation of the
 * buffer-flow [AddressedDatagramChannel] seam, the datagram analogue of a UDP socket with **no OS sockets**.
 * ICE / DTLS / SCTP run end-to-end over this under `runTest` virtual time on every platform, exactly
 * as production runs them over `socket-udp`'s real `AddressedDatagramChannel` actuals — the cores never know
 * the difference (they are caller-clocked and sans-io, RFC §5.1).
 *
 * This is deliberately **ours**, not consumed from socket: socket's deterministic simulation (#225) is
 * QUIC-specific, unpublished test code that drives the internal quiche `UdpChannel`, not the public
 * `AddressedDatagramChannel`, and models no NAT. RFC §5.2 calls the vnet "the WebRTC-specific addition" — so
 * NAT profiles ([Nat]), a virtual TURN server ([TurnServer]), and the impairment pipe ([Impairment])
 * are layered on the [Fabric] seam. The flat [DirectFabric] keeps the seam gate honest.
 *
 * Datagram semantics are honored faithfully (mirroring buffer-flow's own `MemoryDatagramNetwork`):
 * message boundaries preserved (one [AddressedDatagramChannel.send] → the [Fabric] decides zero-or-more
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
    private val groups = HashMap<SocketAddress, MutableSet<SocketAddress>>()

    /** The addresses currently bound in the vnet — the fabric consults this to decide reachability. */
    val boundAddresses: Set<SocketAddress> get() = endpoints.keys.toSet()

    // The next ephemeral port to hand out (see [bind]). A plain counter, not a Random: the vnet's whole
    // purpose is that two runs of the same fixture produce the same wire, so "the kernel picked one"
    // must still be reproducible. IANA's dynamic range starts at 49152.
    private var nextEphemeralPort = EPHEMERAL_PORT_BASE

    /**
     * Bind an **unconnected** endpoint at [local]; datagrams delivered toward [local] arrive here.
     *
     * A port of **0 means ephemeral**, exactly as it does to an OS: the vnet assigns a free port and the
     * returned channel reports it on `localAddress`. Modelled because production gathering binds that way
     * — an ICE restart re-gathers while the previous generation still holds its sockets, so there is no
     * port to pin — and a seam that quietly bound *port zero* would let a candidate advertising `:0`
     * pass every test and fail on the first real kernel.
     */
    fun bind(local: SocketAddress): AddressedDatagramChannel {
        val bound = if (local.port == 0) SocketAddress.ofLiteral(local.host, allocateEphemeralPort(local.host)) else local
        require(bound !in endpoints) { "address already bound: $bound" }
        val inbound = Channel<Datagram>(Channel.UNLIMITED)
        endpoints[bound] = inbound
        return VnetChannel(bound, inbound, this, capabilities)
    }

    private fun allocateEphemeralPort(host: String): Int {
        while (SocketAddress.ofLiteral(host, nextEphemeralPort) in endpoints) nextEphemeralPort++
        // Exhaustion is a fixture that leaked sockets, not a network condition worth modelling — say so
        // rather than wrapping past 65535 and handing back a port number that cannot exist.
        require(nextEphemeralPort <= MAX_PORT) { "vnet ephemeral port range exhausted (bound: ${endpoints.size})" }
        return nextEphemeralPort++
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
     * Join [member] to the link-local multicast [group] — the one datagram-level behaviour mDNS needs that
     * point-to-point delivery cannot express (RFC 6762 §3). A datagram sent *to* a group address is copied to
     * every joined member except the sender, which is what an L2 segment does and what makes "the querier
     * does not know the responder's address" — the entire point of a `.local` name — expressible here.
     */
    fun join(
        group: SocketAddress,
        member: SocketAddress,
    ) {
        groups.getOrPut(group) { LinkedHashSet() } += member
    }

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
        // A group address is not an endpoint: it flood-fills to its members, minus the sender (a real
        // segment does not hand a host back its own multicast unless loopback is asked for).
        groups[dest]?.let { members ->
            var delivered = false
            for (member in members) {
                if (member != observedSource) delivered = deliver(member, observedSource, payload) || delivered
            }
            return delivered
        }
        val inbound = endpoints[dest] ?: return false
        if (inbound.isClosedForSend) return false
        val copy = copyOf(payload)
        return inbound.trySend(Datagram(payload = copy, peer = observedSource, ecn = Ecn.Unknown)).isSuccess
    }

    // Copy [payload] into a receiver-owned buffer (a real socket copies into the kernel), reading from a
    // slice so the caller's position is untouched (the AddressedDatagramSink "ownership is not transferred" rule).
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
) : AddressedDatagramChannel {
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
        to: SocketAddress,
        options: DatagramSendOptions,
    ) {
        check(!closed) { "channel is closed" }
        // `to` was always required here; since buffer 6.23.0 the addressed sink type says so.
        vnet.route(from = localAddress, to = to, payload = payload)
    }

    override fun close() {
        closed = true
        vnet.unbind(localAddress) // remove the endpoint too (not just close the channel), so a flap frees it
    }
}

/** Payload ceiling of the virtual link. */
private const val MAX_UDP_PAYLOAD = 65507

// IANA's dynamic/ephemeral range (RFC 6335 §6) — where a real OS starts handing out `bind(…, 0)` ports.
private const val EPHEMERAL_PORT_BASE = 49152
private const val MAX_PORT = 65535

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

@file:OptIn(ExperimentalDatagramApi::class, DelicateCoroutinesApi::class)

package com.ditchoom.webrtc.testsuite.vnet

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
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.channels.Channel

/**
 * The **WebRTC virtual network** (RFC_KMP_WEBRTC.md §5.2) — an in-memory implementation of the
 * buffer-flow [DatagramChannel] seam, the datagram analogue of a UDP socket with **no OS sockets**.
 * ICE / DTLS / SCTP run end-to-end over this under `runTest` virtual time on every platform, exactly
 * as production runs them over `socket-udp`'s real `DatagramChannel` actuals — the cores never know
 * the difference (they are caller-clocked and sans-io, RFC §5.1). This is what the published
 * `withWebRtcHarness { }` DSL drives.
 *
 * **Provenance / de-dup finding.** This vnet (plus [Nat], [StunServer], [TurnServer], [Impairment],
 * [Vnets]) is a faithful port of `webrtc-ice`'s richer vnet, which lives in that module's **test**
 * source set (`webrtc-ice/src/commonTest/.../vnet/`) and is `internal` — so a *published* `commonMain`
 * testsuite cannot depend on it. The `webrtc` root already copies the flat path of this vnet into its
 * own tests (`webrtc/commonTest/TestNet.kt`) for the same reason. The RFC lists the vnet as a
 * `webrtc-testsuite` deliverable, so its home is here; the minimal promotion that removes the
 * duplication is to have `webrtc-ice`'s test source set depend on this published module (test-scope) —
 * a follow-up, tracked in the W7 Phase 3 handoff.
 *
 * Datagram semantics are honored faithfully (mirroring buffer-flow's own `MemoryDatagramNetwork`):
 * message boundaries preserved (one [DatagramChannel.send] → the [Fabric] decides zero-or-more
 * delivered [Datagram]s), per-packet source ([Datagram.peer] as the receiver observes it), a copy per
 * delivery so senders may pool their own buffers, and unreliable (an unroutable datagram is silently
 * dropped).
 */
internal class Vnet(
    /** Buffer allocator for received copies — inject a counting factory to assert accounting. */
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

    /** Tear down the endpoint at [local] (a link/interface going away). A later delivery is dropped. */
    fun unbind(local: SocketAddress) {
        endpoints.remove(local)?.close()
    }

    /** True iff an endpoint is currently bound at [local]. */
    fun isBound(local: SocketAddress): Boolean = local in endpoints

    internal fun route(
        from: SocketAddress,
        to: SocketAddress,
        payload: ReadBuffer,
    ) {
        fabric.forward(from, to, payload, this)
    }

    /**
     * Deliver exactly one copy of [payload] to the endpoint at [dest], the receiver observing the
     * source as [observedSource]. Returns true iff the datagram was actually queued. No buffer is
     * allocated on the drop path, so a counting factory sees exactly one allocation per *delivered*
     * datagram.
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
 * Delivers a datagram zero times (drop), once (the common case, source optionally rewritten for NAT),
 * or several times (duplication), and may defer delivery onto virtual time (impairment delay). Kept
 * deliberately small so [Nat] and [Impairment] compose by wrapping it.
 */
internal fun interface Fabric {
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
        vnet.unbind(localAddress) // remove the endpoint too, so a flap frees it
    }
}

/** Payload ceiling of the virtual link (65535 − 8 UDP − 20 IP). */
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

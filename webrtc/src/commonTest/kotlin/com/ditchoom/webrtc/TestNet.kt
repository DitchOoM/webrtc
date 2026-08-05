@file:OptIn(ExperimentalDatagramApi::class, DelicateCoroutinesApi::class)

package com.ditchoom.webrtc

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
import com.ditchoom.buffer.freeIfNeeded
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlin.random.Random

/**
 * A minimal **flat** in-memory [AddressedDatagramChannel] network for the `webrtc` module's own tests — the same
 * buffer-flow seam production binds real UDP to, with no OS sockets. It is a deliberately small copy of
 * the essential flat path of `webrtc-ice`'s richer vnet (NAT/TURN/impairment), which lives in that
 * module's test source set and is not visible here. The full-stack fixtures that need NAT topologies stay
 * in `webrtc-ice`; the session round-trip only needs two hosts on one flat link.
 *
 * The link is **lossless by default** (the existing round-trip contract) but can be made **lossy** with a
 * seeded per-datagram [loss] probability drawn from one `Random(seed)` — the same discipline as the ICE
 * vnet's [com.ditchoom.webrtc.ice.vnet.Impairment] and socket's `ImpairedPipe`: a fixed one draw per
 * routed datagram, so the loss stream is independent of any branch and the whole full-stack establishment
 * replays bit-for-bit forever (directive #2). This is what lets [PeerConnectionLossRoundTripTest] stress
 * the *combined* ICE→DTLS→SCTP→DCEP path under loss — the layer-interaction regime the single-layer loss
 * gates cannot see.
 */
internal class TestNet(
    private val bufferFactory: BufferFactory = BufferFactory.Default,
    private val loss: Double = 0.0,
    seed: Long = 0L,
) {
    init {
        require(loss in 0.0..1.0) { "loss must be a probability in [0,1], was $loss" }
    }

    // Seeded so a lossy full-stack scenario is 100% replayable; test-only entropy, the seed IS the seam.
    @Suppress("UnseamedEntropy")
    private val lossRng = Random(seed)
    private val endpoints = HashMap<SocketAddress, Channel<Datagram>>()
    private val groups = HashMap<SocketAddress, MutableSet<SocketAddress>>()

    fun bind(local: SocketAddress): AddressedDatagramChannel {
        require(local !in endpoints) { "address already bound: $local" }
        val inbound = Channel<Datagram>(Channel.UNLIMITED)
        endpoints[local] = inbound
        return FlatChannel(local, inbound, this)
    }

    /** True iff an endpoint is currently bound at [local] — how a fixture observes socket retirement. */
    fun isBound(local: SocketAddress): Boolean = local in endpoints

    /**
     * Join [member] to the link-local multicast [group] (RFC 6762 §3): a datagram sent *to* the group
     * address is copied to every joined member but its sender, which is what an L2 segment does. It is the
     * one datagram behaviour an `<uuid>.local` name depends on — the querier does not know, and must not
     * need, the responder's address.
     */
    fun join(
        group: SocketAddress,
        member: SocketAddress,
    ) {
        groups.getOrPut(group) { LinkedHashSet() } += member
    }

    /** Tear the endpoint at [local] down from *outside* the stack — an interface going away under it. */
    fun tearDown(local: SocketAddress) = unbind(local)

    private fun route(
        from: SocketAddress,
        to: SocketAddress,
        payload: ReadBuffer,
    ) {
        // A group address is not an endpoint: it flood-fills to its members, minus the sender (a real
        // segment does not hand a host back its own multicast unless loopback is asked for).
        groups[to]?.let { members ->
            for (member in members) if (member != from) route(from, member, payload)
            return
        }
        val inbound = endpoints[to] ?: return // into the void
        if (inbound.isClosedForSend) return
        // Draw one value per routed datagram regardless of outcome — a stable RNG stream (directive #2).
        if (loss > 0.0 && lossRng.nextDouble() < loss) return // dropped on the wire
        inbound.trySend(Datagram(payload = copyOf(payload), peer = from, ecn = Ecn.Unknown))
    }

    private fun unbind(local: SocketAddress) {
        endpoints.remove(local)?.close()
    }

    private fun copyOf(payload: ReadBuffer): PlatformBuffer {
        // The slice reads `payload` without disturbing the sender's cursor and is dead once copied — but
        // on a pooled buffer `slice()` is `addRef()`, so leaving it pinned the SENDER's chunk. That made
        // the harness itself look like a production leak: a tracker on `IceConfig.bufferFactory` reported
        // three unreleased slices, and all three were these. Exactly the hazard `LeakTrackingFactory`
        // warns about — harness buffers attributed to the code under test — so the harness has to be
        // clean before its numbers mean anything.
        val slice = payload.slice()
        return try {
            val len = slice.remaining()
            val copy = bufferFactory.allocate(maxOf(1, len))
            copy.write(slice)
            copy.resetForRead()
            copy.setLimit(len)
            copy
        } finally {
            slice.freeIfNeeded()
        }
    }

    private class FlatChannel(
        override val localAddress: SocketAddress,
        private val inbound: Channel<Datagram>,
        private val net: TestNet,
    ) : AddressedDatagramChannel {
        private var closed = false

        override val isOpen: Boolean get() = !closed
        override val maxWritableSize: Int = MAX_UDP_PAYLOAD
        override val capabilities: DatagramCapabilities = CAPABILITIES

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
            net.route(localAddress, to, payload)
        }

        override fun close() {
            closed = true
            net.unbind(localAddress)
        }
    }

    private companion object {
        const val MAX_UDP_PAYLOAD = 65507

        val CAPABILITIES =
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
    }
}

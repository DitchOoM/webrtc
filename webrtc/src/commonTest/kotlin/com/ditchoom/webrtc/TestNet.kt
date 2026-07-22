@file:OptIn(ExperimentalDatagramApi::class, DelicateCoroutinesApi::class)

package com.ditchoom.webrtc

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
import kotlin.random.Random

/**
 * A minimal **flat** in-memory [DatagramChannel] network for the `webrtc` module's own tests — the same
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

    fun bind(local: SocketAddress): DatagramChannel {
        require(local !in endpoints) { "address already bound: $local" }
        val inbound = Channel<Datagram>(Channel.UNLIMITED)
        endpoints[local] = inbound
        return FlatChannel(local, inbound, this)
    }

    private fun route(
        from: SocketAddress,
        to: SocketAddress,
        payload: ReadBuffer,
    ) {
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
        val slice = payload.slice()
        val len = slice.remaining()
        val copy = bufferFactory.allocate(maxOf(1, len))
        copy.write(slice)
        copy.resetForRead()
        copy.setLimit(len)
        return copy
    }

    private class FlatChannel(
        override val localAddress: SocketAddress,
        private val inbound: Channel<Datagram>,
        private val net: TestNet,
    ) : DatagramChannel {
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
            to: SocketAddress?,
            options: DatagramSendOptions,
        ) {
            check(!closed) { "channel is closed" }
            net.route(localAddress, requireNotNull(to) { "unconnected endpoint; `to` is required" }, payload)
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

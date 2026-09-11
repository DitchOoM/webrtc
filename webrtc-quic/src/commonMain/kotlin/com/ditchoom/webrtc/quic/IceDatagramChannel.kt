@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.quic

import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.Datagram
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.Ecn
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.HopLimit
import com.ditchoom.buffer.flow.LocalAddress
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.webrtc.ice.IceDataReadResult
import com.ditchoom.webrtc.ice.IceDataTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch

/**
 * The nominated pair's application-data seam as a buffer-flow [AddressedDatagramChannel] — the type
 * socket's shared-port bindings (`QuicClientBinding.Shared`, `QuicPortBinding.Shared`) read and write,
 * so a QUIC stack rides the RFC 7983 non-STUN half of the very socket ICE checked and nominated.
 *
 * Point-to-point by construction, because [IceDataTransport] is: ICE already routes every send to the
 * pair's remote and everything received here came from it, so the channel stamps [remote] on what
 * arrives and refuses a send addressed anywhere else rather than silently redirecting it.
 *
 * [local] and [remote] are the pair's two ends **as the platform's socket layer spells them**, which is
 * why the caller resolves them: a QUIC engine compares the peer it dialled against `Datagram.peer` and
 * encodes both ends into a `sockaddr`, and neither survives a foreign `SocketAddress` implementation.
 *
 * A branch, not the seam. A pump on [scope] moves packets from the seam into this channel's own inbox,
 * so that [AddressedDatagramChannel.close] can do what a shared-port QUIC listener's teardown relies on
 * — wake a parked `receive()` with `Closed` — and can do it for this branch alone: the seam stays
 * ICE's, a packet the pump took but nobody read is freed, and a later connection can ride the seam.
 */
public fun IceDataTransport.asDatagramChannel(
    scope: CoroutineScope,
    local: SocketAddress,
    remote: SocketAddress,
): AddressedDatagramChannel = IceDatagramChannel(this, scope, local, remote)

internal class IceDatagramChannel(
    private val transport: IceDataTransport,
    scope: CoroutineScope,
    override val localAddress: SocketAddress,
    private val remote: SocketAddress,
) : AddressedDatagramChannel {
    // Taken from ICE but not yet read by the QUIC side; owed back to the pool if the branch closes first.
    private val inbox = Channel<PlatformBuffer>(Channel.UNLIMITED) { it.freeIfNeeded() }
    private val pump: Job = scope.launch { pump() }

    override val isOpen: Boolean get() = pump.isActive

    /** ICE's seam carries payloads only — no ECN, hop limit, source selection or local-address report. */
    override val capabilities: DatagramCapabilities = DatagramCapabilities()

    /** The UDP payload ceiling; the pair's own socket enforces whatever is lower beneath it. */
    override val maxWritableSize: Int = MAX_UDP_PAYLOAD

    private suspend fun pump() {
        while (true) {
            when (val read = transport.receive()) {
                is IceDataReadResult.Received ->
                    // An UNLIMITED inbox refuses only once closed, and then this branch is over.
                    if (inbox.trySend(read.packet).isFailure) {
                        read.packet.freeIfNeeded()
                        return
                    }
                IceDataReadResult.Closed -> {
                    inbox.close()
                    return
                }
            }
        }
    }

    override suspend fun receive(): DatagramReadResult {
        val next = inbox.receiveCatching()
        if (next.isClosed) return DatagramReadResult.Closed()
        return DatagramReadResult.Received(
            Datagram(
                payload = next.getOrThrow(),
                peer = remote,
                ecn = Ecn.Unknown,
                localAddress = LocalAddress.of(localAddress),
                hopLimit = HopLimit.Unknown,
            ),
        )
    }

    override suspend fun send(
        payload: ReadBuffer,
        to: SocketAddress,
        options: DatagramSendOptions,
    ) {
        check(isOpen) { "the ICE datagram channel is closed" }
        require(to == remote) { "the nominated pair reaches $remote only; refusing a datagram addressed to $to" }
        transport.send(payload)
    }

    override fun close() {
        pump.cancel()
        inbox.cancel()
    }
}

private const val MAX_UDP_PAYLOAD = 65_507

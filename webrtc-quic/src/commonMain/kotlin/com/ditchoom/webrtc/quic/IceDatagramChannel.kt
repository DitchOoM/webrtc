@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.quic

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
import com.ditchoom.webrtc.ice.IceDataReadResult
import com.ditchoom.webrtc.ice.IceDataTransport
import kotlin.concurrent.Volatile

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
 * Closing this channel ends only this branch. The seam stays ICE's, so a later connection can ride it.
 */
public fun IceDataTransport.asDatagramChannel(
    local: SocketAddress,
    remote: SocketAddress,
): AddressedDatagramChannel = IceDatagramChannel(this, local, remote)

internal class IceDatagramChannel(
    private val transport: IceDataTransport,
    override val localAddress: SocketAddress,
    private val remote: SocketAddress,
) : AddressedDatagramChannel {
    @Volatile
    private var open = true

    override val isOpen: Boolean get() = open

    /** ICE's seam carries payloads only — no ECN, hop limit, source selection or local-address report. */
    override val capabilities: DatagramCapabilities = DatagramCapabilities()

    /** The UDP payload ceiling; the pair's own socket enforces whatever is lower beneath it. */
    override val maxWritableSize: Int = MAX_UDP_PAYLOAD

    override suspend fun receive(): DatagramReadResult {
        if (!open) return DatagramReadResult.Closed()
        return when (val read = transport.receive()) {
            is IceDataReadResult.Received ->
                DatagramReadResult.Received(
                    Datagram(
                        payload = read.packet,
                        peer = remote,
                        ecn = Ecn.Unknown,
                        localAddress = LocalAddress.of(localAddress),
                        hopLimit = HopLimit.Unknown,
                    ),
                )
            IceDataReadResult.Closed -> DatagramReadResult.Closed()
        }
    }

    override suspend fun send(
        payload: ReadBuffer,
        to: SocketAddress,
        options: DatagramSendOptions,
    ) {
        check(open) { "the ICE datagram channel is closed" }
        require(to == remote) { "the nominated pair reaches $remote only; refusing a datagram addressed to $to" }
        transport.send(payload)
    }

    override fun close() {
        open = false
    }
}

private const val MAX_UDP_PAYLOAD = 65_507

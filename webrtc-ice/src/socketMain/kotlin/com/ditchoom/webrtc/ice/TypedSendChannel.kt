@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.socket.udp.DatagramSendError
import com.ditchoom.socket.udp.DatagramSendException

/**
 * **The one place socket-udp's send vocabulary is translated into ours.**
 *
 * socket-udp reports a refused send as a `DatagramSendException` carrying a sealed `DatagramSendError`
 * (DitchOoM/socket#278). That type lives in `com.ditchoom.socket.udp`, and the sans-io half of this
 * module must not depend on socket at all (ARCHITECTURE §11.6) — so it cannot be read where the
 * decisions are made. This wrapper closes that gap in the only correct direction: classify **here**,
 * where socket-udp is already a dependency, and let the result cross the boundary as an
 * [IceTransmitException] carrying an [IceTransmitFailureReason] that `commonMain` owns.
 *
 * A decorator rather than a change to the drivers, for two reasons. The classification is a property of
 * *the socket implementation*, not of ICE, so it belongs beside the socket. And a consumer who supplies
 * their own [DatagramBinder] — the demuxed socket shared with QUIC-P2P that §11.6 exists to protect —
 * simply does not get the translation, and everything above degrades to
 * [IceTransmitFailureReason.Unknown], which is exactly how this module behaved before any of it existed.
 *
 * Only `send` is wrapped. `receive` is left alone deliberately: [receiveOrClosed] already flattens a
 * throwing read into `Closed`, and there is no second classification to make there.
 */
internal class TypedSendChannel(
    private val delegate: AddressedDatagramChannel,
) : AddressedDatagramChannel by delegate {
    override suspend fun send(
        payload: ReadBuffer,
        to: SocketAddress,
        options: DatagramSendOptions,
    ) {
        try {
            delegate.send(payload, to, options)
        } catch (e: DatagramSendException) {
            throw IceTransmitException(e.error.toIceReason(), e)
        }
    }

    // `by delegate` cannot satisfy these three: they are `val`s with getters on the delegate whose
    // values change over its lifetime (a bound socket learns its port; a closed one flips isOpen), and
    // Kotlin's delegation captures the reference, not the reads. Declared explicitly so each stays live.
    override val localAddress: SocketAddress get() = delegate.localAddress
    override val isOpen: Boolean get() = delegate.isOpen
    override val maxWritableSize: Int get() = delegate.maxWritableSize
    override val capabilities: DatagramCapabilities get() = delegate.capabilities

    override suspend fun receive(): DatagramReadResult = delegate.receive()

    override fun close() = delegate.close()
}

/**
 * socket's reason → ours. Exhaustive with no `else`, so a case added upstream is a compile error here
 * rather than a silent reclassification into [IceTransmitFailureReason.Unknown].
 *
 * The mapping collapses where ICE's response is the same. `Unreachable` and `NotPermitted` are distinct
 * errnos describing distinct kernel decisions, but both mean "this local base will not reach that
 * destination", and ICE has exactly one answer to that — so they are one case. `OsError`,
 * `PlatformError` and `Transport` are the unclassified tail and stay retryable; treating an
 * unrecognized errno as permanent would let one of them cost a candidate.
 */
private fun DatagramSendError.toIceReason(): IceTransmitFailureReason =
    when (this) {
        is DatagramSendError.TooLarge -> IceTransmitFailureReason.PayloadTooLarge(attempted, limit)
        is DatagramSendError.Unreachable -> IceTransmitFailureReason.DestinationUnreachable
        is DatagramSendError.NotPermitted -> IceTransmitFailureReason.DestinationUnreachable
        DatagramSendError.WouldBlock -> IceTransmitFailureReason.Transient
        is DatagramSendError.OsError -> IceTransmitFailureReason.Unknown
        is DatagramSendError.PlatformError -> IceTransmitFailureReason.Unknown
        is DatagramSendError.Transport -> IceTransmitFailureReason.Unknown
    }

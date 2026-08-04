@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramSink
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.stun.TransportAddress
import kotlinx.coroutines.CancellationException

/**
 * What one datagram transmission did — the send-side twin of [DatagramReadResult][com.ditchoom.buffer.flow.DatagramReadResult].
 *
 * A sealed answer rather than "it returned, so it went": on four of socket-udp's five backends `send`
 * historically discarded its result and returned normally having sent nothing (DitchOoM/socket#278), and
 * after that fix it *raises* instead. Neither shape is one a caller can act on without a type, and every
 * caller in this module has a different correct reaction — see [sendOrFailure].
 */
internal sealed interface IceTransmitResult {
    /** The datagram was handed to the socket. */
    data object Sent : IceTransmitResult

    /**
     * The socket refused it.
     *
     * [cause] is a **diagnostic payload, never a discriminant** — the same rule
     * `SessionDiagnostic.NetworkWatcherStopped.cause` follows, and for the same reason: it crosses an API
     * boundary from socket, so its type is socket's to define and ours to pass through intact. Once
     * DitchOoM/socket#278 releases, this is where a sealed `DatagramSendError` gets read — `TooLarge` is
     * permanent for that payload and could mark a pair unusable, while a transport failure is worth
     * another attempt. Until then, every caller here treats a failure as transient, which is the safe
     * direction: retrying a permanent failure costs a retransmit interval, whereas treating a transient
     * one as fatal costs the session.
     */
    data class Failed(
        val cause: Throwable,
    ) : IceTransmitResult
}

/**
 * One datagram the socket refused — the payload of [IceAgentDriver.transmitFailed].
 *
 * See that flow for why this is a diagnostic and not a failure state. [cause] is a **diagnostic payload,
 * never a discriminant** ([IceTransmitResult.Failed] carries the full reasoning); branch on the presence
 * of the observation, read the cause to diagnose.
 */
public data class IceTransmitFailure(
    /** Where the datagram was headed — the remote candidate's transport address. */
    public val to: TransportAddress,
    /** What the socket raised. Diagnostic payload only; see the type KDoc. */
    public val cause: Throwable,
)

/**
 * Send one datagram, **answering** whether it went instead of raising.
 *
 * The exact mirror of [receiveOrClosed], and it exists for the same reason that one does: an escaped
 * throw from a socket call in this module does far more damage than the packet it lost.
 *
 * - `IceAgentDriver.apply()` pumps a *batch* of [IceOutput]s. A throw part-way through skipped the
 *   buffer release — leaking it, against the ownership invariant #142 established — and abandoned every
 *   remaining output in the batch, including `ConnectionStateChanged` and `PathChanged`. The driver's
 *   observable state then silently disagreed with the core state machine, which is a worse failure than
 *   the lost packet that caused it.
 * - The server-reflexive and TURN retransmit loops exist *precisely* to survive transient loss — "a
 *   single lost request or response must not cost the whole srflx". A throw bypassed that tolerance
 *   completely, turning one refused `sendto` into a lost candidate.
 *
 * [CancellationException] is rethrown: structured cancellation is not a socket condition, and swallowing
 * it here would keep a retransmit loop spinning after its scope died. Anything else is reported as
 * [IceTransmitResult.Failed] for the caller to decide on.
 */
internal suspend fun AddressedDatagramSink.sendOrFailure(
    payload: ReadBuffer,
    to: SocketAddress,
): IceTransmitResult =
    try {
        send(payload, to = to)
        IceTransmitResult.Sent
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        IceTransmitResult.Failed(e)
    }

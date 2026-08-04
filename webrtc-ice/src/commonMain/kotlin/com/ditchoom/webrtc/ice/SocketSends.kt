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
     * [reason] is the discriminant — an [IceTransmitFailureReason], classified in `socketMain` from
     * socket-udp's own sealed `DatagramSendError` so the sans-io side never names a socket type
     * (ARCHITECTURE §11.6). [cause] is a **diagnostic payload, never a discriminant**, the same rule
     * `SessionDiagnostic.NetworkWatcherStopped.cause` follows.
     */
    data class Failed(
        val reason: IceTransmitFailureReason,
        val cause: Throwable,
    ) : IceTransmitResult
}

/**
 * Why a datagram could not be transmitted, **in this module's vocabulary rather than the socket's**.
 *
 * socket-udp answers with a sealed `DatagramSendError` (`TooLarge`, `Unreachable`, `NotPermitted`,
 * `WouldBlock`, `OsError`, `PlatformError`, `Transport`), and its KDoc names our use case directly:
 * *"consumers that want to branch (ICE marking a candidate pair unusable)"*. We cannot read that type
 * here — it lives in `com.ditchoom.socket.udp`, and the sans-io side of this module must not depend on
 * socket at all (ARCHITECTURE §11.6). So the classification crosses the boundary as **ours**, translated
 * at the one place socket-udp is visible: the channel `udpDatagramBinder()` hands back.
 *
 * The cases are cut by *what ICE can do differently*, not by what the OS distinguishes. Three errnos
 * that all mean "this base cannot reach that destination" are one case here, because ICE has one
 * response to them.
 *
 * A binder that does not translate — an app sharing a demuxed socket with QUIC-P2P, the vnet — yields
 * [Unknown], which behaves exactly as this module did before any of this existed. That is the safe
 * default on purpose: retrying a permanent failure costs a retransmit interval, while treating a
 * transient one as permanent costs the candidate.
 */
public sealed interface IceTransmitFailureReason {
    /**
     * The datagram was larger than this path will carry (`EMSGSIZE`), and **retransmitting it unchanged
     * cannot succeed**. The only case here that is permanent for the *payload* rather than the path, and
     * the only one that changes control flow: a retransmit loop stops immediately rather than spending
     * its whole budget re-sending bytes the socket has already measured and refused.
     */
    public data class PayloadTooLarge(
        /** Bytes we tried to send. */
        public val attempted: Int,
        /** The most this socket will accept in one datagram. */
        public val limit: Int,
    ) : IceTransmitFailureReason

    /**
     * No route from this local base to that destination, or the send was refused by local policy
     * (`EHOSTUNREACH` / `ENETUNREACH` / `EAFNOSUPPORT` / `EACCES`).
     *
     * Permanent for **this pair** rather than for the datagram — a different local base may well reach
     * it, which is exactly what ICE is for. Reported rather than acted on today: failing the pair in the
     * checklist is a sans-io core change and wants its own fixture, so it is deliberately left as a
     * follow-up rather than smuggled in here.
     */
    public data object DestinationUnreachable : IceTransmitFailureReason

    /**
     * A local, momentary refusal — the socket could not accept the datagram before the backend stopped
     * waiting. Retransmission is the correct response and is what already happens.
     *
     * Rare by construction: socket-udp absorbs and retries backpressure internally, so this reaches us
     * only when a backend gave up, which is a genuine failure to transmit rather than routine flow
     * control.
     */
    public data object Transient : IceTransmitFailureReason

    /**
     * The failure carried no classification we can act on — an unmapped OS error, a transport-level
     * throw, or a binder that does not translate socket's typed errors at all.
     *
     * Treated as retryable. That is the deliberate direction: this is the case a *new* socket error
     * lands in, and defaulting an unknown to permanent would let one unrecognized errno cost a candidate.
     */
    public data object Unknown : IceTransmitFailureReason
}

/**
 * A send failure already classified into [IceTransmitFailureReason] — thrown by the channel wrapper in
 * `socketMain`, where socket-udp's own typed error is visible, and read by [sendOrFailure] here.
 *
 * The type exists so the classification can cross the `socketMain` → `commonMain` boundary without the
 * sans-io side ever naming a socket type (ARCHITECTURE §11.6). It is an exception rather than a return
 * value because it has to travel through `AddressedDatagramSink.send`, whose signature is buffer-flow's
 * and not ours to change.
 */
public class IceTransmitException(
    /** What ICE should do about it. */
    public val reason: IceTransmitFailureReason,
    /** The underlying failure, preserved for diagnostics. */
    override val cause: Throwable,
) : RuntimeException(cause)

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
    /** What ICE made of it — the discriminant, exhaustively matchable. */
    public val reason: IceTransmitFailureReason,
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
    } catch (e: IceTransmitException) {
        // Already classified in `socketMain`, where socket-udp's sealed DatagramSendError is visible.
        IceTransmitResult.Failed(e.reason, e.cause)
    } catch (e: Exception) {
        // An untranslated binder (the vnet, a demuxed socket shared with QUIC-P2P) or a throw from
        // somewhere other than the send path. Retryable — see IceTransmitFailureReason.Unknown.
        IceTransmitResult.Failed(IceTransmitFailureReason.Unknown, e)
    }

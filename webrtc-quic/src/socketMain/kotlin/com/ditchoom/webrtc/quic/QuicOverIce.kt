@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.quic

import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.socket.TransportConfig
import com.ditchoom.socket.quic.QuicClientBinding
import com.ditchoom.socket.quic.QuicCloseException
import com.ditchoom.socket.quic.QuicCloseReason
import com.ditchoom.socket.quic.QuicError
import com.ditchoom.socket.quic.QuicOptions
import com.ditchoom.socket.quic.QuicPortBinding
import com.ditchoom.socket.quic.QuicScope
import com.ditchoom.socket.quic.QuicServer
import com.ditchoom.socket.quic.QuicTlsConfig
import com.ditchoom.socket.quic.defaultQuicEngine
import com.ditchoom.socket.quic.withQuicServer
import com.ditchoom.socket.udp.UdpSocket
import com.ditchoom.webrtc.ice.CandidatePair
import com.ditchoom.webrtc.ice.IceAgentDriver
import com.ditchoom.webrtc.ice.IceConnectionState
import com.ditchoom.webrtc.ice.IceFailureReason
import com.ditchoom.webrtc.ice.IcePath
import com.ditchoom.webrtc.stun.TransportAddress
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeout
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * This endpoint's QUIC identity, whichever role ICE hands it: [tls] is what it serves when it listens,
 * [options] what it dials and listens with — ALPN, the peer's certificate pins, idle timeout.
 */
public class QuicOverIceIdentity(
    public val tls: QuicTlsConfig,
    public val options: QuicOptions,
)

/**
 * QUIC on the pair this agent nominated — the ICE mode of `draft-seemann-quic-nat-traversal`: ICE
 * gathers, punches and nominates; QUIC handshakes over the result on the very socket ICE checked, with
 * no QUIC extension frames involved. The controlling agent dials, the controlled one listens.
 *
 * Suspends until a pair is nominated, runs [block] inside the established connection, and answers how
 * the session ended. Two things bound it, and both arrive as values of [QuicOverIceOutcome] rather than
 * as conditions to infer: an ICE restart that nominates another pair ends it ([QuicOverIceOutcome.PairMoved]
 * — the connection cannot follow, see there), and ICE failing ends it ([QuicOverIceOutcome.IceFailed]).
 * The connection's own failures keep their typed exceptions.
 *
 * [timeout] bounds establishment only — the dialler's handshake, the listener's bind and its wait for
 * the peer's handshake — never [block]: a peer-to-peer session is meant to outlive any establishment
 * budget, which is why the dialling side asks the engine directly instead of riding
 * `withQuicConnection`, whose one timeout covers its block as well.
 */
public suspend fun <R> IceAgentDriver.quicOverIce(
    identity: QuicOverIceIdentity,
    timeout: Duration = 15.seconds,
    block: suspend QuicScope.(QuicOverIcePath) -> R,
): QuicOverIceOutcome<R> =
    coroutineScope {
        val pair =
            when (val nomination = awaitNomination()) {
                is Nomination.Failed -> return@coroutineScope QuicOverIceOutcome.IceFailed(nomination.reason)
                is Nomination.Nominated -> nomination.pair
            }
        val ridden = QuicOverIcePath(pair, QuicOverIceRole.of(role))
        // Both ends spelled by socket-udp's resolver: quiche compares the peer it dialled against
        // `Datagram.peer` and encodes both ends into sockaddrs, and neither accepts a foreign
        // SocketAddress implementation. Literals in, so nothing here touches DNS.
        val remote = pair.remote.address.resolve()
        val channel = appDataTransport().asDatagramChannel(this, pair.local.base.resolve(), remote)
        val session = async { ridden.role.open(channel, remote, identity, timeout) { block(ridden) } }
        val moved = async { path.filterIsInstance<IcePath.Nominated>().first { it.pair != pair }.pair }
        val failed = async { state.filterIsInstance<IceConnectionState.Failed>().first().reason }
        try {
            select<QuicOverIceOutcome<R>> {
                session.onAwait { QuicOverIceOutcome.Completed(it) }
                moved.onAwait { QuicOverIceOutcome.PairMoved(from = pair, to = it) }
                failed.onAwait { QuicOverIceOutcome.IceFailed(it) }
            }
        } finally {
            session.cancel()
            moved.cancel()
            failed.cancel()
            // The branch is ours to end whichever way the session went: a dialler never closes the
            // shared channel it was handed (the port is not its to close), and a pump left running
            // would keep taking packets a later connection over the same seam is owed.
            channel.close()
        }
    }

/** Whether ICE handed us a pair to ride or ended first — the only two ways the wait for one resolves. */
private sealed interface Nomination {
    data class Nominated(
        val pair: CandidatePair,
    ) : Nomination

    data class Failed(
        val reason: IceFailureReason,
    ) : Nomination
}

private suspend fun IceAgentDriver.awaitNomination(): Nomination =
    coroutineScope {
        val nominated = async { Nomination.Nominated(path.filterIsInstance<IcePath.Nominated>().first().pair) }
        val failed = async { Nomination.Failed(state.filterIsInstance<IceConnectionState.Failed>().first().reason) }
        try {
            select<Nomination> {
                nominated.onAwait { it }
                failed.onAwait { it }
            }
        } finally {
            nominated.cancel()
            failed.cancel()
        }
    }

private suspend fun <R> QuicOverIceRole.open(
    channel: AddressedDatagramChannel,
    peer: SocketAddress,
    identity: QuicOverIceIdentity,
    timeout: Duration,
    block: suspend QuicScope.() -> R,
): R =
    when (this) {
        QuicOverIceRole.Client -> {
            val connection =
                defaultQuicEngine.connect(
                    QuicClientBinding.Shared(channel),
                    peer.host,
                    peer.port,
                    identity.options,
                    TransportConfig(),
                    timeout,
                )
            try {
                connection.block()
            } finally {
                connection.close()
            }
        }

        QuicOverIceRole.Server ->
            withQuicServer(QuicPortBinding.Shared(channel), identity.tls, identity.options, timeout) {
                serveOne(timeout, block)
            }
    }

/**
 * One peer, one connection: run [handler] on the first connection that completes its handshake and
 * stop listening once it returns. The wait for that handshake is bounded by [timeout] and reported the
 * way the dialling side reports its own — a typed [QuicError.HandshakeTimeout] close, never a bare
 * `TimeoutCancellationException` (a parent's deadline still propagates as the cancellation it is).
 */
private suspend fun <R> QuicServer.serveOne(
    timeout: Duration,
    handler: suspend QuicScope.() -> R,
): R =
    coroutineScope {
        val handshaken = CompletableDeferred<Unit>()
        val served = CompletableDeferred<R>()
        val accepting =
            launch {
                connections {
                    handshaken.complete(Unit)
                    try {
                        served.complete(handler())
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        served.completeExceptionally(e)
                    }
                }
            }
        try {
            try {
                withTimeout(timeout) { handshaken.await() }
            } catch (e: TimeoutCancellationException) {
                currentCoroutineContext().ensureActive()
                throw QuicCloseException(
                    QuicCloseReason.ByLocal(QuicError.HandshakeTimeout(timeout)),
                    "no peer completed a QUIC handshake over the nominated pair within $timeout",
                    cause = e,
                )
            }
            served.await()
        } finally {
            accepting.cancel()
        }
    }

private suspend fun TransportAddress.resolve(): SocketAddress = UdpSocket.resolve(ip.toString(), port.toInt())

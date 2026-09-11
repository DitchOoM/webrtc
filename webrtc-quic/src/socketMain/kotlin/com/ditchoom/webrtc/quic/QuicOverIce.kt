package com.ditchoom.webrtc.quic

import com.ditchoom.socket.quic.QuicOptions
import com.ditchoom.socket.quic.QuicScope
import com.ditchoom.socket.quic.QuicTlsConfig
import com.ditchoom.webrtc.ice.IceAgentDriver
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
 */
public suspend fun <R> IceAgentDriver.quicOverIce(
    identity: QuicOverIceIdentity,
    timeout: Duration = 15.seconds,
    block: suspend QuicScope.(QuicOverIcePath) -> R,
): QuicOverIceOutcome<R> = TODO("nothing connects QUIC to ICE yet (#190): $identity $timeout $block")

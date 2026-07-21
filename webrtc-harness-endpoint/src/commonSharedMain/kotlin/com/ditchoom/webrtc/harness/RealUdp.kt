@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.socket.udp.UdpSocket
import com.ditchoom.webrtc.ice.DatagramBinder

/**
 * The production real-UDP [DatagramBinder]: binds an unconnected socket-udp [UdpSocket] at the requested
 * local address and hands back its buffer-flow [DatagramChannel] — the exact seam the in-memory vnet
 * implements in tests. Per `webrtc-ice`'s [DatagramBinder] contract, this one lambda is the ONLY
 * substitution between a vnet run and a real-kernel run; the ICE agent, gathering drivers, DTLS and SCTP
 * above are byte-for-byte identical on either.
 *
 * socket-udp is the crypto-free socket module (no BoringSSL), so it links cleanly alongside webrtc-dtls's
 * BoringSSL — unlike socket core / socket-quic, which would duplicate-symbol the native link
 * (see `~/git/cinterop-issues`). That is exactly why the peer binds UDP here and never TCP.
 */
internal fun realUdpBinder(): DatagramBinder =
    DatagramBinder { address ->
        UdpSocket.bind(localHost = address.host, localPort = address.port)
    }

/** Resolve a `host:port` (a compose service name or an IP literal) to a [SocketAddress]. */
internal suspend fun resolveAddress(
    host: String,
    port: Int,
): SocketAddress = UdpSocket.resolve(host, port)

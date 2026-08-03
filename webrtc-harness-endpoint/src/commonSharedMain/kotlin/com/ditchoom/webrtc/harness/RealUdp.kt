@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.socket.udp.UdpSocket
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.ice.udpDatagramBinder

/**
 * The production real-UDP [DatagramBinder] — now `webrtc-ice`'s own [udpDatagramBinder], not a copy of it.
 *
 * This function used to hold the three-line `UdpSocket.bind` itself, which meant the single most important
 * line in the harness (the ONLY substitution between a vnet run and a real-kernel run) was one the library
 * did not ship. Consumers had to rediscover it; this peer was the de-facto reference and nobody could
 * depend on it. The alias stays so the peer's call sites still read `realUdpBinder()`, but the binder the
 * interop lanes exercise on real NAT kernels is now literally the one published to consumers.
 */
internal fun realUdpBinder(): DatagramBinder = udpDatagramBinder()

/** Resolve a `host:port` (a compose service name or an IP literal) to a [SocketAddress]. */
internal suspend fun resolveAddress(
    host: String,
    port: Int,
): SocketAddress = UdpSocket.resolve(host, port)

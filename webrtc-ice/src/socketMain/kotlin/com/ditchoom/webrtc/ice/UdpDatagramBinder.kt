@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.socket.udp.UdpSocket

/**
 * The production real-UDP [DatagramBinder]: binds a `socket-udp` `UdpSocket` at the requested local
 * address and hands back its buffer-flow `AddressedDatagramChannel` — the exact seam the in-memory vnet
 * implements in tests. This one lambda is the **only** substitution between a virtual-time test and a
 * real-kernel run; the ICE agent, the gathering drivers, DTLS and SCTP above are byte-for-byte identical
 * on either.
 *
 * Pass it where a session wants real sockets:
 * ```
 * NativePeerConnection(scope, clock, random, binder = udpDatagramBinder(), gathering, dtls)
 * ```
 *
 * **It is a helper, not a factory, and deliberately so.** It binds when asked and nothing else: it opens
 * no socket eagerly, keeps no state, and does not own a lifecycle — the [IceAgentDriver] closes every
 * channel it took from a binder, once per candidate base, and this must not second-guess that. The
 * reason is not tidiness: a WebRTC session and a QUIC-P2P connection are expected to **share one demuxed
 * UDP socket**, and a binder that owned its sockets could not be composed into that. An app doing so
 * supplies its own [DatagramBinder] handing out demuxed views of the socket it already owns, and
 * everything above is unchanged.
 *
 * [bufferFactory] is where each received datagram's payload is allocated from — pass a pool to keep the
 * receive path allocation-free (directive 6). It defaults to the platform's native-capable factory,
 * which is what `socket-udp` would have used anyway.
 *
 * **Available only where `socket-udp` publishes an actual** — jvm, android, linux, macOS and iOS. It is
 * absent rather than throwing on the rest, which is the whole point: a browser has no raw UDP (there a
 * peer connection delegates to the platform's own `RTCPeerConnection` and never reaches this seam), and
 * on tvOS/watchOS `socket-udp` ships no artifact yet — so on those targets the absence is a compile
 * error at the call site rather than a runtime surprise on the wire.
 */
public fun udpDatagramBinder(bufferFactory: BufferFactory = BufferFactory.Default): DatagramBinder =
    DatagramBinder { address ->
        UdpSocket.bind(localHost = address.host, localPort = address.port, bufferFactory = bufferFactory)
    }

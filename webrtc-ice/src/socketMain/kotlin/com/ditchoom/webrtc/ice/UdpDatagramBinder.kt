@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
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
 * Received datagrams are allocated from **socket-udp's own per-platform factory**, and this overload
 * deliberately has no way to say otherwise. That is not one factory: the receive paths are different
 * implementations with different requirements — NIO on the JVM/Android, io_uring `recvmsg` on Linux,
 * `NWConnection` on Apple — and the last two write into **raw native memory**, which
 * `BufferFactory.Default` is not on those targets. socket-udp resolves it per target behind an
 * `expect val`, so any concrete factory named as a default here would silently replace a platform's
 * validated allocation strategy with one that is wrong somewhere.
 *
 * That is not hypothetical. The first draft of this function took
 * `bufferFactory: BufferFactory = BufferFactory.Default` — correct on the JVM, and fatal to **every
 * received datagram** on Linux and Apple. Host candidates still gathered, because they are synthesized
 * from the bind address and never receive anything, so the only symptom was server-reflexive and relay
 * gathering quietly producing nothing on the two platforms with the least coverage. To inject your own
 * pool, use the [other overload][udpDatagramBinder] — the choice is explicit at the call site, and there
 * is no default to get wrong.
 *
 * **It is a helper, not a factory, and deliberately so.** It binds when asked and nothing else: it opens
 * no socket eagerly, keeps no state, and does not own a lifecycle — the [IceAgentDriver] closes every
 * channel it took from a binder, once per candidate base, and this must not second-guess that. The
 * reason is not tidiness: a WebRTC session and a QUIC-P2P connection are expected to **share one demuxed
 * UDP socket**, and a binder that owned its sockets could not be composed into that. An app doing so
 * supplies its own [DatagramBinder] handing out demuxed views of the socket it already owns, and
 * everything above is unchanged.
 *
 * **Available only where `socket-udp` publishes an actual** — jvm, android, linux, macOS and iOS. It is
 * absent rather than throwing on the rest, which is the whole point: a browser has no raw UDP (there a
 * peer connection delegates to the platform's own `RTCPeerConnection` and never reaches this seam), and
 * on tvOS/watchOS `socket-udp` ships no artifact yet — so on those targets the absence is a compile
 * error at the call site rather than a runtime surprise on the wire.
 */
public fun udpDatagramBinder(): DatagramBinder =
    DatagramBinder { address ->
        // Wrapped so a refused send arrives upstairs already classified — see [TypedSendChannel]. The
        // decoration is here rather than in the drivers because it is a property of socket-udp, not of
        // ICE, and a caller supplying their own binder keeps the pre-existing untyped behaviour.
        TypedSendChannel(UdpSocket.bind(localHost = address.host, localPort = address.port))
    }

/**
 * [udpDatagramBinder] allocating every received datagram from **your** [bufferFactory] — the
 * allocate-and-transfer hook, so the kernel lands each datagram straight in a pooled buffer with no
 * downstream copy (directive 6).
 *
 * A separate overload rather than a defaulted parameter, because there is no value this function could
 * default to: the right factory differs per platform and only socket-udp knows it (see the no-argument
 * overload for what that costs when you get it wrong). Naming one here is therefore always a deliberate
 * act — you are overriding a platform default, and the call site says so.
 *
 * The factory must produce buffers the platform's receive path can write into. On Linux and Apple that
 * means **native memory**; a GC-heap factory is rejected there.
 */
public fun udpDatagramBinder(bufferFactory: BufferFactory): DatagramBinder =
    DatagramBinder { address ->
        TypedSendChannel(
            UdpSocket.bind(localHost = address.host, localPort = address.port, bufferFactory = bufferFactory),
        )
    }

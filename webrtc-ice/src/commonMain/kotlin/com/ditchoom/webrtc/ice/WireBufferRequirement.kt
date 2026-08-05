@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.flow.DatagramSink
import com.ditchoom.buffer.flow.ExperimentalDatagramApi

/**
 * Which injected [BufferFactory] an [UnsendableBufferFactoryException] is about.
 *
 * Sealed and enumerated rather than a string, because "which seam do I fix" is exactly the question the
 * exception exists to answer, and a caller that wants to repair its own configuration programmatically
 * needs a discriminant (directive #3). [description] is the prose for the message; the sealed value is
 * the API surface.
 */
public sealed interface WireBufferSeam {
    /** How this seam is named in the constructor that takes it. */
    public val description: String

    /**
     * `IceConfig.bufferFactory` — the STUN connectivity checks, the TURN control messages, and (via
     * `nativePeerConnection`, which fans one factory out to every layer) the DTLS records and SCTP-bearing
     * datagrams that ride the same socket.
     */
    public data object IceBufferFactory : WireBufferSeam {
        override val description: String get() = "IceConfig.bufferFactory"
    }

    /**
     * The `bufferFactory` of an mDNS endpoint (`MulticastMdnsEndpoint`/`MulticastMdnsResolver`), which
     * encodes queries and responses onto its **own** multicast channel rather than the ICE socket — a
     * separate channel, and therefore a separately answerable requirement.
     */
    public data object MdnsBufferFactory : WireBufferSeam {
        override val description: String get() = "MulticastMdnsEndpoint(bufferFactory = …)"
    }
}

/**
 * An injected [BufferFactory] produces buffers this platform's send path cannot transmit.
 *
 * ## What it replaces
 *
 * socket-udp's Linux (`io_uring sendmsg`) and Apple (`NWConnection`/`sendto`) send paths hand the
 * buffer's raw address straight to the OS, so a heap-backed buffer is refused outright:
 *
 * ```
 * kotlin.IllegalStateException: send requires a native-memory buffer
 *   at IoUringDatagramChannelCore.$sendDatagramCOROUTINE$1.invokeSuspend
 * ```
 *
 * Until now that landed on the **first connectivity check** — after gathering had succeeded and the
 * application believed it had a working session, with nothing in the message naming the seam that caused
 * it (issue #131). It now lands at the bind that precedes the first send, naming [seam].
 *
 * ## Why it is an `IllegalArgumentException`
 *
 * This is a configuration mistake, not a transport condition: no retry, no different peer and no better
 * network changes the answer, and the only repair is to pass a different factory. It is therefore *not*
 * an [IceFailureReason] — those are the ways a correctly configured session can still fail to connect,
 * and putting a programming error in among them would make `when` branches out of something no session
 * can recover from. Same reasoning, and the same supertype, as `SdpFormatException`.
 *
 * ## Why it cannot fire on a configuration that works
 *
 * The question asked is **"does this channel's send path demand a raw address"**, read from the channel's
 * own `DatagramCapabilities.requiresNativeMemoryBuffers` (buffer #328 / socket #281) — not "is this
 * buffer native", which the JVM/NIO and Node paths would fail while sending perfectly happily, and not a
 * platform table, which cannot tell an in-memory vnet channel from a real socket in the same process. A
 * channel that does not advertise the requirement is never probed at all.
 */
public class UnsendableBufferFactoryException(
    /** The configuration seam whose factory must change. */
    public val seam: WireBufferSeam,
) : IllegalArgumentException(
        "${seam.description} produces buffers with no native address, but this channel's send path " +
            "requires one and would reject every datagram at transmit time. Pass `networkBuffer()` " +
            "(the default), or a pool over it: `BufferPool(factory = networkBuffer())`.",
    )

/**
 * Fail now if [factory] cannot back a send on this channel — the whole of issue #131.
 *
 * Answered by **asking the channel**, which is the only participant that knows: one process can run an
 * in-memory endpoint (heap fine) beside a real socket (heap fatal), so a platform-level `expect val`
 * would over-reject the vnet, and `BufferFactory` itself exposes no capability flag to ask instead.
 *
 * Costs nothing on a channel that accepts heap buffers — [DatagramSink.capabilities] is a field read, and
 * [backsNativeMemory]'s 1-byte probe is only allocated once the channel has said it needs one.
 */
internal fun DatagramSink.requireSendableWith(
    factory: BufferFactory,
    seam: WireBufferSeam,
) {
    if (!capabilities.requiresNativeMemoryBuffers) return
    if (factory.backsNativeMemory()) return
    throw UnsendableBufferFactoryException(seam)
}

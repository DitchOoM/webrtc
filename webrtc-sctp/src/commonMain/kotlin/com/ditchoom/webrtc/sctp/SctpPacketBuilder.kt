package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.managed

/**
 * Assembles an outgoing SCTP packet (RFC 4960 §3): a common header ([sourcePort], [destinationPort],
 * [verificationTag]) plus chunks added in wire order. The CRC32c checksum is not the builder's concern
 * — it is computed and placed by [SctpPacket.encode] over the serialized bytes, so a built packet is
 * always emitted with a correct checksum.
 */
public class SctpPacketBuilder(
    private val sourcePort: UShort,
    private val destinationPort: UShort,
    private val verificationTag: VerificationTag,
) {
    private val chunks = mutableListOf<SctpChunk>()

    public fun add(chunk: SctpChunk): SctpPacketBuilder {
        chunks += chunk
        return this
    }

    /** The finished packet (source-less; the checksum is filled in by [SctpPacket.encode]). */
    public fun build(): SctpPacket {
        val header = SctpCommonHeader(sourcePort, destinationPort, verificationTag, checksum = 0u)
        return SctpPacket(header, chunks.toList(), source = null, sourceStart = 0, packetLength = 0)
    }

    /** Convenience: [build] then [SctpPacket.encode]. */
    public fun encode(factory: BufferFactory = BufferFactory.managed()): PlatformBuffer = build().encode(factory)
}

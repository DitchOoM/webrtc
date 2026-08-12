package com.ditchoom.webrtc.sctp

/**
 * Whether a chunk forces its packet to carry a real CRC32c, whatever the peer permitted (RFC 9653 §5.2).
 *
 * A permission to emit a zero checksum ([OutboundChecksum.ZeroWherePermitted]) is necessary and never
 * sufficient: §5.2 lists four restrictions that survive it, and three of them are properties of what the
 * packet contains rather than of the association. So the decision has two independent halves, and this is
 * the one the chunks answer.
 *
 * Honestly stated: this is a Boolean in a sealed coat. RFC 9653 §6 says SCTP-over-DTLS imposes no
 * method-specific constraints, so §5.2's fourth restriction — the one that would justify a third state —
 * is unreachable for this library. What earns the type is not the type: it is the exhaustive `when` over
 * every chunk variant below, which makes a chunk added later a compile error here instead of a silent
 * default. Getting that default wrong in the permissive direction puts a zero checksum on a packet the
 * RFC requires be checksummed, and nothing in a passing test suite would say so.
 */
public sealed interface ChunkChecksumRequirement {
    /** RFC 9653 §5.2 requires a correct CRC32c on any packet containing this chunk. */
    public data object Crc32cRequired : ChunkChecksumRequirement

    /** Nothing about this chunk constrains the checksum; the association's permission decides. */
    public data object EitherPermitted : ChunkChecksumRequirement
}

/**
 * This chunk's half of RFC 9653 §5.2 — the restrictions that outlive the peer's permission.
 *
 * - **INIT** (restriction 1a) — it *is* the negotiation, so nothing has been permitted yet when it goes
 *   out. The INIT ACK is deliberately absent from that list and is therefore [EitherPermitted]: by the
 *   time an endpoint answers an INIT it has already read whatever that INIT advertised.
 * - **COOKIE ECHO** (restriction 2) — the RFC's stated reason is implementation simplicity for the
 *   receiver, which has to find an association for a packet that names none. That reason is the peer's
 *   rather than ours, which is exactly why it cannot be reasoned away locally.
 * - **A reflected ABORT or SHUTDOWN COMPLETE** (restriction 1b) — the RFC 4960 §8.4 T bit set means this
 *   is an answer to an out-of-the-blue packet, sent to an endpoint we hold no association with and which
 *   therefore has granted us nothing. The bit is read here as the OOTB discriminant it is; without the
 *   T bit these are ordinary chunks of a live association.
 * - **An unrecognized chunk** — restriction 3 names ASCONF, which this library does not implement and
 *   would decode as [SctpChunk.Unrecognized], and restriction 4 covers constraints belonging to methods
 *   we do not know. A chunk we cannot name is not one we can vouch for.
 *
 * Everything else rides the association's permission. Note that this deliberately reports what the RFC
 * demands of a *sender*: a chunk we would never build (an unrecognized one) is included because
 * [SctpPacket.encode] is public and re-encodes decoded packets.
 */
public val SctpChunk.checksumRequirement: ChunkChecksumRequirement
    get() =
        when (this) {
            is SctpChunk.Init -> ChunkChecksumRequirement.Crc32cRequired
            is SctpChunk.CookieEcho -> ChunkChecksumRequirement.Crc32cRequired
            is SctpChunk.Abort ->
                if (verificationTagReflected) {
                    ChunkChecksumRequirement.Crc32cRequired
                } else {
                    ChunkChecksumRequirement.EitherPermitted
                }
            is SctpChunk.ShutdownComplete ->
                if (verificationTagReflected) {
                    ChunkChecksumRequirement.Crc32cRequired
                } else {
                    ChunkChecksumRequirement.EitherPermitted
                }
            is SctpChunk.Unrecognized -> ChunkChecksumRequirement.Crc32cRequired
            is SctpChunk.InitAck -> ChunkChecksumRequirement.EitherPermitted
            // RFC 8899's probe padding. RFC 9653 §5.2 does not restrict it, and it could not sensibly:
            // a PMTU probe rides an established association, which is exactly where a granted permission
            // applies. Forcing a CRC32c here would also make the probe measure a different cost than the
            // traffic it is sizing for, which defeats the measurement.
            is SctpChunk.Pad -> ChunkChecksumRequirement.EitherPermitted
            is SctpChunk.Data -> ChunkChecksumRequirement.EitherPermitted
            is SctpChunk.Sack -> ChunkChecksumRequirement.EitherPermitted
            is SctpChunk.Heartbeat -> ChunkChecksumRequirement.EitherPermitted
            is SctpChunk.HeartbeatAck -> ChunkChecksumRequirement.EitherPermitted
            is SctpChunk.Shutdown -> ChunkChecksumRequirement.EitherPermitted
            SctpChunk.ShutdownAck -> ChunkChecksumRequirement.EitherPermitted
            SctpChunk.CookieAck -> ChunkChecksumRequirement.EitherPermitted
            is SctpChunk.Error -> ChunkChecksumRequirement.EitherPermitted
            is SctpChunk.ReConfig -> ChunkChecksumRequirement.EitherPermitted
            is SctpChunk.ForwardTsn -> ChunkChecksumRequirement.EitherPermitted
        }

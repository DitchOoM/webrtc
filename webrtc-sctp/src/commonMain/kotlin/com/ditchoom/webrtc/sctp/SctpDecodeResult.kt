package com.ditchoom.webrtc.sctp

/**
 * The outcome of [SctpPacket.decode]. Parse failure is a **typed reject**, never a throw-through or a
 * crash (T0 discipline / DESIGN_PRINCIPLES §6): a caller `when`s over this exhaustively with no `else`,
 * and a hostile datagram can only ever produce a [Reject], never an exception.
 */
public sealed interface SctpDecodeResult {
    public data class Success(
        public val packet: SctpPacket,
    ) : SctpDecodeResult

    public data class Reject(
        public val reason: SctpRejectReason,
    ) : SctpDecodeResult
}

/**
 * Why a datagram is not a well-formed SCTP packet. A sealed, exhaustive vocabulary — the discriminant
 * is the type, never a string (directive #3); the diagnostic detail rides as data. These map into the
 * `SocketException` hierarchy at the association layer (the rest of W5).
 */
public sealed interface SctpRejectReason {
    /** Fewer than the 12-byte common header (RFC 4960 §3.1). */
    public data object ShorterThanCommonHeader : SctpRejectReason

    /** The packet carried no chunks after the common header — RFC 4960 §3 requires at least one. */
    public data object NoChunks : SctpRejectReason

    /**
     * A chunk's fixed 4-byte header ([offset]) ran past the datagram, or its declared length was less
     * than the 4-byte header (RFC 4960 §3.2: `Chunk Length` counts the 4-byte header + value).
     */
    public data class MalformedChunkHeader(
        public val offset: Int,
    ) : SctpRejectReason

    /** A chunk at [offset] declared [declaredLength] bytes, which extends past the datagram. */
    public data class ChunkLengthBeyondPacket(
        public val offset: Int,
        public val declaredLength: Int,
        public val available: Int,
    ) : SctpRejectReason

    /**
     * A chunk's body did not match the fixed shape its type requires (e.g. a SHUTDOWN whose value is
     * not exactly 4 bytes, a SACK truncated inside its gap/dup arrays, a DATA shorter than its
     * 12-byte fixed prefix). [offset] is the chunk's start; [type] its declared type.
     */
    public data class MalformedChunkBody(
        public val offset: Int,
        public val type: SctpChunkType,
    ) : SctpRejectReason
}

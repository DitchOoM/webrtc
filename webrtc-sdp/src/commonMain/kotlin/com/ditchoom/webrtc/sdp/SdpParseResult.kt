package com.ditchoom.webrtc.sdp

/**
 * The outcome of [SessionDescription.parse]. Parse failure is a **typed reject**, never a
 * throw-through or a crash (T0 discipline / DESIGN_PRINCIPLES §6): a caller `when`s over this
 * exhaustively with no `else`, and a hostile datagram can only ever produce a [Reject].
 */
public sealed interface SdpParseResult {
    public data class Success(
        public val description: SessionDescription,
    ) : SdpParseResult

    public data class Reject(
        public val reason: SdpRejectReason,
    ) : SdpParseResult
}

/**
 * Why a byte sequence is not a well-formed SDP document. A sealed, exhaustive vocabulary — the
 * discriminant is the type, never a string (directive #3); the diagnostic detail rides as data.
 * These map into the `SocketException` hierarchy at the session layer (W6).
 *
 * Only **structural** failures are rejects here (the line grammar of RFC 8866 §5). Semantic
 * interpretation of a specific line — a malformed `o=`, `m=`, or `a=fingerprint` — is deferred to the
 * typed field interpreters ([Origin.parse], [MediaLine.parse], …), which are null-on-malformed, so a
 * document with one broken attribute still parses and round-trips (mirrors STUN's `RawAttribute`).
 */
public sealed interface SdpRejectReason {
    /** The datagram was empty — SDP requires at least a `v=0` line (RFC 8866 §5). */
    public data object Empty : SdpRejectReason

    /** The bytes were not valid UTF-8 text (SDP is a text protocol, RFC 8866 §5). */
    public data object NotText : SdpRejectReason

    /** A line was not of the form `<type>=<value>` with a single-character type (RFC 8866 §5). */
    public data class MalformedLine(
        public val lineIndex: Int,
        public val line: String,
    ) : SdpRejectReason

    /** The first line was not a version line `v=…` (RFC 8866 §5.1: `v=` must come first). */
    public data object MissingVersion : SdpRejectReason

    /** The version was present but not `0`, the only version this codec speaks (RFC 8866 §5.1). */
    public data class UnsupportedVersion(
        public val version: String,
    ) : SdpRejectReason
}

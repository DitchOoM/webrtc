package com.ditchoom.webrtc.sctp.association

import kotlin.jvm.JvmInline

/** The JSEP/browser default ceiling, 256 KiB — see [ReceiveMessageLimit.Default]. */
private const val DEFAULT_RECEIVE_LIMIT_BYTES = 262_144L

/** A ceiling of zero bytes would accept nothing; "no ceiling" is [ReceiveMessageLimit.Unbounded]. */
private const val SMALLEST_CEILING = 1L

/**
 * The largest user message **this endpoint** will reassemble (RFC 8841 §6's `a=max-message-size`, from
 * the receiving side). Two jobs, one value: it is what the session layer advertises to the peer, and it
 * is the ceiling the reassembly queue enforces on what the peer actually sends.
 *
 * That those are the same number is the point. Advertising 256 KiB and enforcing something else is either
 * a promise broken (enforcing less) or an unbounded receive buffer (enforcing more), and a design with
 * two knobs makes both reachable by editing one of them.
 *
 * Sealed rather than a `Long`, for the reason RFC 8841 §6 forces: the wire spells "no limit other than
 * what the implementation can handle" as `0`, which is the *largest* answer written with the smallest
 * number. A `Long` ceiling of `0` refuses every message including the empty one — the arithmetic reads
 * correctly and is backwards. [Unbounded] names that case so no comparison can invert it, and [Bytes]
 * refuses `0` at construction so the inverted value is unconstructible.
 */
public sealed interface ReceiveMessageLimit {
    /**
     * No ceiling — accept whatever the peer sends, bounded only by memory. Advertised as
     * `a=max-message-size:0` (RFC 8841 §6).
     *
     * Deliberately not the default: a receiver with no ceiling is one whose memory a peer paces, and the
     * reassembly queue holds fragments of an incomplete message until they are all there. Choose it only
     * when something above bounds the peer.
     */
    public data object Unbounded : ReceiveMessageLimit

    /** A ceiling of at least one byte. `Bytes(0)` — a ceiling accepting nothing — is unconstructible. */
    @JvmInline
    public value class Bytes(
        public val value: Long,
    ) : ReceiveMessageLimit {
        init {
            require(value >= SMALLEST_CEILING) { "a receive ceiling must be at least 1 byte, was $value" }
        }
    }

    public companion object {
        /**
         * 256 KiB — the JSEP/browser default (`DataChannelParameters.DEFAULT_MAX_MESSAGE_SIZE` in
         * `webrtc-sdp`, which is what an unconfigured session advertises). The two constants live in
         * different modules because `webrtc-sctp` does not depend on SDP; that they agree is asserted by
         * a fixture in `webrtc`, which is the one module that sees both.
         *
         * **Not** RFC 8831 §6.6's 64 KiB. That number is what we must assume of a peer that advertised
         * *nothing* — see `PeerMessageLimit.ASSUMED_DEFAULT_BYTES` — and the two are easy to confuse
         * because both are "the max-message-size default". What we promise and what we assume of silence
         * are different promises made by different endpoints.
         */
        public val Default: ReceiveMessageLimit = Bytes(DEFAULT_RECEIVE_LIMIT_BYTES)
    }
}

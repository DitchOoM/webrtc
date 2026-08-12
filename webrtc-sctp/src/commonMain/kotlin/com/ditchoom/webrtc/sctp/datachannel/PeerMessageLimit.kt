package com.ditchoom.webrtc.sctp.datachannel

import kotlin.jvm.JvmInline

/** A stated peer ceiling of zero bytes cannot exist: the wire's `0` is [PeerMessageLimit.Unlimited]. */
private const val SMALLEST_CEILING = 1L

/** RFC 8831 §6.6 — what a peer that said nothing is assumed to accept. */
private const val ASSUMED_DEFAULT = 65_536L

/**
 * The largest user message **the peer** will accept on this association — what its `a=max-message-size`
 * (RFC 8841 §6) said, read through RFC 8831 §6.6's rule for silence.
 *
 * Four cases, because a `Long?` collapses four genuinely different situations into two and inverts the
 * most dangerous one:
 *
 * - [NotYetNegotiated] — no remote description has been applied, so nothing has been *said*. It is not
 *   the same as a peer that said nothing: the peer has not spoken at all.
 * - [AssumedDefault] — the peer described a data channel and omitted the attribute, so RFC 8831 §6.6's
 *   64 KiB applies. A number we chose on its behalf, not one it stated.
 * - [Unlimited] — `a=max-message-size:0`, RFC 8841 §6's "any size the implementation can handle". The
 *   *largest* answer, spelled with the smallest number; a `Long` holding it refuses every message,
 *   including the empty one, against exactly the peer that would take anything.
 * - [Advertised] — a real stated ceiling, of at least one byte.
 *
 * A peer whose attribute is present but unreadable maps to [AssumedDefault] rather than to a case of its
 * own. That is the conservative direction and it is the only safe one: RFC 8831 §6.6 makes exceeding a
 * peer's limit a MUST NOT, so an unreadable statement has to be treated as the tightest reading it could
 * have had, never as "no limit". (`a=max-message-size:99999999999999999999` is the shape that makes this
 * concrete — a digit string the grammar permits, too large for a `Long`, and unmistakably *not* an
 * invitation to send anything.) The distinction survives where it is diagnostic rather than
 * load-bearing: `MaxMessageSizeAttribute.Malformed` still carries the raw text, one layer down.
 */
public sealed interface PeerMessageLimit {
    /** No remote description applied yet — the peer has not spoken, so nothing may be assumed of it. */
    public data object NotYetNegotiated : PeerMessageLimit

    /**
     * The peer described a data channel and stated no ceiling, so RFC 8831 §6.6's
     * [ASSUMED_DEFAULT_BYTES] applies. Distinct from [Advertised]`(65536)`: the same ceiling, but one
     * we assumed and one it promised — which is why the two produce different refusal reasons.
     */
    public data object AssumedDefault : PeerMessageLimit

    /** `a=max-message-size:0` — RFC 8841 §6's no limit beyond what the peer's implementation can hold. */
    public data object Unlimited : PeerMessageLimit

    /** A ceiling the peer stated, of at least one byte. `Advertised(0)` is unconstructible — see above. */
    @JvmInline
    public value class Advertised(
        public val bytes: Long,
    ) : PeerMessageLimit {
        init {
            require(bytes >= SMALLEST_CEILING) { "an advertised peer ceiling must be at least 1 byte, was $bytes" }
        }
    }

    public companion object {
        /**
         * 64 KiB — RFC 8831 §6.6's assumed ceiling for a peer that advertised none.
         *
         * **Not** `ReceiveMessageLimit.Default` (256 KiB), which is what *we* advertise. The two are the
         * easiest pair in this area to confuse, and getting them the wrong way round overruns every peer
         * that never claimed more than 64 KiB — Pion advertises nothing at all, so that peer is in the
         * interop matrix rather than hypothetical.
         */
        public const val ASSUMED_DEFAULT_BYTES: Long = ASSUMED_DEFAULT
    }
}

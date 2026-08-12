package com.ditchoom.webrtc.sdp

import kotlin.jvm.JvmInline

/** RFC 8841 §6 spells the attribute; it is media-level only, so only a [MediaDescription] carries one. */
private const val MAX_MESSAGE_SIZE = "max-message-size"

/** RFC 8841 §6: the one value that is not a ceiling — `0` means "whatever the implementation can handle". */
private const val UNLIMITED_ON_THE_WIRE = 0L

/** A ceiling of zero bytes would accept nothing; the wire spells that value [MaxMessageSizeAttribute.Unlimited]. */
private const val SMALLEST_CEILING = 1L

/**
 * What a media section says about `a=max-message-size` (RFC 8841 §6) — the largest SCTP user message
 * the peer is willing to **receive** on this association (RFC 8831 §6.6).
 *
 * Four cases, because the attribute really has four readings and the obvious `Long?` collapses them into
 * two — with the most dangerous one **inverted**:
 *
 * - [Absent] — no `a=max-message-size` line at all. This is not "no information": the missing attribute
 *   has a defined meaning, the RFC 8831 §6.6 assumed default of 64 KiB. It stays [Absent] here rather
 *   than being folded into a [Bytes] of 65536, because a peer that said 64 KiB and a peer that said
 *   nothing are answering different questions — §6.6's default is a SHOULD the *transport* applies, and
 *   substituting it in the codec would make that policy unobservable and unoverridable.
 * - [Unlimited] — the wire value `0`, which RFC 8841 §6 defines as no limit other than what the
 *   implementation can handle. It is the **largest** answer the attribute can give and it is spelled with
 *   the smallest number, so a reader that keeps it as a `Long` and compares message sizes against it
 *   refuses every message including the empty one. Naming the case removes that arithmetic entirely.
 * - [Bytes] — a real ceiling, of at least one byte.
 * - [Malformed] — the line is present and its value is not a byte count. A **typed reject**, never a
 *   throw (T0 discipline): the raw text rides along as a diagnostic and is never a discriminant.
 *
 * Read one with [maxMessageSizeAttribute]. This supersedes [MediaDescription.maxMessageSize], whose
 * `Long?` cannot tell [Absent] from [Malformed] and hands [Unlimited] back as a literal `0`.
 */
public sealed interface MaxMessageSizeAttribute {
    /**
     * No `a=max-message-size` in this section — which RFC 8831 §6.6 gives a defined reading (assume
     * 64 KiB), not an absence of one. Distinct from [Malformed]: nothing was said, versus something
     * unreadable was.
     *
     * Note this is **not** [DataChannelParameters.DEFAULT_MAX_MESSAGE_SIZE], which is the 256 KiB
     * ceiling *we* advertise. What we send and what we must assume of a silent peer are different
     * numbers, and conflating them is a way to overrun a peer that never claimed more than 64 KiB.
     */
    public data object Absent : MaxMessageSizeAttribute

    /**
     * `a=max-message-size:0` — RFC 8841 §6's "the endpoint can handle messages of any size", bounded
     * only by its own resources. The ceiling is absent, not zero.
     */
    public data object Unlimited : MaxMessageSizeAttribute

    /**
     * A stated ceiling, in bytes, of at least one. `Bytes(0)` — a ceiling that accepts nothing, while
     * the wire's `0` means everything — is refused at construction, so the inversion is unrepresentable
     * rather than merely undocumented.
     */
    @JvmInline
    public value class Bytes(
        public val value: Long,
    ) : MaxMessageSizeAttribute {
        init {
            require(value >= SMALLEST_CEILING) { "max-message-size ceiling must be at least 1 byte, was $value" }
        }
    }

    /**
     * An `a=max-message-size` whose value is not a decimal byte count (RFC 8841 §6). [value] is the
     * verbatim text, carried for diagnosis only.
     *
     * Signs, decimal points, whitespace and a bare flag line (`a=max-message-size`, whose value is the
     * empty string) all land here, as does a digit string too large for a 64-bit count — the grammar
     * puts no ceiling on the integer, and a number past `Long.MAX_VALUE` is one this type cannot state.
     * A caller that treats [Malformed] the way it treats [Absent] is conservative in the safe direction:
     * it refuses messages a peer might well have accepted, rather than sending one it must not.
     */
    public data class Malformed(
        public val value: String,
    ) : MaxMessageSizeAttribute
}

/**
 * Reads this section's `a=max-message-size` (RFC 8841 §6) as a typed [MaxMessageSizeAttribute]. Total —
 * every input, including a hostile one, produces a case; nothing throws.
 *
 * Defined on [MediaDescription] rather than on [SdpSection] because RFC 8841 §6 defines the attribute at
 * media level only. It describes one SCTP association, so unlike `a=ice-ufrag` or `a=setup` there is no
 * session-level default to fall back to, and offering the reader on the session block would invite one to
 * be invented. Finding *which* media section is the data channel is the caller's question and a separate
 * one — a description whose first `m=` is audio has a `m=application` section further down, and the first
 * section is the wrong answer.
 *
 * The first line wins if a section repeats the attribute, matching every other reader here.
 */
public fun MediaDescription.maxMessageSizeAttribute(): MaxMessageSizeAttribute {
    val raw =
        firstAttributeValue(MAX_MESSAGE_SIZE) ?: return when {
            // A bare flag line: the peer declared the attribute and put nothing in it, which is a
            // statement that cannot be read — not the silence [MaxMessageSizeAttribute.Absent] means.
            hasFlag(MAX_MESSAGE_SIZE) -> MaxMessageSizeAttribute.Malformed("")
            else -> MaxMessageSizeAttribute.Absent
        }
    // RFC 8841 §6's value is a decimal digit string, so `toLongOrNull` alone is too generous: it accepts
    // a sign the grammar does not. It is still needed after the digit check, for the overflow the
    // grammar permits and a Long cannot hold.
    if (raw.isEmpty() || !raw.all { it in '0'..'9' }) return MaxMessageSizeAttribute.Malformed(raw)
    val bytes = raw.toLongOrNull() ?: return MaxMessageSizeAttribute.Malformed(raw)
    return if (bytes == UNLIMITED_ON_THE_WIRE) {
        MaxMessageSizeAttribute.Unlimited
    } else {
        MaxMessageSizeAttribute.Bytes(bytes)
    }
}

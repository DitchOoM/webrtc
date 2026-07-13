package com.ditchoom.webrtc.sdp

/**
 * A parsed origin line (`o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>`,
 * RFC 8866 §5.2). The `<sess-id>`/`<sess-version>` pair is the JSEP renegotiation key (RFC 8829 §5.2.1:
 * a new offer for the same session keeps [sessionId] and increments [sessionVersion]).
 *
 * [parse] is total and null-on-malformed (typed-reject discipline) — it never throws on a broken `o=`.
 * `<sess-id>`/`<sess-version>` are kept as strings, not longs: RFC 8866 permits up to a 64-bit value
 * and JSEP treats them as opaque numeric strings, so parsing to `Long` would both lose fidelity and
 * risk an overflow throw on a hostile input.
 */
public data class Origin(
    public val username: String,
    public val sessionId: String,
    public val sessionVersion: String,
    public val netType: String,
    public val addrType: String,
    public val unicastAddress: String,
) {
    /** Serializes back to the `o=` line value (space-joined), exactly as [parse] consumed it. */
    public fun toValue(): String = "$username $sessionId $sessionVersion $netType $addrType $unicastAddress"

    public companion object {
        private const val FIELD_COUNT = 6

        /** Parses an `o=` line value into an [Origin], or null if it does not have the 6 fields. */
        public fun parse(value: String): Origin? {
            val f = value.split(' ')
            if (f.size != FIELD_COUNT) return null
            return Origin(f[0], f[1], f[2], f[3], f[4], f[5])
        }
    }
}

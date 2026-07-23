package com.ditchoom.webrtc.stun

/**
 * An IP address as a value, held **without a `ByteArray`** (standing directive #1): IPv4 packs into
 * a `UInt`, IPv6 into two `ULong`s. Value equality + a hash for free, and it can outlive the
 * datagram (an ICE candidate keeps it) with no retained slice. The STUN address family byte
 * (RFC 8489 §14.1) is the sealed discriminant, so an "IPv4 with 16 bytes" state is unrepresentable.
 */
public sealed interface IpAddress {
    /** RFC 8489 §14.1 family byte: 0x01 (IPv4) or 0x02 (IPv6). */
    public val family: UByte

    /** IPv4, big-endian in [bits] (bits 31..24 are the first dotted octet). */
    public data class V4(
        public val bits: UInt,
    ) : IpAddress {
        override val family: UByte get() = FAMILY

        override fun toString(): String {
            val b = bits
            return "${(b shr 24) and 0xFFu}.${(b shr 16) and 0xFFu}.${(b shr 8) and 0xFFu}.${b and 0xFFu}"
        }

        public companion object {
            public const val FAMILY: UByte = 0x01u
            public const val SIZE_BYTES: Int = 4
        }
    }

    /** IPv6, [hi] the first 8 bytes (network order), [lo] the last 8. */
    public data class V6(
        public val hi: ULong,
        public val lo: ULong,
    ) : IpAddress {
        override val family: UByte get() = FAMILY

        /** The [i]-th 16-bit hextet in network order (0 = the most significant), by pure ULong shifts. */
        private fun hextet(i: Int): Int {
            val word = if (i < HEXTETS_PER_WORD) hi else lo
            return ((word shr (WORD_HIGH_SHIFT - (i % HEXTETS_PER_WORD) * HEXTET_BITS)) and HEXTET_MASK).toInt()
        }

        /**
         * Canonical **RFC 5952** text form: lowercase hex, leading zeros suppressed (§4.1), the *leftmost*
         * *longest* run of ≥2 zero hextets compressed to `::` (§4.2.2/§4.2.3 — a lone zero hextet is **not**
         * compressed), and **unbracketed** (brackets are a URI-authority concern, never the address itself,
         * and buffer-flow's `ofLiteral` rejects them). This is what every wire/candidate rendering funnels
         * through, so it must round-trip through [parse].
         */
        override fun toString(): String {
            // Find the leftmost-longest run of consecutive zero hextets (compress only if length ≥ 2).
            var bestStart = -1
            var bestLen = 0
            var runStart = -1
            for (i in 0 until HEXTET_COUNT) {
                if (hextet(i) == 0) {
                    if (runStart < 0) runStart = i
                    val len = i - runStart + 1
                    if (len > bestLen) {
                        bestLen = len
                        bestStart = runStart
                    }
                } else {
                    runStart = -1
                }
            }
            if (bestLen < 2) bestStart = -1 // a single zero hextet is written "0", not compressed

            val sb = StringBuilder()
            var i = 0
            while (i < HEXTET_COUNT) {
                if (i == bestStart) {
                    sb.append("::")
                    i += bestLen
                } else {
                    if (sb.isNotEmpty() && !sb.endsWith(":")) sb.append(':')
                    sb.append(hextet(i).toString(HEX_RADIX))
                    i++
                }
            }
            return sb.toString()
        }

        public companion object {
            public const val FAMILY: UByte = 0x02u
            public const val SIZE_BYTES: Int = 16

            /**
             * Parse an IPv6 literal into a [V6], or `null` on any malformed input (a **typed reject**, never
             * a throw — T0 discipline). Accepts every RFC 4291/5952 form the ICE text boundary can hand us:
             * `::` compression (at most one), an embedded-IPv4 tail (`::ffff:1.2.3.4`), and a trailing
             * `%zone` (stripped). Rejects a bracketed literal, `:::`, >8 hextets, empty groups, and a hextet
             * out of range. Accumulates into the two [hi]/[lo] `ULong`s by **shifts only** — no `ByteArray`
             * or primitive array (directive #1); this is control-plane, not a per-datagram hot path.
             */
            public fun parse(literal: String): V6? {
                val s = literal.substringBefore('%')
                if (s.isEmpty() || '[' in s || ']' in s) return null

                val dc = s.indexOf("::")
                val compressed = dc >= 0
                if (compressed && s.indexOf("::", dc + 2) >= 0) return null // more than one "::"

                val head = if (compressed) s.substring(0, dc) else s
                val tail = if (compressed) s.substring(dc + 2) else ""

                // The embedded-IPv4 tail (if any) is always the final group of the WHOLE address (RFC 4291
                // §2.2.3), so it is legal only in the head of an *uncompressed* literal (the head is then the
                // whole address) or in a *non-empty* tail run — never in the head of a "::"-terminated form.
                val headAcc = Hextets()
                val tailAcc = Hextets()
                if (!parseRun(head, headAcc, allowV4Tail = !compressed)) return null
                if (!parseRun(tail, tailAcc, allowV4Tail = compressed && tail.isNotEmpty())) return null

                val total = headAcc.count + tailAcc.count
                return if (compressed) {
                    if (total > HEXTET_COUNT - 1) return null // "::" must stand for ≥1 zero hextet
                    repeat(HEXTET_COUNT - headAcc.count) { headAcc.append(0) } // top-align the head groups
                    V6(headAcc.hi or tailAcc.hi, headAcc.lo or tailAcc.lo)
                } else {
                    if (total != HEXTET_COUNT || tailAcc.count != 0) return null
                    V6(headAcc.hi, headAcc.lo)
                }
            }

            /** A 128-bit accumulator: [append] shifts the (hi,lo) pair left one hextet and ORs [group] in. */
            private class Hextets {
                var hi: ULong = 0uL
                var lo: ULong = 0uL
                var count: Int = 0

                fun append(group: Int) {
                    hi = (hi shl HEXTET_BITS) or (lo shr WORD_HIGH_SHIFT)
                    lo = (lo shl HEXTET_BITS) or group.toULong()
                    count++
                }
            }

            /** Parse a colon-separated group run into [acc]; expands a trailing IPv4 literal to two groups. */
            private fun parseRun(
                run: String,
                acc: Hextets,
                allowV4Tail: Boolean,
            ): Boolean {
                if (run.isEmpty()) return true // the empty side adjacent to "::" contributes no groups
                val groups = run.split(':')
                for ((i, g) in groups.withIndex()) {
                    if (g.isEmpty()) return false // a leading/trailing bare ':' (not "::") is malformed
                    if (allowV4Tail && i == groups.lastIndex && '.' in g) {
                        val v4 = parseEmbeddedV4(g) ?: return false
                        acc.append(((v4 shr HEXTET_BITS) and HEXTET_MASK.toUInt()).toInt())
                        acc.append((v4 and HEXTET_MASK.toUInt()).toInt())
                    } else {
                        if (g.length > MAX_HEXTET_DIGITS || !g.isHexDigits()) return false // rejects '.', '+', '-', …
                        val v = g.toIntOrNull(HEX_RADIX) ?: return false
                        if (v > HEXTET_MASK.toInt()) return false
                        acc.append(v)
                    }
                }
                return true
            }

            /** Parse a dotted-quad into its 32-bit big-endian value, or null (each octet 0..255). */
            private fun parseEmbeddedV4(g: String): UInt? {
                val octets = g.split('.')
                if (octets.size != V4.SIZE_BYTES) return null
                var bits = 0u
                for (octet in octets) {
                    if (octet.isEmpty() || !octet.all { it in '0'..'9' }) return null // rejects '+', '-', …
                    val value = octet.toUIntOrNull() ?: return null
                    if (value > MAX_OCTET) return null
                    bits = (bits shl Byte.SIZE_BITS) or value
                }
                return bits
            }

            // Kotlin's toIntOrNull(radix) tolerates a leading '+'/'-' sign; the wire format does not. Guard
            // the numeric parse so a signed group (e.g. "+a") is a typed reject, matching buffer-flow's parser.
            private fun String.isHexDigits(): Boolean = isNotEmpty() && all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

            private const val HEXTET_COUNT = 8
            private const val HEXTETS_PER_WORD = 4
            private const val HEXTET_BITS = 16
            private const val WORD_HIGH_SHIFT = 48
            private const val HEXTET_MASK: ULong = 0xFFFFuL
            private const val HEX_RADIX = 16
            private const val MAX_HEXTET_DIGITS = 4
            private const val MAX_OCTET = 255u
        }
    }
}

/**
 * A transport address: an [IpAddress] and a 16-bit [port]. The parsed form of MAPPED-ADDRESS and
 * (after un-XOR) XOR-MAPPED-ADDRESS / the TURN peer & relayed addresses.
 */
public data class TransportAddress(
    public val ip: IpAddress,
    public val port: UShort,
)

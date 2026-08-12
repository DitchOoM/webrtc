package com.ditchoom.webrtc.sctp.association

import kotlin.jvm.JvmInline

// The SCTP bytes every DATA packet spends before a single byte of user data: the RFC 4960 §3.1 common
// header (12) plus one DATA chunk's own header (§3.3.1 — a 4-byte TLV header and 12 bytes of fixed
// fields). File-private rather than a `const val` in a private companion, which is still emitted as a
// public static field.
private const val SCTP_PACKET_FIXED_BYTES = 12 + 16

// RFC 8899 §5.1.2 MIN_PMTU for IPv4 — RFC 1122 §3.3.3's EMTU_R floor, the smallest datagram every IPv4
// host must be able to reassemble.
private const val IPV4_MINIMUM_PATH_MTU = 576

// RFC 8200 §5: "IPv6 requires that every link in the Internet have an MTU of 1280 octets or greater."
private const val IPV6_MINIMUM_PATH_MTU = 1280

// What an IPv4 path is assumed to carry before anything has probed it. Not a guarantee and not claimed to
// be one — see [PathAddressFamily.unprobedPathMtu] for why an over-estimate is affordable on IPv4 and is
// not on IPv6.
private const val IPV4_UNPROBED_PATH_MTU = 1500

private const val PMTU_MIN = IPV4_MINIMUM_PATH_MTU
private const val PMTU_MAX = 65535

// The largest overhead any path this stack rides can impose below SCTP, rounded up: a relayed IPv6 path
// pays 40 (IPv6) + 8 (UDP) + 48 (a TURN Send indication carrying an IPv6 XOR-PEER-ADDRESS) + 37 (a
// DTLS 1.2 AES-GCM record) = 133. The bound is what makes [FragmentCeilingBytes] constructible by
// construction — see its KDoc.
private const val OVERHEAD_MAX = 192

// 576 - 192 - 28, and therefore the smallest ceiling any legal (pmtu, overhead) pair can derive.
private const val FRAGMENT_CEILING_MIN = PMTU_MIN - OVERHEAD_MAX - SCTP_PACKET_FIXED_BYTES

private const val FOUR_BYTE_ALIGNMENT = 4

/**
 * Which path the association is riding, as far as the layer *below* it is concerned — an opaque ordinal
 * minted by the session layer, compared for equality and nothing else.
 *
 * It exists because the association cannot answer "did the path move" and must not try. The 5-tuple lives
 * two layers down, in ICE, and the questions that look like they would serve instead do not: the address
 * *family* and the header *overhead* can both be unchanged across a genuine migration (the same interface
 * re-bound on a new port after an RFC 8445 §9 restart is a different path with identical everything), and
 * the congestion window, the RTT estimate and the PMTU search that a migration invalidates are invalidated
 * by exactly that case.
 *
 * **Never ordered, never persisted, never sent.** A caller that repeats an ordinal is saying "the same
 * path", which is correct and harmless; a caller that regresses one is saying the same thing. There is no
 * arithmetic here to get wrong, which is the point of an ordinal that only `==` reads.
 *
 * Distinct from `PathEpoch`, which the association mints for itself: this says *which* path, that says
 * *how many times the path has changed under this association*. Only the session layer can answer the
 * first and only the association needs the second.
 */
@JvmInline
public value class PathIdentity(
    public val ordinal: UInt,
)

/**
 * A path MTU in bytes — the size of the largest **IP datagram** the path carries, headers included.
 *
 * Bounded at construction to `[576, 65535]`. The floor is RFC 8899 §5.1.2's MIN_PMTU for IPv4, which is
 * the smallest value the SCTP/DTLS/UDP stack can be asked about at all; the ceiling is what an IP length
 * field can express. Those bounds are not decoration — together with [PathOverheadBytes]'s they are what
 * makes every derived [FragmentCeilingBytes] legal without a single `coerceAtLeast`.
 */
@JvmInline
public value class PmtuBytes(
    public val value: Int,
) : Comparable<PmtuBytes> {
    init {
        require(value in PMTU_MIN..PMTU_MAX) { "path MTU $value is outside $PMTU_MIN..$PMTU_MAX bytes" }
    }

    override fun compareTo(other: PmtuBytes): Int = value.compareTo(other.value)
}

/**
 * Everything an SCTP packet on this path pays **below** SCTP: the IP header, the UDP header, the DTLS
 * record expansion, and on a relayed path the TURN framing as well.
 *
 * Bounded at `[0, 192]`. Zero is legal because a test transport can have none, and the ceiling is the
 * worst real path this stack rides with room to spare (a relayed IPv6 session costs 133). Anything above
 * that is a caller mistake rather than a path, and admitting it would let a [FragmentCeilingBytes] be
 * derived that no `require` could have saved.
 */
@JvmInline
public value class PathOverheadBytes(
    public val value: Int,
) {
    init {
        require(value in 0..OVERHEAD_MAX) { "path overhead $value is outside 0..$OVERHEAD_MAX bytes" }
    }
}

/**
 * The largest **user-data payload** one DATA chunk may carry (RFC 4960 §6.9's fragmentation point), as a
 * multiple of four bytes.
 *
 * Four-byte aligned because every SCTP chunk is padded to a 4-byte boundary anyway (RFC 4960 §3.2), so a
 * ceiling that is not a multiple of four buys nothing and costs a padding byte per fragment that the
 * arithmetic then has to remember.
 *
 * **The lower bound is a theorem, not a check.** [of] derives `pmtu - overhead - 28`, and `PmtuBytes`
 * cannot be below 576 while `PathOverheadBytes` cannot be above 192, so the smallest derivable value is
 * `576 - 192 - 28 = 356` — already a multiple of four, and already above the floor. The `require` below
 * therefore states an invariant the inputs guarantee rather than defending against them, which is the
 * deliberate inverse of clamping a result that could have been wrong.
 */
@JvmInline
public value class FragmentCeilingBytes(
    public val value: Int,
) : Comparable<FragmentCeilingBytes> {
    init {
        require(value >= FRAGMENT_CEILING_MIN) { "fragment ceiling $value is below the $FRAGMENT_CEILING_MIN-byte floor" }
        require(value % FOUR_BYTE_ALIGNMENT == 0) { "fragment ceiling $value is not a multiple of $FOUR_BYTE_ALIGNMENT" }
    }

    override fun compareTo(other: FragmentCeilingBytes): Int = value.compareTo(other.value)

    public companion object {
        /**
         * The ceiling a path of [pathMtu] carrying [overhead] bytes of lower-layer headers admits: the
         * datagram budget less everything below SCTP, less the SCTP common header and the DATA chunk's own
         * header, rounded down to a 4-byte boundary.
         */
        public fun of(
            pathMtu: PmtuBytes,
            overhead: PathOverheadBytes,
        ): FragmentCeilingBytes {
            val usable = pathMtu.value - overhead.value - SCTP_PACKET_FIXED_BYTES
            return FragmentCeilingBytes(usable - usable % FOUR_BYTE_ALIGNMENT)
        }
    }
}

/**
 * The IP version the path stands on, and the two MTU facts that follow from it.
 *
 * Sealed with the numbers attached rather than an enum plus a lookup, because the two families differ in
 * a way that a single "minimum MTU" column cannot express and that the difference between the two
 * properties below is exactly about.
 */
public sealed interface PathAddressFamily {
    /**
     * RFC 8899 §5.1.2's MIN_PMTU: the smallest datagram the family guarantees end-to-end, and therefore
     * the floor below which probing for a *smaller* size is pointless.
     */
    public val minimumPathMtu: PmtuBytes

    /**
     * The largest datagram that may be emitted **before a probe has confirmed the path carries it**.
     *
     * This is where the two families genuinely part, and why one number would not have done:
     *
     * - On **IPv4** an over-estimate is delivered anyway. A router that meets a datagram larger than its
     *   next-hop MTU fragments it (RFC 791 §2.3) unless DF is set, and this stack sets no DF, so guessing
     *   high costs reassembly work rather than the packet. [Ipv4] therefore assumes the ubiquitous
     *   Ethernet MTU — an assumption, stated as one, and one that a DPLPMTUD search can refute.
     * - On **IPv6** an over-estimate is *lost*. RFC 8200 §5 forbids a router to fragment; an oversized
     *   datagram is dropped and answered with an ICMPv6 Packet Too Big that a UDP socket behind a NAT may
     *   never see. So the unprobed value can only be the guaranteed one, and it is the same 1280.
     *
     * That asymmetry is the whole of the defect this pair fixes: an SCTP payload sized for a 1500-byte
     * link produces a 1313-byte IPv6 datagram, which every 1280-MTU v6 path silently drops — while the
     * identical payload on IPv4 has been arriving on every lane for years, because IPv4 fragmented it.
     */
    public val unprobedPathMtu: PmtuBytes

    /** IPv4 (RFC 791). */
    public data object Ipv4 : PathAddressFamily {
        override val minimumPathMtu: PmtuBytes get() = PmtuBytes(IPV4_MINIMUM_PATH_MTU)
        override val unprobedPathMtu: PmtuBytes get() = PmtuBytes(IPV4_UNPROBED_PATH_MTU)
    }

    /** IPv6 (RFC 8200). */
    public data object Ipv6 : PathAddressFamily {
        override val minimumPathMtu: PmtuBytes get() = PmtuBytes(IPV6_MINIMUM_PATH_MTU)
        override val unprobedPathMtu: PmtuBytes get() = PmtuBytes(IPV6_MINIMUM_PATH_MTU)
    }
}

/**
 * What the association has been told about the path underneath it (RFC 8261 §6.1: *"If the SCTP layer is
 * notified about a path change by its lower layers, SCTP SHOULD retest the path MTU and reset the
 * congestion state to the initial state"* — this is the type that notification carries).
 *
 * Sealed rather than a nullable [Assessed], because [Unassessed] is not an absent profile: it is the
 * state a sans-io association is in when nothing above it has said which path it is riding, and in that
 * state it must behave exactly as it did before any of this existed. A `null` would have made "no profile"
 * and "a profile that happens to be missing" the same value at every read.
 */
public sealed interface SctpPathProfile {
    /**
     * Nobody has said anything about the path. The association falls back to `SctpConfig.maxPayloadBytes`
     * for fragmentation, which is the behaviour it had before path events existed — deliberately, so that
     * a driver which never sends [SctpEvent.PathChanged] is unaffected by this whole mechanism.
     */
    public data object Unassessed : SctpPathProfile

    /**
     * The session layer has named the path: which one ([identity]), what it stands on ([family]), and what
     * every packet on it pays below SCTP ([overhead]).
     *
     * The three together are what the association needs and the least it can be given. [identity] answers
     * "did it move", [family] answers "how big may an unprobed datagram be", and [overhead] converts the
     * second into a fragmentation ceiling. None is derivable from the others: the family is unchanged
     * across most migrations, and a relayed path and a direct one over the same interface differ in
     * overhead alone.
     */
    public data class Assessed(
        public val identity: PathIdentity,
        public val family: PathAddressFamily,
        public val overhead: PathOverheadBytes,
    ) : SctpPathProfile {
        /**
         * The fragmentation ceiling this path admits with **nothing probed** — the RFC 8261 §6.1 "retest
         * the path MTU" answer for an association that has not retested yet, and the value that closes the
         * IPv6 defect on its own (see [PathAddressFamily.unprobedPathMtu]).
         */
        public val unprobedFragmentCeiling: FragmentCeilingBytes
            get() = FragmentCeilingBytes.of(family.unprobedPathMtu, overhead)
    }
}

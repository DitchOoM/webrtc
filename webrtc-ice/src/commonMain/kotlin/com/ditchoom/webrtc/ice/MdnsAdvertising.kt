package com.ditchoom.webrtc.ice

import com.ditchoom.webrtc.stun.IpAddress
import kotlin.jvm.JvmInline
import kotlin.random.Random

/**
 * An mDNS host name (RFC 6762) — in this stack always the `<uuid>.local` privacy name of RFC 8828 §3.1.
 *
 * A value class, not a bare `String`: a name and a hostname-shaped candidate token are not
 * interchangeable, and the compiler is the only thing that reliably remembers that at four in the morning.
 * The wrapped text is the *full* name including the `.local` suffix, exactly as it rides the candidate line.
 */
@JvmInline
public value class MdnsHostName(
    public val value: String,
) {
    override fun toString(): String = value

    public companion object {
        /** The one link-local mDNS suffix (RFC 6762 §3). A name outside it is not ours to mint or answer. */
        public const val SUFFIX: String = ".local"

        /**
         * Mint a fresh RFC 4122 version-4 `<uuid>.local` name from [random] — the same shape Chrome, Firefox
         * and Safari publish, and deliberately carrying **nothing** about the machine: no hostname, no MAC,
         * no interface name, no time. The whole point of RFC 8828 is that the signaling server learns
         * nothing from the name, so anything derived from the host would defeat the feature it implements.
         *
         * [random] is the injected entropy seam (standing directive #2) — under `runTest` a seeded `Random`
         * makes the minted name reproducible, which is what lets a name appear in a deterministic fixture.
         */
        public fun random(random: Random): MdnsHostName {
            // RFC 4122 §4.4: 122 random bits, with the version (4) and variant (10xx) fields overwritten.
            val msb = (random.nextLong() and VERSION_CLEAR_MASK) or VERSION_4
            val lsb = (random.nextLong() and VARIANT_CLEAR_MASK) or VARIANT_RFC4122
            val timeLow = hex((msb ushr TIME_LOW_SHIFT).toULong() and WORD32_MASK, HEX_8)
            val timeMid = hex((msb ushr TIME_MID_SHIFT).toULong() and WORD16_MASK, HEX_4)
            val timeHigh = hex(msb.toULong() and WORD16_MASK, HEX_4)
            val clockSeq = hex((lsb ushr CLOCK_SEQ_SHIFT).toULong() and WORD16_MASK, HEX_4)
            val node = hex(lsb.toULong() and NODE_MASK, HEX_12)
            return MdnsHostName("$timeLow-$timeMid-$timeHigh-$clockSeq-$node$SUFFIX")
        }

        private fun hex(
            value: ULong,
            digits: Int,
        ): String = value.toString(HEX_RADIX).padStart(digits, '0')

        private const val HEX_RADIX = 16
        private const val HEX_4 = 4
        private const val HEX_8 = 8
        private const val HEX_12 = 12
        private const val TIME_LOW_SHIFT = 32
        private const val TIME_MID_SHIFT = 16
        private const val CLOCK_SEQ_SHIFT = 48
        private const val WORD16_MASK = 0xFFFFuL
        private const val WORD32_MASK = 0xFFFFFFFFuL
        private const val NODE_MASK = 0xFFFFFFFFFFFFuL
        private const val VERSION_CLEAR_MASK = -0xF001L // ~0x0000_0000_0000_F000 — clears the version nibble
        private const val VERSION_4 = 0x4000L
        private const val VARIANT_CLEAR_MASK = 0x3FFF_FFFF_FFFF_FFFFL // clears the two variant bits
        private const val VARIANT_RFC4122 = Long.MIN_VALUE // 0x8000_0000_0000_0000 — the `10xx` variant
    }
}

/**
 * The mDNS **advertise** seam (RFC 8828 privacy candidates) — the responder half of the [MdnsResolver] we
 * have shipped since #48, and the answer to #88.
 *
 * A browser hides its private IP behind an `<uuid>.local` host candidate precisely so that the signaling
 * server — and anyone else who sees the SDP — learns nothing about the private network. Without this seam
 * every candidate *we* publish carries a literal LAN address, which makes a page using this library
 * strictly less private on the wire than the same page using `RTCPeerConnection`.
 *
 * Injected, never hardwired: a production actual ([MulticastMdnsEndpoint], non-browser targets only) mints
 * a name, starts answering queries for it on `224.0.0.251` / `[ff02::fb]`, and returns the name to publish;
 * a test double returns a scripted name with no socket anywhere. Browsers need no actual — there
 * `peerConnectionSupport()` delegates to `RTCPeerConnection`, which obfuscates its own candidates.
 */
public fun interface MdnsAdvertiser {
    /**
     * Begin answering A / AAAA queries for a name bound to [address], and return the name to publish in
     * place of that address. Idempotent **per address, per session**: asking twice for the same address
     * yields the same name, so a candidate re-signaled (or re-gathered on the same socket) never appears
     * under two identities — which would tell an observer they belong to one host just as loudly as the
     * address would have.
     */
    public suspend fun advertise(address: IpAddress): MdnsAdvertisement
}

/**
 * What came of asking an [MdnsAdvertiser] to name an address — a sealed outcome rather than a nullable
 * name, so "advertised" always carries the name it minted and a refusal always carries why. The caller
 * `when`s over it: [Advertised] publishes the name, [Declined] publishes the literal address exactly as it
 * did before mDNS advertising existed.
 */
public sealed interface MdnsAdvertisement {
    /** The address is now answerable as [name]; publish that instead of the address. */
    public data class Advertised(
        public val name: MdnsHostName,
    ) : MdnsAdvertisement

    /** Nothing will answer for this address, so it must be published in the clear. */
    public data class Declined(
        public val reason: MdnsDeclineReason,
    ) : MdnsAdvertisement
}

/**
 * Why an [MdnsAdvertiser] would not name an address. Typed and exhaustive (directive #3): "the candidate
 * went out in the clear" is a privacy event, and a consumer that logs it deserves to know whether this
 * platform simply has no responder or a responder tried and failed to reach the group.
 */
public sealed interface MdnsDeclineReason {
    /**
     * No responder exists here — the `commonMain` default, and the honest answer on a target with no
     * multicast socket. Publishing a name nothing answers would be strictly worse than publishing the
     * address: the peer would resolve nothing and simply lose the candidate.
     */
    public data object NoResponder : MdnsDeclineReason

    /** A responder exists but could not bind or join the mDNS group on this address's family. */
    public data object GroupUnavailable : MdnsDeclineReason

    /** The responder holds no socket for this address's family (e.g. a v4-only lane asked to name a v6). */
    public data object UnsupportedFamily : MdnsDeclineReason
}

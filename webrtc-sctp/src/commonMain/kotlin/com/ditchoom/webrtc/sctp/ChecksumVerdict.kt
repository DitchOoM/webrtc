package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.ReadBuffer

/**
 * Where an [SctpPacket]'s bytes came from — and therefore whether there is anything to checksum.
 *
 * Replaces a nullable `source: ReadBuffer?` governing two companion `Int`s. That shape let
 * `source = null, sourceStart = 5, packetLength = 40` be constructed and said nothing about it: two
 * offsets into a buffer that does not exist. Only one of the three fields was ever consulted to decide
 * whether the other two meant anything, and every reader had to know that.
 *
 * Internal rather than public: which buffer a packet was decoded from is nobody's business outside this
 * module, and the one externally interesting consequence — "can this be checked at all" — is already
 * carried by [ChecksumVerdict.NotFromWire].
 */
internal sealed interface PacketOrigin {
    /**
     * Decoded from [buffer], occupying `[start, start + length)`. The span is retained so
     * [SctpPacket.validateChecksum] can re-read the exact bytes that arrived, in place — recomputing over
     * a re-encode would checksum what we *think* the peer sent rather than what it did.
     */
    data class Decoded(
        val buffer: ReadBuffer,
        val start: Int,
        val length: Int,
    ) : PacketOrigin

    /** Assembled locally by `SctpPacketBuilder`. There are no wire bytes, so there is nothing to verify. */
    data object Built : PacketOrigin
}

/**
 * The outcome of checking a packet's CRC32c (RFC 4960 §6.8) — four distinguishable results that a
 * `Boolean` collapsed to two.
 *
 * The collapse mattered in both directions. "False" meant *either* the checksum disagreed — a corrupt or
 * forged datagram, which RFC 4960 §6.8 says to discard silently — *or* the packet was never on a wire at
 * all, which is a caller mistake and cannot happen to received traffic. Those want opposite responses:
 * one is routine and unloggable, the other is a bug in this library. A single `false` is why the second
 * has never been distinguishable from the first at any call site.
 *
 * The fourth variant is the one that makes this worth doing before RFC 9653 arrives rather than with it:
 * a peer that has negotiated zero-checksum legitimately sends packets with the field set to 0 and no
 * CRC32c to compare against. That is neither "verified" nor "mismatch", and a Boolean has no room to say
 * so — the natural implementation returns `true` from a function named `verifyChecksum`, which is a lie
 * that reads as a bug forever after. Naming it now also means Track H adds a *producer* for an existing
 * variant instead of reshaping a sealed hierarchy that public API already depends on.
 */
public sealed interface ChecksumVerdict {
    /**
     * Whether the packet may be processed.
     *
     * Defined once, on the type, rather than at each call site — the whole point of separating
     * [AcceptedZero] from [Verified] is lost the moment somebody writes `verdict == Verified` and
     * silently drops every zero-checksum peer's traffic.
     */
    public val accepted: Boolean

    /** The recomputed CRC32c matched the value on the wire. */
    public data object Verified : ChecksumVerdict {
        override val accepted: Boolean get() = true
    }

    /**
     * The sender declared the RFC 9653 zero-checksum error-detection method and sent a zero checksum, so
     * there is nothing to recompute and the packet is accepted on the transport's own integrity guarantee
     * (for WebRTC, DTLS's AEAD — RFC 9653 §4).
     *
     * **Nothing produces this yet.** It is declared ahead of its producer deliberately; see the class
     * KDoc.
     */
    public data object AcceptedZero : ChecksumVerdict {
        override val accepted: Boolean get() = true
    }

    /**
     * The recomputed CRC32c disagreed with the wire. RFC 4960 §6.8 requires the packet be **discarded
     * silently** — it is not an error to report to the peer, because a corrupt packet's source address
     * and verification tag are exactly as untrustworthy as its payload.
     */
    public data object Mismatch : ChecksumVerdict {
        override val accepted: Boolean get() = false
    }

    /**
     * This packet was built locally rather than decoded, so no wire bytes exist to check. Distinct from
     * [Mismatch]: a received packet can never be this, so seeing it means a caller asked a question about
     * a packet that was never on a network.
     */
    public data object NotFromWire : ChecksumVerdict {
        override val accepted: Boolean get() = false
    }
}

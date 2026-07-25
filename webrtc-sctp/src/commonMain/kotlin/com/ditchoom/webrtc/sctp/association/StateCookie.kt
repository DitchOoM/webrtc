package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.codec.annotations.Endianness
import com.ditchoom.buffer.codec.annotations.ProtocolMessage
import com.ditchoom.webrtc.sctp.Tsn
import com.ditchoom.webrtc.sctp.VerificationTag

/**
 * The State Cookie an [SctpAssociation] mints in its INIT ACK (RFC 4960 §5.1.3) — the whole TCB of a
 * forming association, handed to the peer so the responder holds **no** state until the COOKIE ECHO
 * brings it back.
 *
 * Unlike every other structure in this module the layout here is **not** a wire format: the cookie is
 * opaque to the peer, which only ever echoes the bytes back. So it is ours to define, and it is defined
 * as a `@ProtocolMessage` — all nine fields are FixedSize, so KSP generates a straight-line
 * `StateCookieCodec` (internal, inheriting this class's visibility) that batches the reads and writes.
 * Hand-rolled offsets are exactly what this replaces: the previous version indexed the buffer at
 * `base + 17` / `base + 21` by hand, which is a silent-corruption bug waiting for the next field.
 *
 * [magic] stands in for the RFC's MAC. Over DTLS the transport has already authenticated the peer and
 * bounded the blast radius, so the cookie needs no HMAC of its own; a cookie without our magic is simply
 * one we did not mint, and RFC 4960 §5.1.5 says to discard it silently.
 *
 * [localTieTag] / [peerTieTag] are the RFC 4960 §5.2.2 Tie-Tags: a copy of the tags of the association
 * that was *already running* when this cookie was minted ([SctpAssociation.ZERO_TAG] when there was
 * none). They carry no meaning for the peer either — they exist so that when the cookie comes home,
 * §5.2.4's Table 2 can tell a peer that restarted (tags new, Tie-Tags naming our live association) from
 * an initialization collision, a late cookie, or a duplicate.
 */
@ProtocolMessage(wireOrder = Endianness.Big)
internal data class StateCookie(
    val magic: UInt,
    val peerTag: VerificationTag,
    val peerInitialTsn: Tsn,
    val peerRwnd: UInt,
    val peerForwardTsn: Boolean,
    val ourTag: VerificationTag,
    val ourInitialTsn: Tsn,
    val localTieTag: VerificationTag,
    val peerTieTag: VerificationTag,
) {
    companion object {
        /** Encoded size in bytes: magic + 4 tags + 2 TSNs + rwnd (4 each) and the 1-byte forward-TSN flag. */
        const val SIZE_BYTES: Int = 33

        /** "DitchOom Cookie" — the constant that marks a cookie as one we minted. */
        const val MAGIC: UInt = 0xD1C40C1Eu
    }
}

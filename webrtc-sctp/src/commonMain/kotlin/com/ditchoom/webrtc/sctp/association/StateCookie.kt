package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.codec.EncodeContext
import com.ditchoom.buffer.codec.annotations.Endianness
import com.ditchoom.buffer.codec.annotations.ProtocolMessage
import com.ditchoom.webrtc.sctp.ErrorDetectionMethodId
import com.ditchoom.webrtc.sctp.Tsn
import com.ditchoom.webrtc.sctp.VerificationTag

/**
 * The State Cookie an [SctpAssociation] mints in its INIT ACK (RFC 4960 §5.1.3) — the whole TCB of a
 * forming association, handed to the peer so the responder holds **no** state until the COOKIE ECHO
 * brings it back.
 *
 * Unlike every other structure in this module the layout here is **not** a wire format: the cookie is
 * opaque to the peer, which only ever echoes the bytes back. So it is ours to define, and it is defined
 * as a `@ProtocolMessage` — every field is FixedSize, so KSP generates a straight-line
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
    /**
     * The stream count this association settled on for inbound traffic: `min(our MIS, the peer's OS)`,
     * computed when the INIT arrived (RFC 4960 §5.1.1).
     *
     * It rides here for the same reason the capabilities do — the responder holds no TCB across the
     * handshake, so a number derived from the INIT is gone by the time the COOKIE ECHO returns. Deriving
     * it again from the echo is not an option: the echo carries no stream counts at all.
     */
    val peerMaxInbound: UShort,
    /**
     * Everything the peer's INIT advertised, as one packed field (see [PeerCapabilities]) rather than one
     * `Boolean` per extension. Extensions arrive in batches; fields do not merge, bits do.
     */
    val capabilities: PeerCapabilities,
    /**
     * The RFC 9653 §8 error-detection method the peer advertised, or [ErrorDetectionMethodId.Reserved]
     * when it advertised none.
     *
     * **Nothing populates this with a real method yet** — Track H adds the parameter codec that reads it
     * off the INIT. It is declared now because the cookie is the one structure in this module where
     * incremental widening is genuinely dangerous, and adding it later would mean touching the layout
     * twice: see the class KDoc on why that is worth avoiding once, let alone twice.
     */
    val peerZeroChecksum: ErrorDetectionMethodId,
    val ourTag: VerificationTag,
    val ourInitialTsn: Tsn,
    val localTieTag: VerificationTag,
    val peerTieTag: VerificationTag,
) {
    companion object {
        /**
         * The encoded size, **asked of the generated codec** rather than written down beside the fields.
         *
         * Every field is FixedSize, so `sizeHint` ignores the value it is given and returns a constant —
         * which is why probing with a zeroed cookie answers for all of them. The probe is built once, at
         * class-init, so this costs nothing per encode.
         *
         * It is derived rather than declared because a hand-maintained copy of this number is a trap with
         * no failure signal. Adding a field means bumping it, forgetting means the encode is truncated and
         * every echoed cookie is rejected — which surfaces as a handshake that times out with **nothing**
         * in the log to say why. Worse, several changes in flight at once each bump it by their own field's
         * width, and a textual merge keeps one bump instead of the sum. Deriving it removes the whole class:
         * the codec KSP generates from the fields is now the only place the layout is known.
         */
        val SIZE_BYTES: Int =
            StateCookieCodec.sizeHint(
                StateCookie(
                    magic = 0u,
                    peerTag = VerificationTag(0u),
                    peerInitialTsn = Tsn(0u),
                    peerRwnd = 0u,
                    peerMaxInbound = 0u,
                    capabilities = PeerCapabilities.None,
                    peerZeroChecksum = ErrorDetectionMethodId.Reserved,
                    ourTag = VerificationTag(0u),
                    ourInitialTsn = Tsn(0u),
                    localTieTag = VerificationTag(0u),
                    peerTieTag = VerificationTag(0u),
                ),
                EncodeContext.Empty,
            )

        /** "DitchOom Cookie" — the constant that marks a cookie as one we minted. */
        const val MAGIC: UInt = 0xD1C40C1Eu
    }
}

package com.ditchoom.webrtc.sctp

/**
 * What the layer **underneath** SCTP guarantees about the integrity of the bytes it carries — the
 * "alternate error detection method" of RFC 9653 §3, asked of the transport rather than assumed from the
 * platform.
 *
 * [CrcOnly] is the default everywhere, and it is a refusal rather than an absence: a transport that says
 * nothing gets CRC32c, which is exactly the RFC 4960 §6.8 behaviour that shipped before this existed. The
 * unsafe answer therefore requires a deliberate override, which is the only defence available — no type
 * can check that a transport claiming [Provided] actually authenticates its payload (the plan's residue
 * R4). A [Provided] transport is asserting RFC 9653 §3's two requirements on its own behalf: an equal or
 * lower false-negative probability than CRC32c, and no path failure from middleboxes expecting a correct
 * checksum.
 *
 * DTLS is the one this library ships (RFC 9653 §6): its records are AEAD-protected, and because a
 * middlebox never sees the SCTP header there is nothing on the path that could object to a zero in it.
 */
public sealed interface TransportErrorDetection {
    /** No guarantee beyond SCTP's own: every packet carries a real CRC32c, in both directions. */
    public data object CrcOnly : TransportErrorDetection

    /**
     * The transport detects errors by [method], an identifier from RFC 9653 §8's registry.
     *
     * [ErrorDetectionMethodId.Reserved] is refused at construction rather than tolerated: RFC 9653 §8
     * reserves 0 so that it never names a method, which is precisely what lets a zeroed State Cookie
     * field mean "the peer advertised nothing". A transport allowed to claim `Provided(Reserved)` would
     * compare equal to that absence, and a peer that advertised no method at all would be read as having
     * advertised ours.
     */
    public data class Provided(
        val method: ErrorDetectionMethodId,
    ) : TransportErrorDetection {
        init {
            require(method != ErrorDetectionMethodId.Reserved) {
                "RFC 9653 §8 reserves method identifier 0; it names no method and cannot be a transport's guarantee"
            }
        }
    }
}

/**
 * How far the upper layer is willing to go with RFC 9653 — the "MAY also require the upper layer to
 * indicate" hook of §5.1 and §5.2, which the RFC deliberately puts on *both* directions separately.
 *
 * Three states rather than a Boolean because accepting and emitting are independent decisions with
 * different risk profiles. Accepting costs nothing and cannot be observed by anyone but us: we simply
 * stop insisting on a checksum whose job the transport already does. Emitting is visible on the wire and
 * depends on a promise the *peer* made, so an operator may reasonably want the first without the second
 * while an interop question is open.
 *
 * [Disabled] is the default. RFC 9653 is an optimization, not a correctness fix, and a default that
 * changes what this library puts on the wire against every existing peer is not one a consumer asked for.
 */
public sealed interface ZeroChecksumPolicy {
    /** Never advertise, never emit — the RFC 4960 §6.8 behaviour, unchanged. */
    public data object Disabled : ZeroChecksumPolicy

    /** Advertise the transport's method so the peer may skip its CRC32c; still emit a real one ourselves. */
    public data object AcceptOnly : ZeroChecksumPolicy

    /** Advertise, and emit a zero checksum wherever the peer's own advertisement permits it. */
    public data object AcceptAndEmit : ZeroChecksumPolicy
}

/**
 * The **receive** direction, settled once per association: whether a packet that arrives with a zero in
 * the checksum field may be processed on the transport's guarantee alone (RFC 9653 §5.3).
 *
 * It is a projection of what *we advertised*, and of nothing else. §5.3 is explicit that the obligation
 * follows the parameter we sent — "if an endpoint has sent the Zero Checksum Acceptable Chunk Parameter
 * ... it MUST accept SCTP packets that have an incorrect checksum value of zero ... Otherwise, the
 * endpoint MUST drop all SCTP packets with an incorrect CRC32c checksum."
 *
 * This type and [OutboundChecksum] share no supertype **on purpose**. RFC 9653 negotiation is per
 * direction, and the whole failure mode this shape forecloses is a single "zero checksum is negotiated"
 * Boolean read from the wrong end: read as permission to send, every packet we emit is discarded by a
 * peer that never agreed to receive one, and the association dies looking exactly like a dead path. With
 * two unrelated types, `validateChecksum(outbound)` and `encode(factory, acceptance)` do not compile.
 */
public sealed interface ZeroChecksumAcceptance {
    /** We advertised nothing, so RFC 4960 §6.8 applies unchanged: a checksum that disagrees is a discard. */
    public data object RequireCrc32c : ZeroChecksumAcceptance

    /** We advertised [method] in our INIT or INIT ACK, so a zero checksum from this peer is acceptable. */
    public data class Advertised(
        val method: ErrorDetectionMethodId,
    ) : ZeroChecksumAcceptance
}

/**
 * The **send** direction, settled when the peer's advertisement arrives: whether this endpoint may leave
 * the checksum field at zero instead of computing a CRC32c over every outgoing packet (RFC 9653 §5.2).
 *
 * "Where permitted" is load-bearing and is not a hedge. Even with the peer's permission in hand, §5.2
 * still requires a correct CRC32c on a packet carrying an INIT, a COOKIE ECHO, an ASCONF, or a response
 * to an out-of-the-blue packet — so the permission is necessary and never sufficient. What the chunks in
 * a given packet permit is the other half of the decision, and the encoder combines the two.
 *
 * See [ZeroChecksumAcceptance] for why these two are not one type.
 */
public sealed interface OutboundChecksum {
    /** Compute and place a real CRC32c on every packet — the default, and what an unnegotiated peer gets. */
    public data object Crc32c : OutboundChecksum

    /** The peer advertised [method] and we support it, so packets not covered by §5.2 may carry a zero. */
    public data class ZeroWherePermitted(
        val method: ErrorDetectionMethodId,
    ) : OutboundChecksum
}

/**
 * What one INIT/INIT-ACK parameter turned out to be when read as an RFC 9653 §4 Zero Checksum Acceptable
 * parameter.
 *
 * Three outcomes rather than a nullable [ErrorDetectionMethodId], because "this is some other parameter"
 * and "this is our parameter and the peer built it wrong" are different facts about the peer, and only
 * the second is worth being able to see. Neither is a decode failure: type 0x8001's two high bits are
 * `10`, which RFC 9260 defines as skip-this-parameter-and-continue, so a malformed one may not abort the
 * chunk it rode in on.
 */
public sealed interface ZeroChecksumParameterDecode {
    /** Not type 0x8001 at all. */
    public data object NotZeroChecksum : ZeroChecksumParameterDecode

    /**
     * Type 0x8001, but not the shape RFC 9653 §4 defines: its Length field "MUST be 8" (a 4-byte TLV
     * header plus the 32-bit EDMID), and [declaredLength] is the wire Length that was there instead.
     */
    public data class Malformed(
        val declaredLength: Int,
    ) : ZeroChecksumParameterDecode

    /** The peer will accept a zero checksum from us if we can use error detection [method]. */
    public data class Advertised(
        val method: ErrorDetectionMethodId,
    ) : ZeroChecksumParameterDecode
}

/**
 * What we advertise, and therefore what we are obliged to accept (RFC 9653 §5.1, §5.3).
 *
 * The `CrcOnly` arm is one half of the safety property this whole file exists for, and it is a shape
 * rather than a check: a policy asking for zero checksums over a transport that guarantees nothing gets
 * [ZeroChecksumAcceptance.RequireCrc32c], because there is no alternate method to name in the parameter
 * and advertising one we cannot substantiate would invite a peer to send us packets nothing verifies.
 */
internal fun ZeroChecksumPolicy.acceptanceOver(transport: TransportErrorDetection): ZeroChecksumAcceptance =
    when (this) {
        ZeroChecksumPolicy.Disabled -> ZeroChecksumAcceptance.RequireCrc32c
        ZeroChecksumPolicy.AcceptOnly, ZeroChecksumPolicy.AcceptAndEmit ->
            when (transport) {
                TransportErrorDetection.CrcOnly -> ZeroChecksumAcceptance.RequireCrc32c
                is TransportErrorDetection.Provided -> ZeroChecksumAcceptance.Advertised(transport.method)
            }
    }

/**
 * Whether this endpoint may emit a zero checksum, given the method [peerAdvertised] in its INIT or INIT
 * ACK ([ErrorDetectionMethodId.Reserved] when it advertised none).
 *
 * The equality is the whole of RFC 9653 §5.2 restriction 1: permission depends on the peer naming a
 * method *we support*, which here means the one our own transport provides. A peer advertising an
 * identifier from some future registry entry is declined by this comparison rather than by an allow-list
 * — it costs us the optimization and nothing else, which is why an unknown identifier is data to compare
 * and not a parse failure.
 *
 * The second `Crc32c` arm is the other half of the safety property: [ZeroChecksumPolicy.AcceptAndEmit]
 * over a [TransportErrorDetection.CrcOnly] transport cannot reach a permission, because
 * `Reserved != Provided.method` is unreachable when there is no `Provided` to compare against.
 */
internal fun ZeroChecksumPolicy.emissionTo(
    peerAdvertised: ErrorDetectionMethodId,
    transport: TransportErrorDetection,
): OutboundChecksum =
    when (this) {
        ZeroChecksumPolicy.Disabled, ZeroChecksumPolicy.AcceptOnly -> OutboundChecksum.Crc32c
        ZeroChecksumPolicy.AcceptAndEmit ->
            when (transport) {
                TransportErrorDetection.CrcOnly -> OutboundChecksum.Crc32c
                is TransportErrorDetection.Provided ->
                    if (peerAdvertised == transport.method) {
                        OutboundChecksum.ZeroWherePermitted(peerAdvertised)
                    } else {
                        OutboundChecksum.Crc32c
                    }
            }
    }

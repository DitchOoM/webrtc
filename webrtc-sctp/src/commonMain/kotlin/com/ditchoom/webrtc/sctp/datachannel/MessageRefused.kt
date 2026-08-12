package com.ditchoom.webrtc.sctp.datachannel

/**
 * Why a `send` was refused before anything reached the wire (RFC 8841 §6 / RFC 8831 §6.6): the message
 * is larger than the peer said — or than we may assume — it will accept.
 *
 * Three variants for what is arithmetically one comparison, because the *reason* the ceiling is what it
 * is changes what a caller should do about it. A message over a ceiling the peer **stated** is an
 * application bug: the number was in the offer, and the fix is to send less. A message over the 64 KiB
 * RFC 8831 §6.6 assumes of a peer that stated **nothing** is not necessarily anything of the sort — the
 * peer may well accept it, we simply have no promise to rely on, and the fix may be to ask the peer to
 * advertise. A message refused while no remote description has been applied at all is neither; it is a
 * send racing negotiation. A single "too large" would report all three identically.
 *
 * [messageBytes] is `DataChannelPayload.wireByteCount`, never `String.length` — the distinction the whole
 * gate rests on, since a multi-byte message passes a character count and overruns the peer.
 */
public sealed interface MessageRefusedReason {
    /** The message's size on the wire, in bytes. */
    public val messageBytes: Long

    /**
     * The peer advertised [ceilingBytes] in its `a=max-message-size` (RFC 8841 §6) and this message is
     * larger. The promise is explicit and RFC 8831 §6.6 makes exceeding it a MUST NOT.
     */
    public data class ExceedsAdvertisedLimit(
        override val messageBytes: Long,
        public val ceilingBytes: Long,
    ) : MessageRefusedReason {
        init {
            require(messageBytes > ceilingBytes) {
                "a message of $messageBytes bytes does not exceed an advertised ceiling of $ceilingBytes"
            }
        }
    }

    /**
     * The peer described a data channel and advertised no ceiling, so RFC 8831 §6.6's
     * [PeerMessageLimit.ASSUMED_DEFAULT_BYTES] applies and this message is larger than that.
     *
     * The peer may accept it anyway — Pion advertises nothing and reassembles far more than 64 KiB — but
     * an assumption is the only thing available and the safe direction is the conservative one.
     */
    public data class ExceedsAssumedDefault(
        override val messageBytes: Long,
    ) : MessageRefusedReason {
        init {
            require(messageBytes > PeerMessageLimit.ASSUMED_DEFAULT_BYTES) {
                "a message of $messageBytes bytes does not exceed the assumed default of " +
                    "${PeerMessageLimit.ASSUMED_DEFAULT_BYTES}"
            }
        }
    }

    /**
     * No remote description has been applied, so the peer has not spoken at all — and a message this
     * large is safe under neither reading available. Refused against the same
     * [PeerMessageLimit.ASSUMED_DEFAULT_BYTES] as [ExceedsAssumedDefault], and reported separately
     * because the two are different situations: one peer said nothing, the other has not been heard from.
     *
     * A stack driven without a signaling layer at all — `SctpDataChannelStack` is a published module and
     * a peer's ceiling can be known by other means — says so with
     * [SctpDataChannelStack.setPeerMessageLimit] rather than living under this ceiling forever.
     */
    public data class PeerLimitUnknown(
        override val messageBytes: Long,
    ) : MessageRefusedReason {
        init {
            require(messageBytes > PeerMessageLimit.ASSUMED_DEFAULT_BYTES) {
                "a message of $messageBytes bytes is safe under every reading and must not be refused"
            }
        }
    }
}

/**
 * Thrown by a data-channel `send` whose message is larger than the peer will accept (RFC 8841 §6). The
 * typed [reason] is the discriminant; the message text is a diagnostic (directive #3).
 *
 * An `IllegalArgumentException`, not a transport failure, and deliberately: nothing went wrong on the
 * wire — nothing reached it. The association is untouched, the channel stays open, and the caller's own
 * buffer is never read, let alone consumed. Retrying the same message will fail the same way; sending a
 * smaller one will not.
 */
public class MessageRefusedException(
    public val reason: MessageRefusedReason,
) : IllegalArgumentException("data-channel message refused: $reason")

package com.ditchoom.webrtc

import com.ditchoom.webrtc.sctp.association.ReceiveMessageLimit
import com.ditchoom.webrtc.sctp.datachannel.PeerMessageLimit
import com.ditchoom.webrtc.sdp.MaxMessageSizeAttribute

/**
 * The peer's `a=max-message-size` (RFC 8841 §6) as the limit it binds us to (RFC 8831 §6.6).
 *
 * This is the one seam where the SDP *reading* becomes a *policy*, and the two are deliberately separate
 * types in separate modules: `webrtc-sdp` reports what the line said, and this decides what to do about
 * it. Folding §6.6's default into the reader would make the SHOULD unobservable; folding the reader's
 * cases into the policy would lose the raw text a malformed line carries.
 *
 * Three of the four arms are the obvious mapping. The fourth is the one worth stating:
 * [MaxMessageSizeAttribute.Malformed] becomes [PeerMessageLimit.AssumedDefault], i.e. it is treated
 * exactly as silence. Exceeding a peer's stated limit is a MUST NOT, so an unreadable statement must
 * collapse to the tightest reading it could have had — never to [PeerMessageLimit.Unlimited], which is
 * where a "we could not parse it, so there is no limit" reading would land. A digit string past
 * `Long.MAX_VALUE` is `Malformed` rather than a huge `Bytes`, which is precisely the input that makes
 * the wrong mapping look plausible.
 *
 * There is no zero arm because there is no zero: `MaxMessageSizeAttribute.Bytes` requires at least one
 * byte at construction, and the wire's `0` is already [MaxMessageSizeAttribute.Unlimited].
 */
public fun MaxMessageSizeAttribute.asPeerMessageLimit(): PeerMessageLimit =
    when (this) {
        MaxMessageSizeAttribute.Absent -> PeerMessageLimit.AssumedDefault
        is MaxMessageSizeAttribute.Malformed -> PeerMessageLimit.AssumedDefault
        MaxMessageSizeAttribute.Unlimited -> PeerMessageLimit.Unlimited
        is MaxMessageSizeAttribute.Bytes -> PeerMessageLimit.Advertised(value)
    }

/**
 * The `a=max-message-size` value to emit for [limit] (RFC 8841 §6) — the inverse of the read above.
 *
 * [ReceiveMessageLimit.Unbounded] emits `0`, which is the RFC's spelling for "any size this
 * implementation can handle" and *not* a ceiling of nothing. That inversion is exactly what the sealed
 * type exists to keep out of arithmetic, so it appears once, here, at the wire.
 */
internal fun advertisedMaxMessageSize(limit: ReceiveMessageLimit): Long =
    when (limit) {
        ReceiveMessageLimit.Unbounded -> 0L
        is ReceiveMessageLimit.Bytes -> limit.value
    }

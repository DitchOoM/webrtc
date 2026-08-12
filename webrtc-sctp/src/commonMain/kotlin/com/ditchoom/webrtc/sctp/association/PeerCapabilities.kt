package com.ditchoom.webrtc.sctp.association

import kotlin.jvm.JvmInline

/**
 * The extensions a peer's INIT advertised, packed into the State Cookie's capability octet.
 *
 * The cookie is where these have to live: RFC 4960 §5.1.3 has the responder keep **no** TCB between the
 * INIT and the COOKIE ECHO, so anything the INIT said is forgotten unless the cookie carries it — and an
 * endpoint that forgot the peer supports RE-CONFIG MUST NOT send RE-CONFIG. That is why this is a
 * serialized field rather than association state.
 *
 * A packed octet rather than one `Boolean` field per extension, and the reason is the merge rather than
 * the byte. Every extension added to this protocol wants a cookie field, and the plan this change belongs
 * to has three of them arriving in the same change set. One `Boolean` each means three independent
 * widenings of the same structure; one octet means three bit assignments that a textual merge either
 * combines correctly or conflicts on visibly. The octet has room for eight, which is more than the
 * dcSCTP subset will ever negotiate.
 *
 * Unset bits read as "not advertised", which is the safe default for every extension here — RFC 3758 and
 * RFC 6525 are both opt-in, and an endpoint that wrongly believes a peer supports one sends a chunk the
 * peer will answer with an ERROR.
 */
@JvmInline
internal value class PeerCapabilities(
    val bits: UShort,
) {
    /** RFC 3758 partial reliability: the peer advertised Forward-TSN-Supported. */
    val forwardTsn: Boolean get() = isSet(FORWARD_TSN)

    /** RFC 6525 stream reconfiguration: the peer advertised the RE-CONFIG chunk. */
    val reConfig: Boolean get() = isSet(RE_CONFIG)

    private fun isSet(bit: UShort): Boolean = (bits and bit) != NONE

    companion object {
        private const val FORWARD_TSN_BIT = 1
        private const val RE_CONFIG_BIT = 2

        private val NONE: UShort = 0u
        private val FORWARD_TSN: UShort = FORWARD_TSN_BIT.toUShort()
        private val RE_CONFIG: UShort = RE_CONFIG_BIT.toUShort()

        /** Nothing advertised — the only safe default, and what a zeroed cookie decodes to. */
        val None: PeerCapabilities = PeerCapabilities(NONE)

        fun of(
            forwardTsn: Boolean,
            reConfig: Boolean,
        ): PeerCapabilities {
            var bits = NONE
            if (forwardTsn) bits = bits or FORWARD_TSN
            if (reConfig) bits = bits or RE_CONFIG
            return PeerCapabilities(bits)
        }
    }
}

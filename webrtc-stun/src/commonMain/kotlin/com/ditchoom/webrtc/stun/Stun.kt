package com.ditchoom.webrtc.stun

/**
 * STUN protocol constants (RFC 8489). The message/attribute codecs live in [StunHeader],
 * [StunMessage], and [StunAttribute]; the sans-io client machine in [StunTransaction].
 */
public object Stun {
    public const val MODULE: String = "webrtc-stun"

    /**
     * The STUN magic cookie (RFC 8489 §5) — the fixed 32-bit value in bytes 4..7 of every message,
     * also the XOR seed's high half for XOR-MAPPED-ADDRESS. A named constant, never a bare literal.
     */
    public const val MAGIC_COOKIE: UInt = 0x2112A442u

    /** The magic cookie's two high bytes, used as the XOR key for a mapped port (RFC 8489 §14.2). */
    public const val MAGIC_COOKIE_HIGH_SHORT: UShort = 0x2112u
}

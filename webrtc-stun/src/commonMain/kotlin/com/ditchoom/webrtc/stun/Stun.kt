package com.ditchoom.webrtc.stun

import kotlin.jvm.JvmInline

/**
 * W1 placeholder (see EXECUTION_PLAN.md). The real module is a `buffer-codec` KSP schema plus a
 * sans-io transaction machine; nothing here is wire-final. It exists so the empty module tree
 * builds, publishes a 0.0.x, and demonstrates the house style the STUN codec will follow.
 */
public object Stun {
    public const val MODULE: String = "webrtc-stun"

    /** STUN magic cookie (RFC 8489 §5). A named constant, never a bare literal at a call site. */
    public const val MAGIC_COOKIE: Int = 0x2112A442.toInt()
}

/**
 * The 96-bit STUN transaction id, wrapped so it can never be confused with any other identifier or
 * with a raw string. Represented as its 24-char hex here (placeholder); the real type will be a
 * zero-copy view over the datagram buffer, not a [ByteArray]. (Standing directive: value-class ids.)
 */
@JvmInline
public value class TransactionId(
    public val hex: String,
) {
    init {
        require(hex.length == HEX_LENGTH) { "STUN transaction id is 96 bits = $HEX_LENGTH hex chars, got ${hex.length}" }
    }

    public companion object {
        public const val HEX_LENGTH: Int = 24
    }
}

/**
 * STUN message class (RFC 8489 §5) — an exhaustive set. Modeled so a `when` over it needs no `else`,
 * and no combination of booleans can encode an illegal fifth class. (Standing directive: sealed,
 * exhaustive, no impossible states.)
 */
public enum class StunClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

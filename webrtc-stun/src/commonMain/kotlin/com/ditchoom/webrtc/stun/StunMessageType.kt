package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.codec.annotations.Endianness
import com.ditchoom.buffer.codec.annotations.ProtocolMessage
import kotlin.jvm.JvmInline

/**
 * The STUN message class (RFC 8489 §5) — the 2-bit `C1 C0` field interleaved into the message type.
 * A genuinely dataless closed set, so an enum (DESIGN_PRINCIPLES §3); the ordinals are the on-wire
 * 2-bit class values (`0b00 Request … 0b11 ErrorResponse`), which [StunMessageType] relies on.
 */
public enum class StunClass {
    Request, // 0b00
    Indication, // 0b01
    SuccessResponse, // 0b10
    ErrorResponse, // 0b11
}

/**
 * A STUN method (RFC 8489 §5) — the 12-bit method number, wrapped so it can never be confused with a
 * bare `Int`/`UShort` or with the full [StunMessageType]. Binding is the only core-STUN method; the
 * rest are TURN (RFC 8656), carried here because TURN rides the same message framing.
 */
@JvmInline
public value class StunMethod(
    public val value: UShort,
) {
    init {
        require(value <= MAX) { "STUN method is 12 bits (0..0x0FFF), got 0x${value.toString(HEX)}" }
    }

    public companion object {
        /** Widest 12-bit method value. */
        public const val MAX_VALUE: Int = 0x0FFF
        private const val MAX: UShort = 0x0FFFu
        private const val HEX: Int = 16

        /** STUN Binding (RFC 8489 §3). */
        public val Binding: StunMethod = StunMethod(0x001u)

        // TURN methods (RFC 8656 §5) — codec-only in W1.
        public val Allocate: StunMethod = StunMethod(0x003u)
        public val Refresh: StunMethod = StunMethod(0x004u)
        public val Send: StunMethod = StunMethod(0x006u)
        public val Data: StunMethod = StunMethod(0x007u)
        public val CreatePermission: StunMethod = StunMethod(0x008u)
        public val ChannelBind: StunMethod = StunMethod(0x009u)
    }
}

/**
 * The 16-bit STUN message type (RFC 8489 §5): two leading zero bits, then a [StunMethod] (12 bits)
 * and a [StunClass] (2 bits) **bit-interleaved** — the method bits straddle the two class bits at
 * positions 4 and 8. Modeled as a `value class` over the raw `UShort` so the wire form is exact and
 * zero-cost, with [stunClass]/[method] computed by de-interleaving. Illegal states are unrepresentable:
 * every raw `UShort` with the two high bits clear maps to exactly one (class, method) pair and back.
 *
 * `@ProtocolMessage` over a scalar makes this a 2-byte FixedSize field the generated [StunHeader]
 * codec reads and writes directly.
 */
@JvmInline
@ProtocolMessage(wireOrder = Endianness.Big)
public value class StunMessageType(
    public val raw: UShort,
) {
    init {
        require(raw.toInt() and TWO_HIGH_BITS == 0) {
            "STUN message type must have the two leading bits clear, got 0x${raw.toString(HEX)}"
        }
    }

    /** The 2-bit class, decoded from bits 4 and 8. */
    public val stunClass: StunClass
        get() {
            val r = raw.toInt()
            val c = ((r and C1_BIT) shr C1_SHIFT) or ((r and C0_BIT) shr C0_SHIFT)
            return StunClass.entries[c]
        }

    /** The 12-bit method, decoded from the three method bit-runs around the class bits. */
    public val method: StunMethod
        get() {
            val r = raw.toInt()
            val m = (r and M_LOW) or ((r and M_MID) shr 1) or ((r and M_HIGH) shr 2)
            return StunMethod(m.toUShort())
        }

    public companion object {
        private const val HEX: Int = 16
        private const val TWO_HIGH_BITS = 0xC000

        // Class bit positions within the 16-bit type (RFC 8489 §5): C1 at bit 8, C0 at bit 4.
        private const val C1_BIT = 0x0100
        private const val C0_BIT = 0x0010
        private const val C1_SHIFT = 7 // C1 (0x0100) contributes the 0b10 class bit
        private const val C0_SHIFT = 4 // C0 (0x0010) contributes the 0b01 class bit

        // Method bit-runs: M3..M0 (bits 0-3), M6..M4 (bits 5-7), M11..M7 (bits 9-13).
        private const val M_LOW = 0x000F
        private const val M_MID = 0x00E0
        private const val M_HIGH = 0x3E00

        /** Builds a message type from its [stunClass] and [method], interleaving per RFC 8489 §5. */
        public fun of(
            stunClass: StunClass,
            method: StunMethod,
        ): StunMessageType {
            val m = method.value.toInt()
            val c = stunClass.ordinal
            val raw =
                (m and M_LOW) or
                    ((m and 0x0070) shl 1) or
                    ((m and 0x0F80) shl 2) or
                    ((c and 0b10) shl C1_SHIFT) or
                    ((c and 0b01) shl C0_SHIFT)
            return StunMessageType(raw.toUShort())
        }
    }
}

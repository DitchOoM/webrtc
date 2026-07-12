package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.codec.annotations.Endianness
import com.ditchoom.buffer.codec.annotations.ProtocolMessage
import kotlin.random.Random

/**
 * The 96-bit STUN transaction id (RFC 8489 §5), modeled as three network-order 32-bit words rather
 * than a `ByteArray` — it is a map key in the transaction machine, so it needs value equality and a
 * hash without a primitive array (standing directive #1) and without a copy out of the datagram.
 *
 * `@ProtocolMessage` makes it a 12-byte FixedSize field the generated [StunHeader] codec reads and
 * writes inline. It is decoded by value (a 96-bit id is small and outlives the datagram as a key),
 * which is the one deliberate exception to view-parsing in this module — everything larger stays a
 * slice view.
 */
@ProtocolMessage(wireOrder = Endianness.Big)
public data class TransactionId(
    public val w0: UInt,
    public val w1: UInt,
    public val w2: UInt,
) {
    /** Lowercase 24-char hex, for diagnostics only (never a wire or equality path). */
    public fun toHex(): String = w0.toHexPadded() + w1.toHexPadded() + w2.toHexPadded()

    private fun UInt.toHexPadded(): String = toString(HEX).padStart(WORD_HEX, '0')

    public companion object {
        private const val HEX = 16
        private const val WORD_HEX = 8

        /**
         * A fresh transaction id from injected entropy (standing directive #2 — the caller passes the
         * seam; production supplies `CryptoRandom`, tests a seeded [Random], so ids are replayable).
         */
        public fun random(random: Random): TransactionId =
            TransactionId(random.nextInt().toUInt(), random.nextInt().toUInt(), random.nextInt().toUInt())
    }
}

package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed

/**
 * Pure-Kotlin streaming MD5 (RFC 1321), **internal on purpose**.
 *
 * This exists for exactly one reason: RFC 8489 §9.2.2 defines the long-term-credential *key* as
 * `MD5(username ":" realm ":" password)`, so a TURN client that must interoperate with a real server
 * has no choice of digest. It is **key derivation mandated by the wire format, not a security hash** —
 * do not "upgrade" it to SHA-256, and do not reach for it as a general-purpose digest. That is why it
 * is `internal` and why the only public surface is [longTermCredentialKey].
 *
 * Why here rather than in `buffer-crypto`: that module models every digest as an `expect class` with
 * four actuals, and **WebCrypto has no MD5** (the spec defines only SHA-1/2), so an upstream MD5 would
 * need a pure-Kotlin core anyway — the same pressure that produced buffer's `Sha256Core`. One common
 * implementation covers all seven targets with no expect/actual, and cannot be refused by a FIPS-mode
 * JVM the way `MessageDigest.getInstance("MD5")` can.
 *
 * Holds **no primitive arrays** (standing directive #1): the 64-byte message block lives in a single
 * little-endian managed [work] buffer read word-at-a-time via absolute `getInt`, the chaining state is
 * four `UInt` fields, and the round constants and shift schedule are shared read-only buffers.
 *
 * Not thread-safe — one instance per digest.
 */
internal class Md5Core {
    private var h0 = 0x67452301u
    private var h1 = 0xefcdab89u
    private var h2 = 0x98badcfeu
    private var h3 = 0x10325476u

    // The 64-byte message block. Little-endian: MD5 reads its 16 schedule words as LE (RFC 1321 §2)
    // and appends the message length as a 64-bit LE bit count, so the buffer's byte order does both.
    private val work: PlatformBuffer = BufferFactory.managed().allocate(BLOCK_BYTES, ByteOrder.LITTLE_ENDIAN)
    private var blockLen = 0
    private var totalBytes = 0L

    /** Absorbs the remaining bytes of [input] without disturbing its position. */
    fun update(input: ReadBuffer) {
        val start = input.position()
        val end = input.limit()
        var i = start
        while (i < end) {
            absorbByte(input.get(i))
            i++
        }
    }

    /** Absorbs a single byte. */
    fun absorbByte(b: Byte) {
        work.set(blockLen, b)
        blockLen++
        if (blockLen == BLOCK_BYTES) {
            processBlock()
            blockLen = 0
        }
        totalBytes++
    }

    /** Pads and finalizes; afterwards [digestByte] returns the digest bytes. */
    fun finish() {
        val bitLen = totalBytes * BITS_PER_BYTE
        work.set(blockLen, 0x80.toByte())
        blockLen++
        if (blockLen > BLOCK_BYTES - LENGTH_FIELD_BYTES) {
            while (blockLen < BLOCK_BYTES) {
                work.set(blockLen, 0.toByte())
                blockLen++
            }
            processBlock()
            blockLen = 0
        }
        while (blockLen < BLOCK_BYTES - LENGTH_FIELD_BYTES) {
            work.set(blockLen, 0.toByte())
            blockLen++
        }
        work.set(BLOCK_BYTES - LENGTH_FIELD_BYTES, bitLen) // 64-bit little-endian bit length at bytes 56..63
        processBlock()
    }

    /** Digest byte [i] (0..15), valid only after [finish]. MD5 emits each word little-endian. */
    fun digestByte(i: Int): Byte {
        val word =
            when (i ushr 2) {
                0 -> h0
                1 -> h1
                2 -> h2
                else -> h3
            }
        return (word shr (BITS_PER_BYTE * (i and BYTE_INDEX_MASK))).toByte()
    }

    private fun processBlock() {
        var a = h0
        var b = h1
        var c = h2
        var d = h3

        for (i in 0 until ROUNDS) {
            // The four round functions and their message-word orders (RFC 1321 §3.4). `and
            // WORD_INDEX_MASK` is the spec's `mod 16` — the schedule index is never negative.
            val f: UInt
            val g: Int
            when {
                i < ROUND_2_START -> {
                    f = (b and c) or (b.inv() and d)
                    g = i
                }
                i < ROUND_3_START -> {
                    f = (d and b) or (d.inv() and c)
                    g = (5 * i + 1) and WORD_INDEX_MASK
                }
                i < ROUND_4_START -> {
                    f = b xor c xor d
                    g = (3 * i + 5) and WORD_INDEX_MASK
                }
                else -> {
                    f = c xor (b or d.inv())
                    g = (7 * i) and WORD_INDEX_MASK
                }
            }
            val sum = a + f + K.getInt(i * WORD_BYTES).toUInt() + work.getInt(g * WORD_BYTES).toUInt()
            a = d
            d = c
            c = b
            b += sum.rotateLeft(SHIFTS.get(i).toInt())
        }

        h0 += a
        h1 += b
        h2 += c
        h3 += d
    }

    companion object {
        const val MD5_DIGEST_BYTES = 16

        private const val BLOCK_BYTES = 64 // MD5 operates on 512-bit blocks
        private const val LENGTH_FIELD_BYTES = 8 // trailing 64-bit little-endian message length
        private const val ROUNDS = 64
        private const val ROUND_2_START = 16 // round-function boundaries (RFC 1321 §3.4)
        private const val ROUND_3_START = 32
        private const val ROUND_4_START = 48
        private const val WORD_BYTES = 4
        private const val WORD_INDEX_MASK = 15 // schedule index mod 16
        private const val BITS_PER_BYTE = 8
        private const val BYTE_INDEX_MASK = 3 // i mod 4 → byte within the word
        private const val HEX_RADIX = 16
        private const val K_BYTES = 256 // 64 round constants × 4 bytes

        // T[i] = floor(2^32 × |sin(i + 1)|) for i in 0..63 (RFC 1321 §3.4), in a shared read-only
        // big-endian buffer: written and read back as whole words, so the container's order only has
        // to round-trip. (The *message* words are the ones that must be little-endian — see [work].)
        private const val K_HEX =
            "d76aa478e8c7b756242070dbc1bdceeef57c0faf4787c62aa8304613fd469501" +
                "698098d88b44f7afffff5bb1895cd7be6b901122fd987193a679438e49b40821" +
                "f61e2562c040b340265e5a51e9b6c7aad62f105d02441453d8a1e681e7d3fbc8" +
                "21e1cde6c33707d6f4d50d87455a14eda9e3e905fcefa3f8676f02d98d2a4c8a" +
                "fffa39428771f6816d9d6122fde5380ca4beea444bdecfa9f6bb4b60bebfbc70" +
                "289b7ec6eaa127fad4ef308504881d05d9d4d039e6db99e51fa27cf8c4ac5665" +
                "f4292244432aff97ab9423a7fc93a039655b59c38f0ccc92ffeff47d85845dd1" +
                "6fa87e4ffe2ce6e0a30143144e0811a1f7537e82bd3af2352ad7d2bbeb86d391"

        // Per-round left-rotation amounts (RFC 1321 §3.4): 7,12,17,22 / 5,9,14,20 / 4,11,16,23 /
        // 6,10,15,21, each group repeated four times. One byte per round.
        private const val SHIFTS_HEX =
            "070c1116070c1116070c1116070c1116" +
                "05090e1405090e1405090e1405090e14" +
                "040b1017040b1017040b1017040b1017" +
                "060a0f15060a0f15060a0f15060a0f15"

        private val K: ReadBuffer = hexBuffer(K_HEX, K_BYTES, ByteOrder.BIG_ENDIAN)
        private val SHIFTS: ReadBuffer = hexBuffer(SHIFTS_HEX, ROUNDS, ByteOrder.BIG_ENDIAN)

        private fun hexBuffer(
            hex: String,
            byteCount: Int,
            order: ByteOrder,
        ): PlatformBuffer =
            BufferFactory.managed().allocate(byteCount, order).apply {
                for (i in 0 until byteCount) set(i, hex.substring(i * 2, i * 2 + 2).toInt(HEX_RADIX).toByte())
            }
    }
}

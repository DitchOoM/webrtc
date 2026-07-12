package com.ditchoom.webrtc.stun.fuzz

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.stun.RawAttribute
import com.ditchoom.webrtc.stun.StunDecodeResult
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.asErrorCode
import com.ditchoom.webrtc.stun.asText
import com.ditchoom.webrtc.stun.asTransportAddress
import com.ditchoom.webrtc.stun.asXorMappedAddress

/**
 * Coverage-guided **Jazzer** fuzz target over the STUN decoder (RFC 8489) — the module's real
 * adversarial surface. The code under test is **pure Kotlin**, so Jazzer's JVM instrumentation gives
 * genuine edge coverage of the header decode, TLV walk, and in-place MESSAGE-INTEGRITY / FINGERPRINT
 * checks — a true coverage-guided fuzzer, not just a crash harness.
 *
 * **Invariant** (T0, stronger than a typed-exception model): [StunMessage.decode] is **total** — for
 * *any* input it returns [StunDecodeResult.Success] or [StunDecodeResult.Reject], never a throw. And
 * every operation reachable on a decoded message — re-encode, both integrity verifications, and every
 * typed attribute interpreter — must also not throw on attacker-shaped content. So this target wraps
 * nothing in a `try`: ANY `Throwable` (buffer underflow, IOOBE, NPE, `IllegalArgumentException`, OOM,
 * hang) bubbles out of [fuzzerTestOneInput] and Jazzer records a `crash-*` repro. This is the dynamic
 * counterpart to the seeded `StunMalformedCorpusTest` totality property.
 *
 * Run it via the `stunCodecFuzz` Gradle task. The target uses the `byte[]` entry-point form, so it has
 * no compile-time dependency on Jazzer — Jazzer is only on the runtime classpath of that task.
 * Intentionally not a `@Test`: a JUnit run would call it once with no input.
 */
object StunCodecFuzzer {
    private const val INPUT_CAP = 2048
    private val factory = BufferFactory.Default

    // A fixed key so MESSAGE-INTEGRITY verification exercises the HMAC path deterministically.
    private val key: ReadBuffer =
        factory.allocate(16, ByteOrder.BIG_ENDIAN).apply {
            writeString("fuzz-integrity-k")
            resetForRead()
        }

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val len = if (data.size > INPUT_CAP) INPUT_CAP else data.size
        if (len == 0) return
        // The single byte[] → buffer conversion at the driver ABI boundary; everything below is buffers.
        val source =
            factory.allocate(len, ByteOrder.BIG_ENDIAN).apply {
                writeBytes(data, 0, len)
                resetForRead()
            }

        when (val result = StunMessage.decode(source)) {
            is StunDecodeResult.Reject -> Unit // a typed reject is the correct outcome, not a finding
            is StunDecodeResult.Success -> exercise(result.message)
        }
    }

    // Everything reachable on a successfully decoded message must be crash-free on hostile content.
    private fun exercise(message: StunMessage) {
        message.encode() // re-serialization must not throw
        message.verifyFingerprint() // CRC-32 over the decoded span
        message.verifyMessageIntegrity(key) // HMAC-SHA1 slicing + compare
        for (attr in message.attributes) {
            attr.asText()
            attr.asTransportAddress()
            attr.asXorMappedAddress(message.transactionId)
            attr.asErrorCode()
            drainValueView(attr)
        }
    }

    // Touch the raw value view end-to-end so any slice/offset bug on a malformed length surfaces.
    private fun drainValueView(attr: RawAttribute) {
        val v = attr.value
        var i = 0
        val n = v.remaining()
        while (i < n) {
            v.get(v.position() + i)
            i++
        }
    }
}

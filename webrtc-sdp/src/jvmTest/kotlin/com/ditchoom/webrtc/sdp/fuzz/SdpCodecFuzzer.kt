package com.ditchoom.webrtc.sdp.fuzz

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.webrtc.sdp.SdpParseResult
import com.ditchoom.webrtc.sdp.SessionDescription
import com.ditchoom.webrtc.sdp.fingerprints
import com.ditchoom.webrtc.sdp.icePwd
import com.ditchoom.webrtc.sdp.iceUfrag
import com.ditchoom.webrtc.sdp.setup

/**
 * Coverage-guided **Jazzer** fuzz target over the SDP parser (RFC 8866) — the module's real
 * adversarial surface. The code under test is **pure Kotlin**, so Jazzer's JVM instrumentation gives
 * genuine edge coverage of the line walk, the session/media split, and every typed field interpreter
 * (`origin`, `mediaLine`, `fingerprints`, `setup`, `sctpPort`, …).
 *
 * **Invariant** (T0, stronger than a typed-exception model): [SessionDescription.parse] is **total** —
 * for *any* input it returns `Success` or `Reject`, never a throw. And every operation reachable on a
 * decoded description — re-serialize (`toText`/`encode`) and every typed interpreter — must also not
 * throw on attacker-shaped content. So this target wraps nothing in a `try`: ANY `Throwable` (buffer
 * underflow, IOOBE, NPE, `IllegalArgumentException`, OOM, hang) bubbles out of [fuzzerTestOneInput]
 * and Jazzer records a `crash-*` repro. This is the dynamic counterpart to the seeded
 * `SdpMalformedCorpusTest` totality property.
 *
 * Run it via the `sdpCodecFuzz` Gradle task. The target uses the `byte[]` entry-point form, so it has
 * no compile-time dependency on Jazzer — Jazzer is only on the runtime classpath of that task.
 * Intentionally not a `@Test`: a JUnit run would call it once with no input.
 */
object SdpCodecFuzzer {
    private const val INPUT_CAP = 8192
    private val factory = BufferFactory.Default

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val len = if (data.size > INPUT_CAP) INPUT_CAP else data.size
        if (len == 0) return
        // The single byte[] → buffer conversion at the driver ABI boundary; everything below is buffers.
        val source =
            factory.allocate(len, ByteOrder.BIG_ENDIAN).apply {
                writeBytes(data, 0, len)
                resetForRead()
                setLimit(len)
            }

        when (val result = SessionDescription.parse(source)) {
            is SdpParseResult.Reject -> Unit // a typed reject is the correct outcome, not a finding
            is SdpParseResult.Success -> exercise(result.description)
        }
    }

    // Everything reachable on a successfully parsed description must be crash-free on hostile content.
    private fun exercise(sdp: SessionDescription) {
        sdp.toText() // re-serialization must not throw
        sdp.encode() // datagram serialization must not throw
        sdp.origin()
        sdp.sessionName()
        sdp.bundleGroups()
        sdp.fingerprints()
        sdp.setup()
        for (m in sdp.mediaDescriptions) {
            m.mediaLine()
            m.mid()
            m.iceUfrag()
            m.icePwd()
            m.setup()
            m.fingerprints()
            m.sctpPort()
            m.maxMessageSize()
            m.candidates()
            m.hasEndOfCandidates()
            m.isBundleOnly()
        }
    }
}

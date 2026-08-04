package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.managed
import com.ditchoom.buffer.nativeMemoryAccess
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * [networkBuffer] is the answer to "which factory can this platform's socket actually send from"
 * (issue #125). The invariant is one-directional and holds on **every** target, which is why these run
 * in `commonTest` rather than beside the Linux actual that motivated them.
 */
class NetworkBufferTest {
    /**
     * The load-bearing property. A buffer with no native address is rejected outright by socket-udp's
     * io_uring `sendmsg` and `NWConnection` send paths, so whatever this returns must have one — on the
     * platform the test is currently running on, whichever that is.
     */
    @Test
    fun network_buffer_always_backs_its_buffers_with_native_memory() {
        val probe = networkBuffer().allocate(1)
        assertNotNull(
            probe.nativeMemoryAccess,
            "networkBuffer() returned a factory with no native address — socket-udp's Linux and Apple " +
                "send paths reject it (`send requires a native-memory buffer`)",
        )
    }

    /**
     * Anti-vacuity for the test above: [backsNativeMemory] genuinely discriminates, rather than passing
     * because every factory happens to look native.
     *
     * Skipped on js, where `managedBufferFactory` **is** `defaultBufferFactory` — the platform has one
     * buffer type, so no factory can be distinguished from any other and the property is unfalsifiable
     * by construction rather than by accident. That costs nothing: a browser delegates to
     * `RTCPeerConnection` (ARCHITECTURE §1.1) and never hands one of these buffers to a socket. Every
     * platform that *can* reach a socket — jvm, android, apple, linux, wasmJs — runs the assertion.
     */
    @Test
    fun the_probe_rejects_a_heap_factory() {
        if (BufferFactory.managed() === BufferFactory.Default) return
        assertTrue(
            !BufferFactory.managed().backsNativeMemory(),
            "managed() is a GC-heap ByteArrayBuffer here — a probe that calls it native cannot tell a " +
                "sendable factory from an unsendable one",
        )
    }

    /**
     * Where `Default` is already correct — Apple (ARC), JVM 21 (auto-arena), Android (Cleaner-backed
     * direct), wasm (linear memory) — it must be returned **unchanged**, keeping automatic reclamation.
     * A flat alias to `deterministic()` would pass the native check above while silently moving those
     * targets onto manual frees, so this is the half that pins the choice rather than the capability.
     */
    @Test
    fun default_is_preserved_wherever_it_is_already_native() {
        if (!BufferFactory.Default.backsNativeMemory()) return // Kotlin/Native Linux: fallback expected
        assertSame(
            BufferFactory.Default,
            networkBuffer(),
            "Default is native-backed on this platform, so networkBuffer() must not downgrade it to a " +
                "manually-freed factory",
        )
    }

    /** Resolved once and cached — the probe is an allocation, not something to repeat per call. */
    @Test
    fun resolution_is_stable_across_calls() {
        assertSame(networkBuffer(), networkBuffer())
    }
}

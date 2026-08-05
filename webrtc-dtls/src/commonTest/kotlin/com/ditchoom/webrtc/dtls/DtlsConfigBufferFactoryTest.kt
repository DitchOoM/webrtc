package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.managed
import com.ditchoom.buffer.nativeMemoryAccess
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The default [DtlsConfig.bufferFactory] must produce buffers this platform's UDP socket will actually
 * send (webrtc#125).
 *
 * This looks like a test of a one-word default, and it is not. Every record [DtlsEngine] seals is handed
 * to the ICE transport and sent **unmodified** — `IceAgentDriver.send(packet)` passes it straight to the
 * bound `DatagramChannel` — and socket-udp's Linux (`io_uring sendmsg`) and Apple (`NWConnection`) send
 * paths reject a buffer with no native address outright. The default was once `managed()`, which is a GC
 * **heap** `ByteArrayBuffer` on *every* target, so a session built the way the README documents could not
 * put a single DTLS record on the wire on Apple. Nothing caught it because the one place the native peer
 * meets a real kernel — `webrtc-harness-endpoint` — injects its own factory into every seam, so the
 * defaults are exercised everywhere except where they are wrong.
 *
 * **What changed:** this used to pin the default's *identity* — `assertSame(BufferFactory.Default, …)` —
 * and recorded Kotlin/Native Linux as the target it "cannot fix and does not pretend to", because
 * `Default` is a GC-heap buffer there and the only native alternative is manually freed. The default is
 * now [networkBuffer], which keeps `Default` wherever it is already native *and* auto-reclaimed and falls
 * back only where it is not, so the identity no longer holds on every target and pinning it would fail
 * Linux by design. The invariant below is the stronger claim it was always standing in for: whatever the
 * default resolves to, **this platform's socket can send from it**.
 *
 * The Linux fallback is `malloc`-backed and freed by hand, which is why every seam above it is owned by
 * name — see [DtlsRecordSeamOwnershipTest], which gates this module at zero outstanding chunks. It ends
 * when `buffer` gives Kotlin/Native Linux a GC-managed native buffer — the thing Apple gets from ARC and
 * the JVM from `Arena.ofAuto` — after which [networkBuffer] picks `Default` back up with no change here.
 */
class DtlsConfigBufferFactoryTest {
    @Test
    fun the_default_produces_buffers_this_platform_can_send() {
        val probe = DtlsConfig().bufferFactory.allocate(1)
        assertNotNull(
            probe.nativeMemoryAccess,
            "DtlsConfig's default factory has no native address — socket-udp's Linux and Apple send " +
                "paths reject the record outright (`send requires a native-memory buffer`)",
        )
    }

    /**
     * Anti-vacuity: the sendability check above must be able to answer *no*, or it proves nothing and
     * the original defect (a `managed()` default) slips straight back through.
     *
     * Skipped on js, where `managedBufferFactory` **is** `defaultBufferFactory` — the platform has one
     * buffer type, so no factory can be distinguished from any other and the property is unfalsifiable
     * by construction rather than by accident. That costs nothing: a browser delegates to
     * `RTCPeerConnection` (ARCHITECTURE §1.1) and never hands one of these buffers to a socket. Every
     * platform that *can* reach a socket — jvm, android, apple, linux, wasmJs — runs the assertion.
     */
    @Test
    fun a_heap_factory_would_fail_that_check() {
        if (BufferFactory.managed() === BufferFactory.Default) return
        val heapProbe = BufferFactory.managed().allocate(1)
        assertTrue(
            heapProbe.nativeMemoryAccess == null,
            "managed() reported a native address — the sendability check above proves nothing",
        )
    }

    /**
     * The half that pins the *choice* rather than the capability: where `Default` is already native —
     * Apple (ARC), JVM 21 (auto-arena), Android (`Cleaner`-backed direct), wasm (linear memory) — it must
     * be returned unchanged. A flat alias to `deterministic()` would satisfy the sendability check while
     * silently moving every one of those targets onto manual frees.
     */
    @Test
    fun default_is_preserved_wherever_it_is_already_native() {
        val defaultIsNative = BufferFactory.Default.allocate(1).nativeMemoryAccess != null
        if (!defaultIsNative) return // Kotlin/Native Linux: the fallback is expected here
        assertSame(
            BufferFactory.Default,
            DtlsConfig().bufferFactory,
            "Default is native-backed on this platform, so the default must not be downgraded to a " +
                "manually-freed factory",
        )
    }

    /** Resolved once and cached — the probe is an allocation, not something to repeat per config. */
    @Test
    fun resolution_is_stable_across_calls() {
        assertSame(networkBuffer(), networkBuffer())
    }
}

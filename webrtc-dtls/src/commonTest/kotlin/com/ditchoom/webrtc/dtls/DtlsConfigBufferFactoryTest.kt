package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import kotlin.test.Test
import kotlin.test.assertSame

/**
 * The default [DtlsConfig.bufferFactory] must produce buffers this platform's UDP socket will actually
 * send (webrtc#125).
 *
 * This looks like a test of a one-word default, and it is not. Every record [DtlsEngine] seals is handed
 * to the ICE transport and sent **unmodified** — `IceAgentDriver.send(packet)` passes it straight to the
 * bound `DatagramChannel` — and socket-udp's Linux (`io_uring sendmsg`) and Apple (`NWConnection`) send
 * paths reject a buffer with no native address outright. The default was `managed()`, which is a GC
 * **heap** `ByteArrayBuffer` on *every* target, so a session built the way the README documents could not
 * put a single DTLS record on the wire on Apple. Nothing caught it because the one place the native peer
 * meets a real kernel — `webrtc-harness-endpoint` — injects its own factory into every seam, so the
 * defaults are exercised everywhere except where they are wrong.
 *
 * **Kotlin/Native Linux is the one target this cannot fix and does not pretend to.** buffer's `Default`
 * there is a GC-heap `ByteArrayBuffer`, and its only native-backed factory, `deterministic()`, is
 * `malloc`-backed and must be freed by hand — which nothing in this stack does, because every default has
 * always been GC-managed and no free-tracking invariant was ever wired up (`CountingBufferFactory` counts
 * allocations only). Flipping Linux to it would trade "cannot send" for an unbounded native leak at the
 * consent-check and per-record rate. That gap is tracked on webrtc#125 and wants a GC-managed
 * native-memory buffer from buffer itself — the thing Apple gets from ARC and the JVM from `Arena.ofAuto`.
 */
class DtlsConfigBufferFactoryTest {
    @Test
    fun the_default_is_buffer_s_platform_default_not_a_heap_only_factory() {
        // `managed()` is a GC-heap ByteArrayBuffer on *every* target, so it is unsendable on all seven that
        // demand a native address — the five Apple ones this fixes, and the two Kotlin/Native Linux ones it
        // cannot. Pinning the identity keeps an innocuous-looking "use the managed one, it needs no
        // cleanup" edit from silently un-fixing this.
        assertSame(
            BufferFactory.Default,
            DtlsConfig().bufferFactory,
            "DtlsConfig must default to buffer's per-platform Default — records are sent unmodified",
        )
    }
}

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.deterministic
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.nativeMemoryAccess

/**
 * The buffer factory for anything that will be handed to a **real socket**.
 *
 * Every datagram this stack transmits is sent *unmodified* — `IceAgentDriver.send(packet)` passes it
 * straight to the bound `DatagramChannel` — and socket-udp's Linux (`io_uring sendmsg`) and Apple
 * (`NWConnection`) send paths reject a buffer with no native address outright:
 *
 * ```
 * kotlin.IllegalStateException: send requires a native-memory buffer
 * ```
 *
 * So a wire-facing factory has two requirements, and they pull against each other: the buffer must be
 * **native-backed**, and it should still be **reclaimed without an explicit free**, because a factory
 * with manual lifetime turns every un-released datagram into a permanent leak rather than garbage.
 *
 * [BufferFactory.Default] satisfies both on almost every target — `MutableDataBuffer` (ARC) on Apple, an
 * auto-arena `FfmAutoBuffer` on JVM 21+, a `Cleaner`-backed direct buffer on Android/JVM 8-20, linear
 * memory on wasm. **Kotlin/Native Linux is the sole exception**: there `defaultBufferFactory` resolves to
 * `managedBufferFactory`, a GC-heap `ByteArrayBuffer` with no native address, which is why a
 * default-configured session on linuxX64/linuxArm64 died on its first connectivity check (#125).
 *
 * This resolves that, and resolves it by **asking rather than by a platform table**: allocate one
 * throwaway 1-byte probe and keep [BufferFactory.Default] if it is native-backed, falling back to
 * [BufferFactory.deterministic] only where it is not. Two things follow from probing instead of
 * hardcoding an `expect`/`actual`:
 *
 * - No platform gets a worse factory than it has today. On the 15 targets whose `Default` is already
 *   native this returns `Default` **unchanged**, keeping automatic reclamation — a flat alias to
 *   `deterministic()` (which is what `socket-quic`'s `BufferFactory.network()` is) would trade JVM 21's
 *   `Arena.ofAuto` for a manually-freed shared arena, a regression on a target that works.
 * - It self-corrects. When `buffer` gives Kotlin/Native Linux a GC-managed native buffer — the
 *   equivalent of Apple's ARC `MutableDataBuffer` and the JVM's `Arena.ofAuto` — this starts returning
 *   `Default` there too, and the manual-free caveat below disappears with no change at this call site.
 *
 * **The caveat, stated plainly:** on Kotlin/Native Linux the fallback *is* manually freed, and this
 * stack's receive side has no last-reader rule yet (a decoded attribute is a slice of the datagram, so
 * "release when done" needs an owner first, or a leak becomes a use-after-free). Inbound datagrams can
 * therefore accumulate there. That is strictly better than the status quo it replaces, which was not a
 * leak but a crash — but it is a real cost, and it is the reason the upstream fix is the one that ends
 * this rather than this being the end state.
 *
 * The probe costs one 1-byte allocation, once per process — it is resolved lazily and cached. Asking an
 * opaque [BufferFactory] what it produces is the only way to know; there is no capability flag on it.
 */
public fun networkBuffer(): BufferFactory = resolvedNetworkBuffer

private val resolvedNetworkBuffer: BufferFactory by lazy {
    if (BufferFactory.Default.backsNativeMemory()) BufferFactory.Default else BufferFactory.deterministic()
}

/**
 * Does this factory back its buffers with native memory? One throwaway 1-byte probe, freed immediately.
 *
 * Shared with [webrtc-dtls]'s own copy of this decision (`DtlsConfig.bufferFactory`), which cannot see
 * this module — `webrtc-dtls` is a leaf over `buffer` alone and must not gain an upward dependency on
 * ICE to reach eight lines. Both delete together when `buffer` publishes the equivalent upstream.
 */
internal fun BufferFactory.backsNativeMemory(): Boolean {
    val probe: PlatformBuffer = allocate(1)
    val isNative = probe.nativeMemoryAccess != null
    probe.freeIfNeeded()
    return isNative
}

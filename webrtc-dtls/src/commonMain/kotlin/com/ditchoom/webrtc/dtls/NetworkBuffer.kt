package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.deterministic
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.nativeMemoryAccess

/**
 * The buffer factory for DTLS **records**, which go to the wire unmodified.
 *
 * This is deliberately a twin of `com.ditchoom.webrtc.ice.networkBuffer()`, and the duplication is the
 * lesser evil: `webrtc-dtls` is a leaf over `buffer` alone (ARCHITECTURE §3, "each depending only
 * downward"), so reaching the ICE copy would mean either an upward dependency on ICE or a new published
 * artifact — both disproportionate to eight lines of probe. The two are expected to be deleted together
 * when `buffer` gives Kotlin/Native Linux a GC-managed native buffer and `BufferFactory.Default` becomes
 * correct everywhere; see the ICE copy for the full rationale and the manual-free caveat.
 *
 * Why DTLS needs it and SCTP does not: every record leaving this engine is freshly allocated here
 * (`Dtls12Handshake.encode` / `Dtls13Handshake`) and handed to `IceAgentDriver.send` untouched, so a
 * heap buffer is rejected by socket-udp's Linux and Apple send paths. An SCTP chunk, by contrast, is
 * *input* to `sealApplicationData` and is copied into the record — an SCTP buffer never reaches a
 * socket, which is why `SctpConfig.bufferFactory` is correctly left on [BufferFactory.Default].
 */
internal fun networkBuffer(): BufferFactory = resolvedNetworkBuffer

private val resolvedNetworkBuffer: BufferFactory by lazy {
    val probe: PlatformBuffer = BufferFactory.Default.allocate(1)
    val isNative = probe.nativeMemoryAccess != null
    probe.freeIfNeeded()
    if (isNative) BufferFactory.Default else BufferFactory.deterministic()
}

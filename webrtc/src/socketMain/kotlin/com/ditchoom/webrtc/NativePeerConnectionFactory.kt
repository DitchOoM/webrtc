@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.deterministic
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.ice.IceGatheringNotice
import com.ditchoom.webrtc.ice.IceServer
import com.ditchoom.webrtc.ice.MulticastMdnsEndpoint
import com.ditchoom.webrtc.ice.systemIceGathering
import kotlinx.coroutines.CoroutineScope
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Build a working native [RtcPeerConnection] — the entry point issues #135 and #136 exist to close.
 *
 * ```kotlin
 * val pc = nativePeerConnection(
 *     scope = scope,
 *     binder = udpDatagramBinder(),
 *     iceServers = listOf(IceServer("turn:turn.example.org", "user", "credential")),
 * )
 * ```
 *
 * Everything a session needs and nobody should have to assemble by hand is defaulted here: interface
 * enumeration and STUN/TURN gathering (`systemIceGathering`), the pure-Kotlin DTLS transport, and —
 * unlike a hand-built [NativePeerConnection] — **mDNS candidate privacy is on**.
 *
 * ## The binder is required, and that is the design
 *
 * A native factory that bound its own UDP socket could never be composed into the arrangement this
 * stack is built for: one demuxed UDP socket shared between a WebRTC session and a QUIC-P2P connection
 * (ARCHITECTURE §11.6). That is why a factory was deferred twice rather than written twice. Passing
 * [binder] in makes the constraint structural — there is no code path here that can bind anything the
 * caller did not hand over. Pass `udpDatagramBinder()` for a session that owns its sockets, or a
 * demuxed view of an existing one to share.
 *
 * ## mDNS is on
 *
 * A page using this library was, until now, **less private on the wire** than the same page using
 * `RTCPeerConnection`, which obfuscates host candidates unconditionally. This factory wires a real
 * [MulticastMdnsEndpoint] into both halves of the config (resolution *and* advertising), which also
 * turns on the `raddr` + foundation redaction that rides the same policy (RFC 8828).
 *
 * It is on **here only**: constructing [NativePeerConnection] directly is unchanged, so no existing
 * consumer's wire behaviour moves under them, and a test that must read a literal host address (the
 * `same-lan` lane gates on a selected pair, which mDNS makes unassertable) passes `mdns = false`.
 *
 * ## What it does not decide for you
 *
 * [bufferFactory] defaults to [BufferFactory.deterministic], **not** [BufferFactory.Default], because
 * `Default` is a GC-heap buffer on Kotlin/Native with no native address and io_uring `sendmsg` /
 * `NWConnection` reject it outright — a session built the documented way dies on its first connectivity
 * check (issue #125). `deterministic()` is native-backed everywhere it needs to be and is ARC-managed on
 * Apple; on Linux, the JVM and Android it is malloc/Arena/Unsafe memory that the stack must release, and
 * our release discipline is not yet complete (issue #125 again — `webrtc-stun` releases nothing). For a
 * long-lived server process, pass a pooled factory: `BufferPool(factory = BufferFactory.deterministic())`
 * returns each buffer to the pool on free instead of growing.
 *
 * The [iceConfig][PeerConnectionConfig.iceConfig] and [sctpConfig][PeerConnectionConfig.sctpConfig]
 * inside [config] have their buffer factories replaced by [bufferFactory], since having those disagree is
 * a bug rather than a configuration. To set them apart, construct [NativePeerConnection] directly.
 *
 * @param onGatheringNotice non-fatal gathering refusals — an unsupported `turns:` URL, a name that did
 *   not resolve, a `turn:` server with no credential. Each explains an absent candidate, which is
 *   otherwise indistinguishable from a server that never answered. Defaults to discarding them.
 */
public fun nativePeerConnection(
    scope: CoroutineScope,
    binder: DatagramBinder,
    iceServers: List<IceServer> = emptyList(),
    bufferFactory: BufferFactory = BufferFactory.deterministic(),
    mdns: Boolean = true,
    config: PeerConnectionConfig = PeerConnectionConfig(),
    @Suppress("UnseamedEntropy") random: Random = Random.Default,
    @Suppress("UnseamedEntropy") clock: () -> Instant = { Clock.System.now() },
    onGatheringNotice: (IceGatheringNotice) -> Unit = {},
): RtcPeerConnection {
    val withFactories =
        config.copy(
            iceConfig = config.iceConfig.copy(bufferFactory = bufferFactory),
            sctpConfig = config.sctpConfig.copy(bufferFactory = bufferFactory),
        )
    val resolved =
        if (!mdns) {
            withFactories
        } else {
            withFactories.withMulticastMdns(
                MulticastMdnsEndpoint(scope = scope, bufferFactory = bufferFactory, random = random),
            )
        }
    return NativePeerConnection(
        scope = scope,
        clock = clock,
        random = random,
        binder = binder,
        gathering =
            systemIceGathering(
                binder = binder,
                iceServers = iceServers,
                onNotice = onGatheringNotice,
            ),
        dtls = PureKotlinDtls(scope, clock, DtlsConfig(bufferFactory = bufferFactory, random = random)),
        config = resolved,
    )
}

package com.ditchoom.webrtc.ice

import com.ditchoom.socket.default
import kotlin.time.Duration
import com.ditchoom.socket.NetworkMonitor as SocketNetworkMonitor

/**
 * The Kotlin/Native trigger — **event-driven on both native platforms**, via socket core's
 * `NetworkMonitor.default()`: `AF_NETLINK`/`NETLINK_ROUTE` on Linux, `NWPathMonitor` on Apple. One file
 * for both, because `default()` is a single `expect` in socket's `commonMain` and the body here is
 * genuinely identical (unlike the `getifaddrs` walk next door, which needs `platform.linux` on one and
 * `platform.darwin` on the other and so must exist twice).
 *
 * **Why this is the one place that depends on socket *core* rather than `com.ditchoom:network-monitor`.**
 * These two monitors reuse socket's own `LinuxSockets` / `NWHelpers` cinterop, and `:network-monitor` is
 * deliberately cinterop-free so it never perturbs the commonizer — so on native it ships the portable
 * contract only, with no implementation behind it. Depending on socket core at this leaf is a known
 * interim, tracked upstream as **DitchOoM/socket#269**; if those monitors are ever extracted, this file
 * changes its import and nothing else.
 *
 * **The historical objection to this dependency no longer holds, and was verified rather than assumed.**
 * socket core once vendored its own BoringSSL, which duplicate-collided with buffer-crypto's at the K/N
 * Linux link. Since socket 3.15.1 it does not: its `LinuxSockets` cinterop klib embeds only `liburing.a`
 * (the `libssl.a`/`libcrypto.a` still present in 3.9.5 are gone), and both `socket:3.15.1` and
 * `buffer-crypto:6.22.0` now resolve to the **same** `com.ditchoom.boringssl:boringssl-canonical:0.0.6`,
 * which Gradle dedupes. There is one BoringSSL on the link line, not two. Confirmed by linking the
 * production `webrtc-harness-endpoint` executable on linuxX64 **and** linuxArm64 with this dependency in
 * place, and by running socket's netlink monitor in `linuxX64Test`.
 */
internal actual fun platformInterfaceChangeTrigger(pollInterval: Duration): InterfaceChangeTrigger =
    InterfaceChangeTrigger.Signalled(
        platformMonitorSignals(
            open = { SocketNetworkMonitor.default() },
            signals = { listOf(it.availability, it.networkId) },
            close = { it.close() },
        ),
    )

package com.ditchoom.webrtc.ice

/**
 * Kotlin/JS has **no** interface table to read, and this actual says so in the type rather than
 * pretending — [systemNetworkMonitor] therefore reports [NetworkMonitorSupport.Unavailable] here and an
 * app cannot accidentally build an [IceRestartPolicy.OnNetworkChange] on a monitor that would never fire.
 *
 * Two reasons, and the second is the decisive one:
 *
 *  1. **A browser page cannot enumerate NICs**, by design — and does not need to: on a browser
 *     `peerConnectionSupport()` returns `BrowserDelegated`, so ICE (including restarting it on a network
 *     change) is the platform `RTCPeerConnection`'s job, not ours.
 *  2. **There is no raw-UDP `AddressedDatagramChannel` actual on js at all** — `socket-udp` publishes no js
 *     artifact (see `webrtc-ice/build.gradle.kts`), so even under Node, where `os.networkInterfaces()`
 *     exists, there is no ICE agent of ours to restart. Reading the table would be reporting on a
 *     network nothing here can bind to.
 *
 * If a js UDP actual ever lands, this is the file that changes: Node's `os.networkInterfaces()` is a
 * direct fit for [InterfaceSnapshot.Enumerated], guarded by a runtime Node check so the same
 * compilation still loads in a browser (the pattern `peerConnectionSupport()` already uses).
 */
public actual fun systemInterfaceEnumerator(): InterfaceEnumerator =
    InterfaceEnumerator { InterfaceSnapshot.Unavailable(InterfaceEnumerationFailure.NoPlatformApi) }

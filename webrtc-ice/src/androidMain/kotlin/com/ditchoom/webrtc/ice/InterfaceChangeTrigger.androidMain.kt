package com.ditchoom.webrtc.ice

import kotlin.time.Duration
import com.ditchoom.socket.NetworkMonitor as SocketNetworkMonitor

/**
 * The Android trigger: `ConnectivityManager.NetworkCallback`, through
 * `com.ditchoom:network-monitor`'s `AndroidNetworkMonitor` — **if** the app has installed a `Context`.
 *
 * A `ConnectivityManager` cannot be reached without one, and a library has no correct way to obtain a
 * `Context` by itself (the `ActivityThread` reflection trick and the auto-init `ContentProvider` hack are
 * both worse than the problem). Socket's answer is an explicit process-wide install, and we read it
 * rather than duplicate it:
 *
 * ```
 * // once, in Application.onCreate — also enables QUIC auto-migration and anything else asking socket
 * NetworkMonitor.installAndroidContext(applicationContext)
 * ```
 *
 * Absent that we return [InterfaceChangeTrigger.Polled] and say so through
 * [SystemNetworkMonitor.detection]. That is the honest answer rather than the convenient one: claiming
 * `PlatformSignalled` here would mean an app that never installed a `Context` sees a monitor advertising
 * push while nothing ever pushes — the precise failure this whole type exists to make impossible.
 *
 * The installed monitor is documented as **caller-owned and long-lived**, so we do not close it; closing
 * a monitor we did not open would tear down QUIC's network-awareness along with our own.
 */
internal actual fun platformInterfaceChangeTrigger(pollInterval: Duration): InterfaceChangeTrigger {
    val installed = SocketNetworkMonitor.installedProcessDefaultOrNull() ?: return InterfaceChangeTrigger.Polled(pollInterval)
    return InterfaceChangeTrigger.Signalled(
        platformMonitorSignals(
            open = { installed },
            signals = { listOf(it.availability, it.networkId) },
            close = { }, // app-owned: installed once at startup, shared with every other subsystem
        ),
    )
}

package com.ditchoom.webrtc.ice

import com.ditchoom.socket.MonitorMechanism
import com.ditchoom.socket.androidOrNull
import com.ditchoom.socket.hasAndroidApplicationContext
import kotlinx.coroutines.flow.map
import kotlin.time.Duration
import com.ditchoom.socket.NetworkMonitor as SocketNetworkMonitor

/**
 * The Android trigger: `ConnectivityManager.NetworkCallback`, through
 * `com.ditchoom:network-monitor`'s `AndroidNetworkMonitor`.
 *
 * A `ConnectivityManager` cannot be reached without a `Context`, and a library has no correct way to
 * obtain one by itself. Since network-monitor 3.16.0 it no longer has to: `NetworkMonitorInitializer`
 * captures the application `Context` through androidx.startup before any app code runs, so
 * [androidOrNull] can build a reactive monitor with nothing asked of the app.
 *
 * **Two seams, in priority order.** An explicitly installed process default wins — an app that called
 * `installAndroidContext(...)` or installed a test double has said what it wants, and that must not be
 * silently replaced by one we build. Otherwise we build our own from the captured context.
 *
 * Deliberately **not** `NetworkMonitor.processDefault()`, which would be the obvious choice: that lives
 * in `com.ditchoom:socket` rather than `:network-monitor`, and this source set depends only on the
 * latter — on purpose, since network-monitor was extracted precisely so a consumer could take network
 * awareness without TCP + TLS. [androidOrNull] is published for exactly this cross-module case and costs
 * the Android leaf nothing.
 *
 * The reported reactivity is socket's [MonitorMechanism], never re-derived here: it is the one place
 * that knows whether it resolved a `ConnectivityManager` callback or fell back to polling, and a second
 * derivation would drift from it silently.
 */
internal actual fun platformInterfaceChangeTrigger(pollInterval: Duration): InterfaceChangeTrigger {
    // An app-installed monitor is app-owned and long-lived, so we never close it: tearing it down would
    // take QUIC's network awareness with it.
    SocketNetworkMonitor.installedProcessDefaultOrNull()?.let { installed ->
        return triggerFor(installed.capability.mechanism, pollInterval, open = { installed }, close = { })
    }

    // Nothing installed: decide on the captured context, WITHOUT constructing anything.
    // `hasAndroidApplicationContext()` is documented as exactly "whether androidOrNull would return a
    // reactive monitor", so reading it is not a second derivation of socket's choice — it is socket's
    // answer. Every alternative has a side effect: androidOrNull() and default() register a
    // ConnectivityManager callback we would immediately unregister, and processDefault() is worse in the
    // negative case, caching a PollingNetworkMonitor whose 5-second coroutine then runs for the life of
    // the process inside a caller that falls back to its own polling anyway.
    if (!SocketNetworkMonitor.hasAndroidApplicationContext()) {
        // The one degradation an app can act on, so it is named rather than lumped in with the platforms
        // that simply have no signal to give — and it surfaces at systemNetworkMonitor() time, not on a
        // monitor the caller has already wired into a session.
        return InterfaceChangeTrigger.Polled(pollInterval, ReactivityDegradation.NoAndroidContext)
    }

    return triggerFor(
        MonitorMechanism.PlatformSignalled,
        pollInterval,
        // Built per collection, so registration ties to collection and teardown rides structured
        // cancellation — the same lifecycle as the JVM actual.
        open = { SocketNetworkMonitor.androidOrNull() },
        close = { it?.close() },
    )
}

/**
 * Signalled only when socket says it is genuinely pushed. The `when` is exhaustive with no `else`, so a
 * new [MonitorMechanism] variant is a compile error here rather than a silent claim of reactivity —
 * which is the failure mode this whole type exists to prevent.
 */
private fun triggerFor(
    mechanism: MonitorMechanism,
    pollInterval: Duration,
    open: () -> SocketNetworkMonitor?,
    close: (SocketNetworkMonitor?) -> Unit,
): InterfaceChangeTrigger =
    when (mechanism) {
        MonitorMechanism.PlatformSignalled ->
            InterfaceChangeTrigger.Signalled(
                platformMonitorSignals(
                    open = open,
                    // Android is the one platform whose `resolution` is `RouteAndInternet`, so it is the
                    // one platform where [linkTopology]'s erasure of the reachability verdict actually
                    // suppresses anything: without it every Wi-Fi reassociation's ~0.7-1s
                    // INTERNET-before-VALIDATED window would signal a network change that moved no
                    // address. See [platformMonitorSignals].
                    signals = { monitor ->
                        if (monitor == null) emptyList() else listOf(monitor.state.map { it.linkTopology() })
                    },
                    close = close,
                ),
            )
        // socket resolved a poller, a constant, or declines to say. Polling ourselves is the honest
        // answer: claiming Signalled would advertise push while nothing pushes. Not NoAndroidContext —
        // reaching here means a monitor exists (installed, or built from a captured Context) and *it*
        // does not push, so there is nothing for the app to install; saying otherwise would send it
        // chasing a fix it has already applied.
        is MonitorMechanism.Polled,
        MonitorMechanism.Static,
        MonitorMechanism.Unknown,
        -> InterfaceChangeTrigger.Polled(pollInterval, ReactivityDegradation.NoPlatformSignal)
    }

package com.ditchoom.webrtc.ice

import com.ditchoom.socket.defaultJvmNetworkMonitor
import kotlin.time.Duration

/**
 * The JVM trigger: `com.ditchoom:network-monitor`'s own selector.
 *
 * That artifact is a **multi-release JAR** — on JDK 21+ the JVM loads the `META-INF/versions/21` copy of
 * `defaultJvmNetworkMonitor()`, which returns an FFM routing-socket monitor (netlink on Linux, `PF_ROUTE`
 * on macOS); on JDK 8-20, and on Windows, it returns network-monitor's own polling monitor. Either way it
 * *pushes* to us through its `StateFlow`s, so **we** never poll — which is exactly what
 * [InterfaceChangeDetection.PlatformSignalled] claims and all it claims.
 *
 * Whether that push is OS-driven or socket's own poller *is* knowable since socket 3.16.0, which publishes
 * a sealed `MonitorMechanism`. We still do not report it here, and the reason is a cost rather than an
 * inability: reading it requires **constructing** the monitor, and construction is what opens the FFM
 * routing socket. This actual builds the monitor lazily, inside [platformMonitorSignals]' `open` on
 * collection, precisely so an uncollected trigger costs nothing — probing the mechanism to describe
 * ourselves would undo that for every `PeerConnectionConfig` built. Android is the exception because
 * `hasAndroidApplicationContext()` answers the same question with no construction at all.
 *
 * We opened the monitor, so we close it — in the `finally` inside [platformMonitorSignals], on collector
 * cancellation.
 */
internal actual fun platformInterfaceChangeTrigger(pollInterval: Duration): InterfaceChangeTrigger =
    InterfaceChangeTrigger.Signalled(
        platformMonitorSignals(
            open = { defaultJvmNetworkMonitor() },
            signals = { listOf(it.availability, it.networkId) },
            close = { it.close() },
        ),
    )

package com.ditchoom.webrtc.ice

import com.ditchoom.socket.defaultJvmNetworkMonitor
import kotlinx.coroutines.flow.map
import kotlin.time.Duration

/**
 * The JVM trigger: `com.ditchoom:network-monitor`'s own selector.
 *
 * That artifact is a **multi-release JAR** — on JDK 21+ the JVM loads the `META-INF/versions/21` copy of
 * `defaultJvmNetworkMonitor()`, which returns an FFM routing-socket monitor (netlink on Linux, `PF_ROUTE`
 * on macOS); on JDK 8-20, and on Windows, it returns network-monitor's own polling monitor. Either way it
 * *pushes* to us through its `StateFlow`, so **we** never poll — which is exactly what
 * [InterfaceChangeDetection.PlatformSignalled] claims and all it claims.
 *
 * The state is projected to [linkTopology] before it reaches us; see [platformMonitorSignals] for why the
 * reachability verdict is deliberately not a trigger. On this platform `resolution` is `RouteOnly`, so
 * the verdict is always `Unobserved` and the projection is a no-op here — it is the shared rule, applied
 * uniformly, not a JVM workaround.
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
            signals = { monitor -> listOf(monitor.state.map { it.linkTopology() }) },
            close = { it.close() },
        ),
    )

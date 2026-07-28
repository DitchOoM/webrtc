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
 * [InterfaceChangeDetection.PlatformSignalled] claims and all it claims. Whether the push is OS-driven or
 * socket's own poller is not observable from here and we deliberately do not guess (DitchOoM/socket#269).
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

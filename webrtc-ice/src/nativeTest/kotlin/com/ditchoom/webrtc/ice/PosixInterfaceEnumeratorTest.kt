package com.ditchoom.webrtc.ice

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The native half of the production monitor, on both of its axes, for **every** native target — the
 * common shape test accepts either branch (it also runs on js/wasmJs, where `NoPlatformApi` and `Polled`
 * are correct), so these pin the branch down where a table and a signal both exist.
 *
 * They live in `nativeTest` rather than `linuxTest` on purpose: the Apple `getifaddrs` walk
 * (`SystemNetworkMonitor.appleMain.kt`) and the Apple side of the socket-core trigger are only compiled on
 * a macOS host, so this is what exercises them on the `build-apple` job — including the `sockaddr`
 * reinterpretation, the `IFF_*` policy, and `NWPathMonitor` construction, none of which a Linux developer
 * machine can reach.
 *
 * The second test is also the standing proof that depending on socket **core** here still links: it can
 * only pass if `NetworkMonitor.default()` resolved and constructed, which on Linux means an `AF_NETLINK`
 * socket and on Apple an `NWPathMonitor`.
 */
class PosixInterfaceEnumeratorTest {
    @Test
    fun getifaddrs_reads_this_machines_interface_table() = assertRealInterfaceTable(systemInterfaceEnumerator().enumerate())

    @Test
    fun native_is_driven_by_a_platform_signal_and_never_polls() {
        val monitor =
            when (val support = systemNetworkMonitor()) {
                is NetworkMonitorSupport.Watching -> support.monitor
                is NetworkMonitorSupport.Unavailable ->
                    error("this native target enumerates interfaces, so this must be Watching — got ${support.reason}")
            }
        assertEquals(
            InterfaceChangeDetection.PlatformSignalled,
            monitor.detection,
            "netlink (Linux) / NWPathMonitor (Apple) via socket core — event-driven, so we never poll",
        )
    }
}

package com.ditchoom.webrtc.ice

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The JVM half of the production monitor, on both of its axes — the common shape test accepts either
 * branch (it also runs on js/wasmJs, where `NoPlatformApi` and `Polled` are the correct answers), so it
 * would pass on a JVM whose actual had quietly regressed. These pin the branch down for a platform that
 * has both an interface table and a signal.
 */
class JvmInterfaceEnumeratorTest {
    @Test
    fun the_jvm_reads_this_machines_interface_table() = assertRealInterfaceTable(systemInterfaceEnumerator().enumerate())

    @Test
    fun the_jvm_is_driven_by_a_platform_signal_and_never_polls() {
        // network-monitor's selector always hands back a monitor that pushes to us — an FFM routing socket
        // on JDK 21+, its own poller below that — so our side is signalled either way. A regression to
        // Polled here would mean we had stopped consuming it and gone back to re-reading on a timer.
        val monitor =
            when (val support = systemNetworkMonitor()) {
                is NetworkMonitorSupport.Watching -> support.monitor
                // Not folded into an `Available` branch on purpose: Degraded here would mean the JVM had
                // silently fallen back to our own timer, which is the regression this test exists to catch.
                is NetworkMonitorSupport.Degraded ->
                    error("the JVM is pushed by network-monitor, so this must be Watching — got ${support.reason}")
                is NetworkMonitorSupport.Unavailable ->
                    error("the JVM enumerates interfaces, so this must be Watching — got ${support.reason}")
            }
        assertEquals(
            InterfaceChangeDetection.PlatformSignalled,
            monitor.detection,
            "the JVM trigger is com.ditchoom:network-monitor, so we are signalled — never polling",
        )
    }
}

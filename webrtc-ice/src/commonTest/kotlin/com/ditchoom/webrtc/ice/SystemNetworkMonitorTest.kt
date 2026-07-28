@file:OptIn(ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * The production [NetworkMonitor] (#69), on all three of its halves: that a platform signal is acted on
 * **without waiting for any poll** (the reactivity property — asserted on the virtual clock, so a
 * regression to polling fails by orders of magnitude rather than passing slowly), that collecting
 * registers with the platform and cancelling unregisters, and that the enumeration/diff behaviour built
 * on top is correct.
 *
 * Everything asserts observable state behind a watchdog — no wall-clock budgets — and every fixture whose
 * passing outcome is "nothing happened" also asserts the enumerator was genuinely read, because a monitor
 * that never woke at all would otherwise pass vacuously.
 */
class SystemNetworkMonitorTest {
    @Test
    fun a_platform_signal_is_acted_on_without_waiting_for_any_poll() =
        runTest {
            // THE reactivity fixture. The assertion is elapsed VIRTUAL time across signal→emission: a
            // signalled monitor spends exactly the coalescing window and nothing more. Swap the trigger
            // for Polled and the same edge costs a whole poll interval — 20 ms vs 5 000 ms — so this
            // fails on the difference between reactive and polled, not merely on correctness.
            val signals = MutableSharedFlow<Unit>(extraBufferCapacity = BURST)
            val enumerator = ScriptedEnumerator(enumerated(WIFI))
            val monitor = SystemNetworkMonitor(enumerator, InterfaceChangeTrigger.Signalled(signals), COALESCE)
            assertEquals(InterfaceChangeDetection.PlatformSignalled, monitor.detection)
            val emissions = collectChanges(monitor)

            enumerator.next = enumerated(CELLULAR)
            val before = testScheduler.currentTime
            signals.emit(Unit)

            val emitted = assertNotNull(withTimeoutOrNull(WATCHDOG) { emissions.receive() }, "the signal is acted on")
            val elapsed = testScheduler.currentTime - before
            assertEquals(listOf(CELLULAR), emitted.map { it.networkId.value })
            assertEquals(
                COALESCE.inWholeMilliseconds,
                elapsed,
                "a signalled monitor spends the settling window and NOTHING else — no poll interval",
            )
            assertTrue(
                elapsed < DEFAULT_INTERFACE_POLL_INTERVAL.inWholeMilliseconds,
                "…and is therefore not secretly riding the polling fallback",
            )
        }

    @Test
    fun collecting_registers_with_the_platform_and_cancelling_unregisters() =
        runTest {
            // Teardown rides structured cancellation: there is no close() for a caller to forget. Without
            // it, every session that ended would leak a ConnectivityManager callback or an open netlink
            // socket for the life of the process.
            val platform = FakePlatformMonitor()
            val opened = mutableListOf<FakePlatformMonitor>()
            val trigger =
                InterfaceChangeTrigger.Signalled(
                    platformMonitorSignals(
                        open = { platform.also { opened += it } },
                        signals = { listOf(it.updates) },
                        close = { it.closed = true },
                    ),
                )
            val monitor = SystemNetworkMonitor(ScriptedEnumerator(enumerated(WIFI)), trigger, COALESCE)

            val job = launch { monitor.changes.collect { } }
            runCurrent()
            assertEquals(1, opened.size, "collecting the changes flow is what registers with the platform")
            assertFalse(platform.closed, "…and it stays registered while the session watches")

            job.cancelAndJoin()
            assertTrue(platform.closed, "cancelling the collector unregisters the platform callback")
        }

    @Test
    fun a_burst_of_platform_callbacks_is_coalesced_into_one_enumeration() =
        runTest {
            // One physical Wi-Fi→cellular flip surfaces as several callbacks (availability drops, the link
            // id changes, addresses settle). Probing on each would re-enumerate repeatedly and could
            // publish a half-configured interface set as though it were a network change.
            val signals = MutableSharedFlow<Unit>(extraBufferCapacity = BURST)
            val enumerator = ScriptedEnumerator(enumerated(WIFI))
            val monitor = SystemNetworkMonitor(enumerator, InterfaceChangeTrigger.Signalled(signals), COALESCE)
            val emissions = collectChanges(monitor)
            val readsBefore = enumerator.reads

            enumerator.next = enumerated(CELLULAR)
            repeat(BURST) { signals.emit(Unit) }

            assertNotNull(withTimeoutOrNull(WATCHDOG) { emissions.receive() }, "the burst produces an emission")
            assertNull(withTimeoutOrNull(QUIET) { emissions.receive() }, "…exactly one, not one per callback")
            assertTrue(
                enumerator.reads - readsBefore < BURST,
                "…off fewer enumerations than callbacks (was ${enumerator.reads - readsBefore} for $BURST)",
            )
        }

    @Test
    fun an_unchanged_interface_set_is_never_emitted() =
        runTest {
            // The churn guard, one level below IceRestartPolicy's own: a monitor that re-announced the
            // same set on every wakeup would ask the app to renegotiate on every network blip.
            val enumerator = ScriptedEnumerator(enumerated(WIFI))
            val monitor = SystemNetworkMonitor(enumerator, InterfaceChangeTrigger.Polled(POLL), COALESCE)
            assertEquals(InterfaceChangeDetection.Polled(POLL), monitor.detection)

            assertNull(withTimeoutOrNull(QUIET) { monitor.changes.first() }, "an unchanged table is not a change")
            assertTrue(enumerator.reads > 1, "…and it stayed quiet by polling and comparing, not by never polling")
        }

    @Test
    fun a_failed_probe_neither_emits_nor_reports_an_empty_interface_set() =
        runTest {
            // The restart-storm guard, and the reason InterfaceSnapshot is sealed. An unreadable table
            // rendered as `emptyList()` is exactly what IceAgentDriver.pathRidesOneOf reads as "the
            // interface carrying our selected pair is gone" — so a transient getifaddrs failure would tear
            // down a perfectly healthy session for as long as the failure lasted.
            val enumerator = ScriptedEnumerator(enumerated(WIFI))
            val monitor = SystemNetworkMonitor(enumerator, InterfaceChangeTrigger.Polled(POLL), COALESCE)
            enumerator.next =
                InterfaceSnapshot.Unavailable(InterfaceEnumerationFailure.EnumerationFailed("scripted probe failure"))

            assertNull(withTimeoutOrNull(QUIET) { monitor.changes.first() }, "a failed probe is not a network change")
            assertTrue(enumerator.reads > 1, "…and the failure was actually read, repeatedly")
            assertEquals(
                listOf(WIFI),
                monitor.interfaces().map { it.networkId.value },
                "the last successfully read set stands — never an empty one",
            )
            val snapshot = monitor.lastSnapshot.value
            assertTrue(
                snapshot is InterfaceSnapshot.Unavailable &&
                    snapshot.reason is InterfaceEnumerationFailure.EnumerationFailed,
                "…while the failure itself is reported, typed, for a caller that wants to log it",
            )
        }

    @Test
    fun refresh_probes_ahead_of_the_next_wakeup() =
        runTest {
            // The escape hatch for a caller with its own reason to suspect the network moved. The poll
            // interval here is an hour: without refresh() shortcutting it, this could only pass by waiting.
            val enumerator = ScriptedEnumerator(enumerated(WIFI))
            val monitor = SystemNetworkMonitor(enumerator, InterfaceChangeTrigger.Polled(1.hours), COALESCE)
            val emissions = collectChanges(monitor)

            enumerator.next = enumerated(CELLULAR)
            monitor.refresh()

            val emitted = assertNotNull(withTimeoutOrNull(1.minutes) { emissions.receive() }, "refresh() probes now")
            assertEquals(listOf(CELLULAR), emitted.map { it.networkId.value })
        }

    @Test
    fun a_scoped_ipv6_literal_keeps_its_address_and_loses_its_zone() {
        // What the JVM actually renders for a link-local v6 interface address. The ICE candidate side
        // never carries an RFC 4007 zone, so the interface side is normalized to the bare literal and the
        // two are textually the same thing. Both parsers involved happen to tolerate the suffix today —
        // this pins the boundary rather than fixing a match, and it is what stops the tolerance of a
        // dependency from becoming a load-bearing assumption here.
        val local = assertNotNull(localInterfaceOrNull(NetworkId("eth0"), "fe80::1%eth0"), "a scoped literal is kept")
        assertEquals(NetworkId("eth0"), local.networkId)
        assertEquals(
            SocketAddress.ofLiteral("fe80::1", 0).toTransportAddressOrNull(),
            local.address.toTransportAddressOrNull(),
            "…as the same address the candidate side would carry, zone removed",
        )
    }

    @Test
    fun an_unparseable_literal_is_skipped_rather_than_thrown() {
        // SocketAddress.ofLiteral throws on a literal it cannot parse. One odd interface must cost that
        // interface, not the enumeration of every other one on the host.
        assertNull(localInterfaceOrNull(NetworkId("odd"), "not-an-ip-literal"))
        assertNull(localInterfaceOrNull(NetworkId("odd"), "%eth0"))
    }

    @Test
    fun the_platform_either_watches_real_interfaces_or_says_it_cannot() =
        runTest {
            // The real actual, on whatever target is running this. There is no third answer: a platform
            // either enumerates a well-formed interface table, or reports the typed NoPlatformApi that
            // keeps an app from building an IceRestartPolicy.OnNetworkChange on a monitor that can never
            // fire. `systemNetworkMonitor()` returning a monitor is itself proof the first probe succeeded.
            when (val support = systemNetworkMonitor()) {
                is NetworkMonitorSupport.Watching -> assertRealInterfaceTable(support.monitor.lastSnapshot.value)
                is NetworkMonitorSupport.Unavailable ->
                    assertEquals(
                        InterfaceEnumerationFailure.NoPlatformApi,
                        support.reason,
                        "a platform with no interface table says so; a transient failure is a different case",
                    )
            }
        }

    /** Collect [SystemNetworkMonitor.changes] into a channel for the life of the test. */
    private fun TestScope.collectChanges(monitor: SystemNetworkMonitor): Channel<List<LocalInterface>> {
        val emissions = Channel<List<LocalInterface>>(Channel.UNLIMITED)
        backgroundScope.launch { monitor.changes.collect { emissions.send(it) } }
        runCurrent() // let the collector subscribe before the fixture signals
        return emissions
    }

    /** Stands in for socket's platform monitor: a state flow to push on, and an observable teardown. */
    private class FakePlatformMonitor {
        val updates = MutableStateFlow(0)
        var closed: Boolean = false
    }

    private class ScriptedEnumerator(
        initial: InterfaceSnapshot,
    ) : InterfaceEnumerator {
        var next: InterfaceSnapshot = initial
        var reads: Int = 0
            private set

        override fun enumerate(): InterfaceSnapshot {
            reads++
            return next
        }
    }

    private fun enumerated(vararg ids: String): InterfaceSnapshot.Enumerated =
        InterfaceSnapshot.Enumerated(
            ids.mapIndexed { index, id ->
                // Port 0: enumerating interfaces tells you nothing about which ephemeral port ICE bound.
                LocalInterface(NetworkId(id), SocketAddress.ofLiteral("10.0.0.${index + 1}", 0))
            },
        )

    private companion object {
        /** Fallback poll cadence for the polled fixtures. */
        val POLL: Duration = 1.seconds

        /** The settling window under test — the production default, so a change to it fails these. */
        val COALESCE: Duration = DEFAULT_COALESCE_WINDOW

        /** Watchdog on observable state — generous, and free: every fixture here runs in virtual time. */
        val WATCHDOG: Duration = 60.seconds

        /** Long enough for many [POLL] ticks, so "nothing emitted" is a finding rather than impatience. */
        val QUIET: Duration = 30.seconds

        /** Callbacks in a simulated platform burst — one physical event, several notifications. */
        const val BURST = 5

        const val WIFI = "wifi"
        const val CELLULAR = "cellular"
    }
}

/**
 * Assert a snapshot really is this machine's interface table — shared by the common shape test above and
 * by the per-target fixtures that additionally pin down *which* branch their platform must take
 * (`jvmTest` / `nativeTest`), so the strict assertions live once.
 */
internal fun assertRealInterfaceTable(snapshot: InterfaceSnapshot) {
    val interfaces =
        when (snapshot) {
            is InterfaceSnapshot.Enumerated -> snapshot.interfaces
            is InterfaceSnapshot.Unavailable -> fail("this platform enumerates interfaces, but reported ${snapshot.reason}")
        }
    assertTrue(interfaces.isNotEmpty(), "a running host has at least one up interface")
    assertTrue(
        interfaces.any { it.address.host == "127.0.0.1" || it.address.host == "::1" },
        "loopback is deliberately kept — dropping an address ICE may have bound to invents a network change",
    )
    for (local in interfaces) {
        assertTrue(local.networkId.value.isNotEmpty(), "every interface is identified by its OS name")
        assertEquals(0, local.address.port, "an enumerated interface carries no meaningful port")
        assertTrue(
            '%' !in local.address.host,
            "an RFC 4007 zone suffix would never match a candidate: ${local.address.host}",
        )
        assertNotNull(
            local.address.toTransportAddressOrNull(),
            "…and the literal must parse on the ICE side, or pathRidesOneOf could never match it: $local",
        )
    }
}

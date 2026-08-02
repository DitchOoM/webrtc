package com.ditchoom.webrtc.ice

import com.ditchoom.socket.InternetAccess
import com.ditchoom.socket.MonitorCapability
import com.ditchoom.socket.MonitorMechanism
import com.ditchoom.socket.NetworkMonitor
import com.ditchoom.socket.NetworkState
import com.ditchoom.socket.ReachResolution
import com.ditchoom.socket.transport.NetworkId
import com.ditchoom.socket.transport.NetworkKind
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * What counts as *"the network moved"* under socket 4.0.0's [NetworkState] ladder.
 *
 * This exists because the bump from `availability` + `networkId` to one state flow is not a pure
 * rename: the ladder carries a rung the old pair did not, the reachability verdict inside
 * `Routable`, and Android publishes a transition on it during **every** Wi-Fi reassociation
 * (`INTERNET` lands ~0.7-1s before `VALIDATED`; measured on a Realme RMX3933, 3/3 reassociations).
 * Forwarding that as an interface change would re-enumerate on a link whose addresses did not move.
 *
 * The suppression is only safe if it is *narrow*, so both halves are asserted: the verdict is erased,
 * and everything that genuinely relocates addresses still gets through.
 *
 * Lives in the shared `monitorReplayTest` set so it runs against **both** copies of [linkTopology] —
 * `javaMain`'s and `nativeMain`'s (they read the same `NetworkState` from different artifacts;
 * DitchOoM/socket#269). That matters most for [a_link_change_survives_the_erasure], which is the
 * assertion `DeviceFlapReplayTest` measurably cannot make: the captured handset timeline passes through
 * `Offline` between every reassociation, so it contains no direct link → link edge to discriminate on.
 */
class LinkTopologyTest {
    private val wifi = NetworkId.Link(NetworkKind.Wifi, handle = 100L)
    private val cell = NetworkId.Link(NetworkKind.Cellular, handle = 200L)

    /** The whole point: a validation window is not a network change. */
    @Test
    fun the_reachability_verdict_is_erased() {
        val pending = NetworkState.Routable(wifi, InternetAccess.Observed.Pending)
        val confirmed = NetworkState.Routable(wifi, InternetAccess.Observed.Confirmed)

        assertEquals(
            pending.linkTopology(),
            confirmed.linkTopology(),
            "Pending -> Confirmed on the same link is Android's ~1s validation window. Treating it as a " +
                "network change re-enumerates on every Wi-Fi reassociation, for addresses that did not move.",
        )
    }

    /** …and every other verdict, so the erasure is not accidentally Pending-specific. */
    @Test
    fun every_verdict_on_one_link_collapses_to_one_key() {
        val keys =
            listOf(
                InternetAccess.Unobserved,
                InternetAccess.Observed.Confirmed,
                InternetAccess.Observed.Pending,
                InternetAccess.Observed.Limited,
            ).map { NetworkState.Routable(wifi, it).linkTopology() }.toSet()

        assertEquals(1, keys.size, "the verdict must not survive into the key at all: $keys")
    }

    /** A different link is a different network, verdict notwithstanding — Wi-Fi→cellular must survive. */
    @Test
    fun a_link_change_survives_the_erasure() {
        assertNotEquals(
            NetworkState.Routable(wifi, InternetAccess.Observed.Confirmed).linkTopology(),
            NetworkState.Routable(cell, InternetAccess.Observed.Confirmed).linkTopology(),
            "Wi-Fi to cellular is the canonical case the whole reactive path exists for.",
        )
    }

    /** A rung change means a route appeared or vanished — a DHCP lease landing moves addresses. */
    @Test
    fun a_rung_change_survives_the_erasure() {
        assertNotEquals(
            NetworkState.LinkLocal(wifi).linkTopology(),
            NetworkState.Routable(wifi, InternetAccess.Unobserved).linkTopology(),
            "LinkLocal -> Routable is a default route appearing; the address set moves with it.",
        )
        assertNotEquals(
            NetworkState.Offline.linkTopology(),
            NetworkState.Unknown.linkTopology(),
            "'no link' and 'not yet determined' are different answers and must not merge.",
        )
    }

    /**
     * The erasure in the pipeline it actually runs in. [platformMonitorSignals] applies
     * `distinctUntilChanged().drop(1)`, and this asserts the composition end-to-end rather than the
     * projection alone — the `drop(1)` and the dedup interact, and getting their order wrong would
     * swallow the first real change instead of the seed.
     */
    @Test
    fun the_signal_flow_forwards_link_changes_and_swallows_validation_windows() =
        runTest {
            val state = MutableStateFlow<NetworkState>(NetworkState.Unknown)
            val monitor = FakeMonitor(state)
            var signals = 0

            val collector =
                launch {
                    platformMonitorSignals(
                        open = { monitor },
                        signals = { m -> listOf(m.state.map { it.linkTopology() }) },
                        close = { },
                    ).collect { signals++ }
                }
            runCurrent()
            assertEquals(0, signals, "the replayed seed is not a change")

            // Wi-Fi arrives, still validating. One genuine change.
            state.value = NetworkState.Routable(wifi, InternetAccess.Observed.Pending)
            runCurrent()
            assertEquals(1, signals, "a link appearing must signal")

            // Validation completes ~1s later. Same link, same addresses, no signal.
            state.value = NetworkState.Routable(wifi, InternetAccess.Observed.Confirmed)
            runCurrent()
            assertEquals(
                1,
                signals,
                "the validation window signalled a network change. On Android this fires on every " +
                    "reassociation, so an IceRestartPolicy.OnNetworkChange would restart a healthy session.",
            )

            // Handover to cellular. A real change again.
            state.value = NetworkState.Routable(cell, InternetAccess.Observed.Pending)
            runCurrent()
            assertEquals(2, signals, "Wi-Fi to cellular must signal")

            collector.cancel()
        }
}

/** A [NetworkMonitor] whose state the test drives directly — no platform, no callbacks, virtual time. */
private class FakeMonitor(
    override val state: StateFlow<NetworkState>,
) : NetworkMonitor {
    override val capability =
        MonitorCapability(MonitorMechanism.PlatformSignalled, ReachResolution.RouteAndInternet)

    override fun close() = Unit
}

@file:OptIn(ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.socket.ScriptedNetworkMonitor
import com.ditchoom.socket.canRouteOffLink
import com.ditchoom.socket.networkId
import com.ditchoom.socket.testkit.networkMonitorScriptFromTrace
import com.ditchoom.socket.testkit.trace.TraceEvent
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import com.ditchoom.socket.transport.NetworkId as SocketNetworkId

/**
 * A network flap **captured from a physical Android handset**, replayed through our own trigger on
 * every platform with no device attached (webrtc#113).
 *
 * **The gap this closes.** `androidHostTest` drives a real `ConnectivityManager`, which is a genuine
 * adapter proof — but the *ordering* in it is ours: a Robolectric shadow invokes the callbacks in
 * whatever sequence the fixture author wrote. Nothing here asserted our seam against a sequence a real
 * radio produced. This does, because socket#271 published the loop that makes it cheap:
 * `TraceEvent.parseAll` and `networkMonitorScriptFromTrace` from `:socket-testkit`, feeding
 * `ScriptedNetworkMonitor` from `:network-monitor`.
 *
 * **What it does NOT prove.** That a handset delivers these callbacks on a real handover — the capture
 * is evidence one did, not a live radio. The end-to-end join (real interface change → automatic restart
 * → session survives) is #102, unbuilt on every platform, which is why `IceRestartPolicy` still defaults
 * to `Manual`.
 *
 * **Why it lives in a shared test source set.** [linkTopology] exists twice — `javaMain` and
 * `nativeMain` — because those read the same `NetworkState` from `:network-monitor` and `:socket` core
 * respectively (DitchOoM/socket#269). Two copies of one decision need one test, or editing a copy goes
 * unnoticed. `jvmTest` and `nativeTest` both `dependsOn` this set, so each compiles these assertions
 * against its own copy.
 */
class DeviceFlapReplayTest {
    /**
     * The capture decodes to the edges the device produced. Pinned first, so every assertion below is
     * known to be running against the real timeline rather than a fixture that silently parsed to
     * nothing.
     */
    @Test
    fun the_captured_flap_decodes_to_the_sequence_the_handset_produced() {
        val events = TraceEvent.parseAll(DEVICE_FLAP_V1)

        assertEquals(5, events.size, "the capture is 5 state edges; a different count means it was edited")
        assertEquals(
            DEVICE_FLAP_V1.trim(),
            events.joinToString("\n") { it.toString() },
            "re-encoding must be a fixpoint — if it is not, this fixture was hand-edited rather than re-captured",
        )

        val states = networkMonitorScriptFromTrace(events).let { s -> listOf(s.initialState) + s.transitions.map { it.state } }
        assertEquals(
            listOf(true, false, true, false, true),
            states.map { it.canRouteOffLink },
            "the handset went routable -> offline -> routable -> offline -> routable (two driven flaps)",
        )
        assertEquals(
            3,
            states.mapNotNull { (it.networkId as? SocketNetworkId.Link)?.handle }.distinct().size,
            "each reassociation came up on a DISTINCT network handle — that is the property that makes " +
                "this a link change rather than a blip, and the reason it must reach ICE at all",
        )
    }

    /**
     * The whole point: the handset's timeline, through our trigger, into the interface-change signals an
     * ICE session collects. [SystemNetworkMonitor] only emits when the interface set actually **moved**,
     * so this asserts the join — device edge → our projection → re-enumeration → emission — end to end.
     */
    @Test
    fun the_handsets_flap_reaches_an_ice_session_as_interface_changes() =
        runTest {
            val monitor = ScriptedNetworkMonitor(networkMonitorScriptFromTrace(TraceEvent.parseAll(DEVICE_FLAP_V1)))
            val subject =
                SystemNetworkMonitor(
                    enumerator = enumeratorFollowing(monitor),
                    trigger =
                        InterfaceChangeTrigger.Signalled(
                            platformMonitorSignals(
                                open = { monitor },
                                signals = { m -> listOf(m.state.map { it.linkTopology() }) },
                                close = { },
                            ),
                        ),
                )

            val seen = mutableListOf<List<LocalInterface>>()
            backgroundScope.launch { subject.changes.collect { seen += it } }
            runCurrent() // subscribe before playback, so no early edge is missed

            monitor.play()
            // Past the settling window, and with advanceTimeBy rather than advanceUntilIdle.
            // SystemNetworkMonitor delays before probing, so one physical event's burst of callbacks
            // collapses into one enumeration — which leaves the LAST signal still inside that window when
            // play() returns. advanceUntilIdle() does NOT rescue it: the only pending work belongs to
            // `backgroundScope`, and idleness is judged on foreground tasks, so it returns without moving
            // the clock at all. Measured, not assumed — the timeline ended one emission short until this
            // line advanced time explicitly.
            advanceTimeBy(SETTLE)
            runCurrent()

            assertEquals(
                listOf(emptyList(), listOf(WIFI_2), emptyList(), listOf(WIFI_3)),
                seen,
                "an ICE session on this handset should have seen four interface changes: the link " +
                    "vanishing, coming back on a new address, vanishing again, and coming back on a third. " +
                    "The set it was established on (WIFI_1) is the seed, not a change.",
            )
        }

    /**
     * Every rung transition the handset produced reaches the trigger as exactly one signal — four edges,
     * four signals, no coalescing and no spurious extra.
     *
     * **What this capture cannot discriminate, stated because it was measured.** Mutating [linkTopology]
     * to erase the entire `Routable` rung (not merely the verdict) leaves every assertion in this file
     * green. The reason is structural: the handset's two flaps each pass through `Offline`, so the trace
     * never transitions link → link *directly*, and a key that collapses all `Routable` states still
     * alternates with `Offline` and still yields four signals. So the id-preservation half of
     * [linkTopology] is **not** proven here — `LinkTopologyTest.a_link_change_survives_the_erasure` is
     * where that lives, on a direct Wi-Fi→cellular edge this recording happens not to contain.
     *
     * Likewise the verdict-suppression half: this trace is `Pending` throughout (the recorder predates
     * the ladder and never read `VALIDATED`), so there is no `Pending` → `Confirmed` window in it to
     * suppress. A re-capture on the current monitor would carry one after each reassociation and would
     * strengthen this file; until then `LinkTopologyTest` owns that half too.
     *
     * What this file *does* own is the join none of those unit tests touch: a real recorded timeline,
     * through the shipped parser, our projection, the conflated/coalescing wakeup path and a real
     * enumeration, arriving as the interface changes an ICE session consumes.
     */
    @Test
    fun a_timeline_of_unvalidated_links_still_signals_every_link_change() =
        runTest {
            val monitor = ScriptedNetworkMonitor(networkMonitorScriptFromTrace(TraceEvent.parseAll(DEVICE_FLAP_V1)))
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
            monitor.play()
            advanceTimeBy(SETTLE)
            runCurrent()

            assertEquals(
                4,
                signals,
                "five captured edges is four transitions; the first is the seed a StateFlow replays, " +
                    "which drop(1) removes because it is the state the session was established on.",
            )
            collector.cancel()
        }

    /**
     * A failed probe must never be mistaken for "every interface went away" — that input is exactly what
     * `pathRidesOneOf` reads as "the selected pair's interface is gone". Asserted on this timeline rather
     * than in the abstract, because a flap is when a real `getifaddrs` is most likely to fail.
     *
     * **The enumerator must succeed once first, and that is the whole test.** An enumerator that fails
     * from its very first call leaves the "last good set" *empty*, and empty is then indistinguishable
     * from the bug — a monitor that wrongly published `emptyList()` on failure would also emit nothing,
     * so the test would pass either way. Established as WIFI_1 and only then broken, the two behaviours
     * separate: correct is silence, buggy is an emission of `[]`. Found by mutating
     * `InterfaceSnapshot.Unavailable -> knownInterfaces.value` to `-> emptyList()` and watching an
     * earlier draft of this test pass.
     */
    @Test
    fun a_failed_probe_mid_flap_leaves_the_last_good_set_standing() =
        runTest {
            val monitor = ScriptedNetworkMonitor(networkMonitorScriptFromTrace(TraceEvent.parseAll(DEVICE_FLAP_V1)))
            var broken = false
            val subject =
                SystemNetworkMonitor(
                    enumerator =
                        InterfaceEnumerator {
                            if (broken) {
                                InterfaceSnapshot.Unavailable(InterfaceEnumerationFailure.EnumerationFailed("probe failed"))
                            } else {
                                InterfaceSnapshot.Enumerated(listOf(WIFI_1))
                            }
                        },
                    trigger =
                        InterfaceChangeTrigger.Signalled(
                            platformMonitorSignals(
                                open = { monitor },
                                signals = { m -> listOf(m.state.map { it.linkTopology() }) },
                                close = { },
                            ),
                        ),
                )

            val seen = mutableListOf<List<LocalInterface>>()
            backgroundScope.launch { subject.changes.collect { seen += it } }
            runCurrent()
            // The session is now established on WIFI_1. Break enumeration only now, so "the last good
            // set" is a real set rather than the empty list a never-successful probe would leave.
            broken = true
            monitor.play()
            advanceTimeBy(SETTLE)
            runCurrent()

            assertTrue(
                seen.isEmpty(),
                "four platform signals arrived and every probe failed, yet the monitor published an " +
                    "interface set anyway: $seen. An empty set here restarts a healthy session on every " +
                    "signal, which is the whole reason InterfaceSnapshot is sealed.",
            )
            // Anti-vacuity. Silence is the expected result, so without this the test would also pass if
            // the trigger never fired, the script never played, or the enumerator was never consulted —
            // three ways of proving nothing. The typed reason on lastSnapshot is the evidence that the
            // probes really did run and really did fail.
            assertEquals(
                InterfaceSnapshot.Unavailable(InterfaceEnumerationFailure.EnumerationFailed("probe failed")),
                subject.lastSnapshot.value,
                "the failure must be reported on lastSnapshot — a caller asking why restarts are quiet " +
                    "has nowhere else to look, and it is what proves this test is not vacuous.",
            )
        }

    /**
     * An enumerator that answers the way the handset's stack would: no usable interface while the link is
     * down, and a fresh address on each reassociation — the capture shows all three coming up on distinct
     * network handles, which in practice means distinct DHCP leases.
     */
    private fun enumeratorFollowing(monitor: ScriptedNetworkMonitor) =
        InterfaceEnumerator {
            InterfaceSnapshot.Enumerated(
                when (val handle = (monitor.state.value.networkId as? SocketNetworkId.Link)?.handle) {
                    null -> emptyList()
                    else -> listOf(ADDRESS_BY_HANDLE.getValue(handle))
                },
            )
        }

    private companion object {
        /** Comfortably past [DEFAULT_COALESCE_WINDOW], so the last signal's probe has certainly run. */
        val SETTLE = 1.seconds

        /**
         * Captured 2026-07-29 on a **Realme RMX3933 (Android 15 / API 35)** over real Wi-Fi by socket's
         * `AndroidNetworkMonitorTraceCapture`, which drives genuine radio transitions through
         * `UiAutomation.executeShellCommand`. Two driven flaps:
         *
         *  - `t≈2.3s` Wi-Fi disabled → `t≈13.6s` re-associated on a new handle
         *  - `t≈35.4s` airplane mode on → `t≈46.7s` off, re-associated on a third handle
         *
         * Copied verbatim from `DitchOoM/socket`'s `AndroidDeviceFlapReplayTests`, because socket does
         * not publish its test fixtures. **Regenerate, never edit** — the round-trip assertion above
         * exists to catch a hand-edit, and a `v1` trace is a recording, not a document.
         *
         * `Pending` throughout is honest rather than lossy: the recorder predates the ladder and read
         * `NET_CAPABILITY_INTERNET` without ever reading `VALIDATED`, so "routes exist, validation not
         * observed" is exactly what it witnessed and nothing more.
         */
        const val DEVICE_FLAP_V1 =
            """v1 50170269 NET Routable Link:Wifi:441492361229 Pending
v1 2324165652 NET Offline
v1 13649972336 NET Routable Link:Wifi:445787328525 Pending
v1 35429576167 NET Offline
v1 46677846544 NET Routable Link:Wifi:450082295821 Pending"""

        val WIFI_1 = LocalInterface(NetworkId("wlan0"), SocketAddress.ofLiteral("192.168.7.31", 0))
        val WIFI_2 = LocalInterface(NetworkId("wlan0"), SocketAddress.ofLiteral("192.168.7.52", 0))
        val WIFI_3 = LocalInterface(NetworkId("wlan0"), SocketAddress.ofLiteral("192.168.7.77", 0))

        val ADDRESS_BY_HANDLE =
            mapOf(
                441492361229L to WIFI_1,
                445787328525L to WIFI_2,
                450082295821L to WIFI_3,
            )
    }
}

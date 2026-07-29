package com.ditchoom.webrtc.ice

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import androidx.test.core.app.ApplicationProvider
import com.ditchoom.socket.MonitorMechanism
import com.ditchoom.socket.androidOrNull
import com.ditchoom.socket.hasAndroidApplicationContext
import com.ditchoom.socket.installAndroidApplicationContext
import com.ditchoom.socket.installAndroidContext
import com.ditchoom.socket.resetAndroidContextForTesting
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowNetwork
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds
import com.ditchoom.socket.NetworkMonitor as SocketNetworkMonitor

/**
 * The Android half of the [InterfaceChangeTrigger] contract, against a **real** `ConnectivityManager`
 * running on the host JVM under Robolectric — no emulator, so this rides the existing build-linux lane.
 *
 * Why this file exists (webrtc#104): every other target proves its trigger against the actual platform
 * API — Linux `AF_NETLINK`, Apple `NWPathMonitor` on the macOS runner, the JVM's JDK-21 FFM routing
 * socket — and Android, the one platform where Wi-Fi→cellular handoff is a *routine* event rather than
 * a hypothetical, proved nothing at all. The coverage was inverted.
 *
 * **What this proves:** a `ConnectivityManager.NetworkCallback` invocation propagates through socket's
 * `AndroidNetworkMonitor`, through [platformMonitorSignals]' `drop(1)`, and out of the
 * [InterfaceChangeTrigger.Signalled] flow an ICE session collects.
 *
 * **What it does not prove, and must not be read as proving:** that a real handset delivers `onLost`
 * when the radio actually switches. Robolectric shadows are our simulation of Android, not Android. The
 * end-to-end join — real interface change → automatic restart → session survives — is #102, and it is
 * unbuilt on every platform, which is why `IceRestartPolicy` still defaults to `Manual`.
 *
 * SDK is pinned rather than inherited: the module compiles against 36 and Robolectric 4.15.1 ships
 * framework jars up to 35, so an inherited `targetSdk` would fail to resolve one.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [ROBOLECTRIC_SDK])
class AndroidInterfaceChangeTriggerTest {
    private lateinit var context: Context
    private lateinit var connectivityManager: ConnectivityManager

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        // Both process-globals survive between tests inside Robolectric's per-config classloader, so
        // clear them explicitly — otherwise whichever test ran first decides what the "nothing
        // installed" cases observe. socket publishes these reset seams for exactly this; before it did,
        // this file reached the same statics by reflection, which breaks silently on a rename.
        SocketNetworkMonitor.resetProcessDefaultForTesting()
        SocketNetworkMonitor.resetAndroidContextForTesting()
    }

    @Test
    fun with_no_context_installed_the_trigger_polls_and_says_so() {
        val trigger = platformInterfaceChangeTrigger(POLL_INTERVAL)

        // Not a defect — the honest answer. It is the DEGRADED answer, and #104 exists because a
        // consumer had to inspect `detection` after the fact to discover it.
        assertIs<InterfaceChangeTrigger.Polled>(trigger)
    }

    @Test
    fun an_installed_context_makes_the_trigger_platform_signalled() {
        SocketNetworkMonitor.installAndroidContext(context)

        assertIs<InterfaceChangeTrigger.Signalled>(platformInterfaceChangeTrigger(POLL_INTERVAL))
    }

    @Test
    fun a_connectivity_manager_callback_reaches_the_signalled_flow() =
        runTest {
            SocketNetworkMonitor.installAndroidContext(context)
            val trigger = platformInterfaceChangeTrigger(POLL_INTERVAL)
            assertIs<InterfaceChangeTrigger.Signalled>(trigger)

            val signalled = CompletableDeferred<Unit>()
            val collector = launch { trigger.signals.collect { signalled.complete(Unit) } }
            // Let the collector subscribe — and let drop(1) swallow each StateFlow's replayed current
            // value, so what we assert below is a genuine change rather than the seed.
            runCurrent()

            fireOnAvailable()
            runCurrent()

            assertTrue(
                signalled.isCompleted,
                "A ConnectivityManager.NetworkCallback fired and the Signalled flow stayed silent — an " +
                    "ICE session on this platform would never learn the network moved.",
            )
            collector.cancel()
        }

    /**
     * Deciding reactivity must cost **nothing** — no `ConnectivityManager` callback registered, in
     * either direction. That is the whole reason `hasAndroidApplicationContext()` exists, and it is a
     * property a fixture can hold onto: an earlier draft of this seam answered the same question by
     * constructing a monitor and immediately closing it, which registers and unregisters a real
     * callback every time a `PeerConnectionConfig` is built.
     *
     * The `Signalled` trigger stays cold — registration belongs to collection, so cancelling the
     * collector is what unregisters, and there is no `close()` for a caller to forget.
     */
    @Test
    fun building_a_trigger_registers_no_callback_in_either_direction() {
        assertFalse(SocketNetworkMonitor.hasAndroidApplicationContext())
        assertIs<InterfaceChangeTrigger.Polled>(platformInterfaceChangeTrigger(POLL_INTERVAL))
        assertTrue(
            shadowOf(connectivityManager).networkCallbacks.isEmpty(),
            "Deciding we must POLL registered a ConnectivityManager callback — a side effect paid by " +
                "exactly the configuration that gets no benefit from it.",
        )

        SocketNetworkMonitor.installAndroidApplicationContext(context)
        assertTrue(SocketNetworkMonitor.hasAndroidApplicationContext())
        assertIs<InterfaceChangeTrigger.Signalled>(platformInterfaceChangeTrigger(POLL_INTERVAL))
        assertTrue(
            shadowOf(connectivityManager).networkCallbacks.isEmpty(),
            "Merely BUILDING the trigger registered a callback. Registration must ride collection, or " +
                "an uncollected trigger leaks a NetworkCallback for the life of the process.",
        )
    }

    /**
     * Drive every callback socket registered, exactly as the framework would. Robolectric hands back the
     * real registered instances, so this exercises `AndroidNetworkMonitor`'s own `onAvailable` rather
     * than a stand-in for it.
     */
    private fun fireOnAvailable() {
        val callbacks = shadowOf(connectivityManager).networkCallbacks
        assertTrue(
            callbacks.isNotEmpty(),
            "socket's AndroidNetworkMonitor registered no NetworkCallback — the adapter under test " +
                "never reached ConnectivityManager, so the rest of this test would pass vacuously.",
        )
        val network: Network = connectivityManager.activeNetwork ?: ShadowNetwork.newInstance(FAKE_NET_ID)
        callbacks.forEach { it.onAvailable(network) }
    }

    /**
     * The initializer works, and socket can build a reactive monitor from what it captured.
     *
     * This calls `installAndroidApplicationContext` — precisely what `NetworkMonitorInitializer.create`
     * does — rather than the initializer class itself, which consumers deliberately CANNOT compile
     * against: socket ships `androidx.startup` in `releaseRuntimeElements` only, never `api`. So the
     * reachable state is what is asserted here, and it is the state every real process is in before app
     * code runs. That App Startup actually gets it there is verified in the published AAR's merged
     * manifest, and on a real device by socket's own instrumented test.
     */
    @Test
    fun the_startup_initializer_lets_socket_build_a_platform_signalled_monitor() {
        SocketNetworkMonitor.installAndroidApplicationContext(context)

        val monitor = SocketNetworkMonitor.androidOrNull()
        assertNotNull(
            monitor,
            "socket captured no application context, so the rest of this file's premise is wrong.",
        )
        assertEquals(MonitorMechanism.PlatformSignalled, monitor.mechanism)
        monitor.close()
    }

    /**
     * **The join #104 is about.** App Startup captured a context, socket built a `PlatformSignalled`
     * monitor from it — and an ICE session now sees that, without the app calling anything.
     *
     * This assertion is the whole fix. Before it, [platformInterfaceChangeTrigger] read
     * `installedProcessDefaultOrNull()`, which the initializer never populates (it is deliberately
     * capture-only), so socket 3.15.2 could hand us reactivity and we reported [Polled] anyway. Measured,
     * not reasoned: against the real 3.15.2 artifact this test asserted `Polled` and passed until the
     * seam moved to `androidOrNull()`.
     */
    @Test
    fun a_captured_context_alone_makes_an_ice_session_reactive() =
        runTest {
            SocketNetworkMonitor.installAndroidApplicationContext(context)

            val trigger = platformInterfaceChangeTrigger(POLL_INTERVAL)
            assertIs<InterfaceChangeTrigger.Signalled>(
                trigger,
                "App Startup captured a Context and socket reports PlatformSignalled, yet ICE would " +
                    "still poll — the seam is reading something the initializer does not populate.",
            )

            val signalled = CompletableDeferred<Unit>()
            val collector = launch { trigger.signals.collect { signalled.complete(Unit) } }
            runCurrent()

            fireOnAvailable()
            runCurrent()

            assertTrue(
                signalled.isCompleted,
                "The trigger claimed PlatformSignalled and then stayed silent through a real " +
                    "ConnectivityManager callback — worse than reporting Polled honestly.",
            )
            collector.cancel()
        }

    /**
     * **The degraded state is answered at config time, and it is actionable.**
     *
     * The trigger tests above prove the seam; this proves the seam is *reachable by a consumer* through
     * the one call an app actually makes. Before [NetworkMonitorSupport.Degraded] existed, both of these
     * returned the same `Watching`, and the only way to tell a reactive Android session from a polled one
     * was to build the monitor, wire it into an [IceRestartPolicy], and then go read
     * [SystemNetworkMonitor.detection] on it — which is why the gap survived to become webrtc#104.
     *
     * The reason is [ReactivityDegradation.NoAndroidContext] rather than `NoPlatformSignal` because it is
     * the one an app can fix, and the second half of this test is that fix: install a context, and the
     * very next call reports [NetworkMonitorSupport.Watching].
     */
    @Test
    fun a_process_with_no_captured_context_reports_a_degraded_but_working_monitor() {
        val support = systemNetworkMonitor(POLL_INTERVAL)

        // The branch an app actually writes stays two-armed and still yields a usable monitor: the
        // reactivity axis must not force every consumer to care about it. That is what `Available`
        // buys, and asserting it through the `when` is the only way to assert it at all — the subtype
        // relation is a compile-time fact, so `assertIs<Available>` on a known Degraded proves nothing.
        val monitor =
            when (support) {
                is NetworkMonitorSupport.Available -> support.monitor
                is NetworkMonitorSupport.Unavailable ->
                    fail("Android reads java.net.NetworkInterface, so this enumerates — got ${support.reason}")
            }
        assertEquals(InterfaceChangeDetection.Polled(POLL_INTERVAL), monitor.detection)
        assertRealInterfaceTable(monitor.lastSnapshot.value)

        assertIs<NetworkMonitorSupport.Degraded>(
            support,
            "Android with no Context is neither fully reactive nor unsupported, and collapsing it into " +
                "either one is what hid #104: Unavailable would be a lie (the interface table reads " +
                "fine) and Watching would be the more dangerous lie (nothing pushes).",
        )
        assertEquals(
            ReactivityDegradation.NoAndroidContext,
            support.reason,
            "NoPlatformSignal would be the wrong diagnosis — it tells the app there is nothing to do, " +
                "when in fact there is exactly one thing to do.",
        )

        SocketNetworkMonitor.installAndroidApplicationContext(context)

        assertIs<NetworkMonitorSupport.Watching>(
            systemNetworkMonitor(POLL_INTERVAL),
            "the degradation named an action; taking that action must change the answer, or the reason " +
                "is decoration rather than a diagnosis.",
        )
    }

    private companion object {
        val POLL_INTERVAL = 5.seconds
        const val FAKE_NET_ID = 1
    }
}

/** Robolectric 4.15.1's newest bundled framework jar; the module itself compiles against 36. */
internal const val ROBOLECTRIC_SDK = 35

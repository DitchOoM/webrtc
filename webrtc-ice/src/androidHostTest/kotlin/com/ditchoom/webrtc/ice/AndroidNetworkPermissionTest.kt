package com.ditchoom.webrtc.ice

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkRequest
import androidx.test.core.app.ApplicationProvider
import com.ditchoom.socket.installAndroidApplicationContext
import com.ditchoom.socket.resetAndroidContextForTesting
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowConnectivityManager
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import com.ditchoom.socket.NetworkMonitor as SocketNetworkMonitor

/**
 * **The permission residue.** `hasAndroidApplicationContext()` answers *"can socket reach a
 * `ConnectivityManager`"*, and that is not the same question as *"will registering a callback on it
 * succeed"*. An app that strips `ACCESS_NETWORK_STATE` from the merged manifest
 * (`tools:node="remove"` — network-monitor's own AAR declares it, so this takes deliberate effort) has a
 * reachable `ConnectivityManager` that throws `SecurityException` the moment anything registers.
 *
 * So the seam decides [InterfaceChangeTrigger.Signalled] at config time and the failure can only appear
 * later, at **collection**. This file pins down what "later" does, because the three plausible answers
 * are very far apart: a typed throw the app can catch, a session torn down by an exception escaping a
 * `launch`, or a callback that is registered and never fires. This file holds the first — that the throw
 * arrives and names the permission. The second is held one module up, by
 * `PeerConnectionRestartTest.a_monitor_that_cannot_watch_disables_automatic_restart_without_taking_the_session_down`,
 * and it is not hypothetical: before that guard existed, this exception really did cancel the app's scope.
 *
 * Isolated in its own class because the shadow is installed for the whole class — the same reason
 * socket isolates its own version of this test. Robolectric's stock `ShadowConnectivityManager` always
 * succeeds, so without the shadow the entire path below is unreachable and would test nothing.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [ROBOLECTRIC_SDK], shadows = [PermissionDeniedConnectivityManager::class])
class AndroidNetworkPermissionTest {
    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        SocketNetworkMonitor.resetProcessDefaultForTesting()
        SocketNetworkMonitor.resetAndroidContextForTesting()
    }

    /**
     * **The residue, measured rather than reasoned about.** A `Context` is present, so the trigger says
     * `Signalled` — correctly, on the information available without constructing anything — and the
     * permission failure surfaces on the first collection.
     *
     * It is deliberately **not swallowed**. Socket already converts the framework's raw
     * `SecurityException` into a typed `NetworkMonitorPermissionException` whose message names the
     * permission, which is precisely the "typed failure rather than a silently dead callback" this was
     * meant to deliver — and webrtc cannot do better, because we have no `Context` of our own to check a
     * permission against and `ACCESS_NETWORK_STATE` is a `normal` permission that is decided at install
     * time and never changes for the life of the app. Catching it here and quietly polling instead would
     * convert a one-line manifest bug into a permanent, invisible latency regression.
     */
    @Test
    fun a_stripped_permission_surfaces_as_a_typed_failure_on_collection_not_a_silent_dead_callback() =
        runTest {
            SocketNetworkMonitor.installAndroidApplicationContext(context)
            val trigger = platformInterfaceChangeTrigger(POLL_INTERVAL)

            // Config time cannot see this, and says so honestly: the question it can answer is whether a
            // ConnectivityManager is reachable, and one is.
            assertIs<InterfaceChangeTrigger.Signalled>(trigger)

            var failure: Throwable? = null
            val collector = launch { runCatching { trigger.signals.collect { } }.onFailure { failure = it } }
            runCurrent()
            collector.cancel()

            val thrown =
                assertNotNull(
                    failure,
                    "the permission is missing, so the callback can never fire — collection must fail " +
                        "loudly rather than hand back a flow that stays silent forever, which is " +
                        "indistinguishable from a network that never changes.",
                )
            assertTrue(
                thrown.message.orEmpty().contains("ACCESS_NETWORK_STATE"),
                "the failure must name the permission, or the app cannot act on it: ${thrown.message}",
            )
        }
}

/**
 * A `ConnectivityManager` that fails registration the way the real one does when the app lacks
 * `ACCESS_NETWORK_STATE`. Mirrors socket's own `PermissionDeniedConnectivityManager`; duplicated rather
 * than shared because socket does not publish its test fixtures, and a shadow is compile-time wiring that
 * cannot be injected.
 */
@Implements(ConnectivityManager::class)
class PermissionDeniedConnectivityManager : ShadowConnectivityManager() {
    @Implementation
    override fun registerNetworkCallback(
        request: NetworkRequest?,
        networkCallback: ConnectivityManager.NetworkCallback?,
    ): Unit =
        throw SecurityException(
            "ConnectivityService: Neither user 10001 nor current process has " +
                "android.permission.ACCESS_NETWORK_STATE.",
        )
}

private val POLL_INTERVAL = 5.seconds

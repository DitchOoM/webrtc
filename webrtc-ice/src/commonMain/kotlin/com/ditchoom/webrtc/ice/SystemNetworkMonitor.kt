@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.merge
import kotlinx.coroutines.launch
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * One reading of the OS interface table — **sealed**, because "I could not read it" is a distinct
 * outcome from "I read it and it is empty", and collapsing the two is not a cosmetic mistake here: an
 * empty interface set is precisely the input [IceAgentDriver.pathRidesOneOf] reads as *"the interface
 * carrying our selected pair is gone"*, so a failed probe reported as an empty list would restart ICE on
 * a perfectly healthy session, every time the platform signalled.
 */
public sealed interface InterfaceSnapshot {
    /** The OS interface table, as read. May legitimately be empty (a host with every interface down). */
    public data class Enumerated(
        public val interfaces: List<LocalInterface>,
    ) : InterfaceSnapshot

    /** The table could not be read — see the exhaustive [reason]. Never an empty [Enumerated]. */
    public data class Unavailable(
        public val reason: InterfaceEnumerationFailure,
    ) : InterfaceSnapshot
}

/**
 * Why an interface enumeration produced nothing — a typed reason, exhaustively matchable. The
 * discriminant is the type; the strings inside are diagnostics only (standing directive 3).
 */
public sealed interface InterfaceEnumerationFailure {
    /**
     * This platform exposes **no** interface table at all, and never will: a browser page cannot see the
     * machine's NICs, by design. Distinct from [EnumerationFailed], which is a transient failure of an API
     * that does exist — a caller can meaningfully retry that one, and can only give up on this one.
     */
    public data object NoPlatformApi : InterfaceEnumerationFailure

    /**
     * The platform has an enumeration API and this call failed (a `getifaddrs` errno, a JVM
     * `SocketException`). [diagnostic] is prose for a log, never a discriminant — branch on the type.
     */
    public data class EnumerationFailed(
        public val diagnostic: String,
    ) : InterfaceEnumerationFailure
}

/**
 * Read the OS interface table **once**, synchronously — the *enumeration* half of a production
 * [NetworkMonitor].
 *
 * This is deliberately **not** delegated to `com.ditchoom:network-monitor`, and the reason is structural
 * rather than a preference: socket's `NetworkMonitor` answers *"is the network up, and what link am I
 * on"* — `availability` plus a sealed `NetworkId` of `Link(kind, handle)` / `KindOnly` / `Unidentified`,
 * whose per-link discriminator is documented as a numeric OS handle, "never an interface-name string".
 * It carries **no addresses at all**. But [IceAgentDriver.pathRidesOneOf] compares the selected pair's
 * local **IP** against the interface set, so ICE needs an address list socket structurally cannot
 * provide. Socket supplies the *trigger* ([InterfaceChangeTrigger.Signalled]); this supplies the
 * addresses. The two halves are why this file exists alongside the dependency rather than instead of it.
 */
public fun interface InterfaceEnumerator {
    /** Read the interface table now. Must not throw: a failure is an [InterfaceSnapshot.Unavailable]. */
    public fun enumerate(): InterfaceSnapshot
}

/**
 * This platform's [InterfaceEnumerator] (`expect`/`actual`).
 *
 *  - **jvm / android** — `java.net.NetworkInterface`, up interfaces only.
 *  - **linux / macOS / iOS / watchOS / tvOS (K/N)** — POSIX `getifaddrs(3)`, up-and-running interfaces only.
 *  - **js / wasmJs** — [InterfaceEnumerationFailure.NoPlatformApi], always. A browser cannot enumerate
 *    NICs, and it does not need to: on a browser `peerConnectionSupport()` delegates to the platform
 *    `RTCPeerConnection`, which restarts ICE on a network change itself. Under Node the answer is the
 *    same and for a stronger reason — there is no raw-UDP `DatagramChannel` actual on those targets, so
 *    there is no ICE agent of ours to restart.
 */
public expect fun systemInterfaceEnumerator(): InterfaceEnumerator

/**
 * What wakes a [SystemNetworkMonitor] to re-read the interface table — sealed, so a monitor that claims
 * to be signalled cannot exist without the signal that drives it (the flow and the claim are one value,
 * not two fields that can disagree).
 */
public sealed interface InterfaceChangeTrigger {
    /**
     * A platform network monitor pushes. [signals] is a **cold** flow that registers with the platform
     * on collection and unregisters when the collector is cancelled, so teardown rides structured
     * cancellation rather than a `close()` a caller can forget.
     */
    public data class Signalled(
        public val signals: Flow<Unit>,
    ) : InterfaceChangeTrigger

    /** No platform signal on this configuration — re-read the table every [interval]. */
    public data class Polled(
        public val interval: Duration,
    ) : InterfaceChangeTrigger
}

/**
 * How a [SystemNetworkMonitor] learns that the network moved — the answer to *"why did this session not
 * notice my Wi-Fi drop for four seconds?"*, readable from a bug report without opening the source.
 *
 * Deliberately **coarse**. Socket exposes no accessor for which concrete mechanism it resolved
 * (`ConnectivityManager` / `NWPathMonitor` / netlink / the JDK-21 FFM routing socket), and re-deriving it
 * here from `os.name` plus the JDK version would be a second source of truth that can drift from socket's
 * actual choice — a type that confidently names the wrong mechanism is worse than one that admits it
 * cannot see. Naming the mechanism is a bonus; never claiming *signalled* where we are in fact polling is
 * the property that must hold, and that one is exact. Tracked upstream as DitchOoM/socket#269.
 */
public sealed interface InterfaceChangeDetection {
    /**
     * A platform monitor signals us and **we never poll**. Note this describes *our* side of the seam:
     * socket's monitor is event-driven on Android, Apple and Linux-native, and on the JVM only from JDK
     * 21 (the multi-release FFM routing socket) — below that, and on Windows, socket polls internally and
     * we are signalled by its poller. So this promises "we do not poll", not "the OS pushes"; the latter
     * is socket's to state, and it does not yet expose it.
     */
    public data object PlatformSignalled : InterfaceChangeDetection

    /** No platform monitor is available here at all — this monitor re-reads every [interval] itself. */
    public data class Polled(
        public val interval: Duration,
    ) : InterfaceChangeDetection
}

/**
 * This platform's [InterfaceChangeTrigger] (`expect`/`actual`) — the *reactivity* half, delegated to
 * `com.ditchoom:network-monitor` and (at the two native leaves) `com.ditchoom:socket`.
 *
 *  - **jvm** — network-monitor's `defaultJvmNetworkMonitor()`: a JDK-21 FFM routing socket where
 *    available (shipped under `META-INF/versions/21`), its polling monitor below that. Either way it
 *    pushes to us, so we never poll.
 *  - **android** — the `ConnectivityManager.NetworkCallback` monitor, but **only** if the app installed a
 *    `Context` via socket's `NetworkMonitor.installAndroidContext(...)`; there is no way to obtain a
 *    functional Android monitor without one, so absent that we honestly report [Polled].
 *  - **linux / apple (K/N)** — socket core's `NetworkMonitor.default()`: netlink on Linux, `NWPathMonitor`
 *    on Apple. These two stay in socket *core* because they reuse its `LinuxSockets` / `NWHelpers`
 *    cinterop, which `:network-monitor` deliberately stays free of — a known interim, DitchOoM/socket#269.
 *  - **js / wasmJs** — [Polled], and moot: the enumerator reports `NoPlatformApi` there anyway.
 */
internal expect fun platformInterfaceChangeTrigger(pollInterval: Duration): InterfaceChangeTrigger

/**
 * Turn a platform network monitor into the cold `Flow<Unit>` an [InterfaceChangeTrigger.Signalled]
 * carries — **generic over the monitor type**, so this lives in `commonMain` and never names a socket
 * type. That is what keeps the sans-io core dependency-free while every actual below shrinks to three
 * lines: they differ only in which monitor they open and whether they own it.
 *
 * Lifecycle rides structured cancellation: [open] runs on collection, [close] in a `finally`, so
 * cancelling the collector unregisters the platform callback. There is no `close()` for a caller to
 * forget, and the teardown is observable in a fixture.
 *
 * [signals] are the monitor's state flows. Each is `drop(1)`-ed because a `StateFlow` replays its
 * current value to a new collector, and that replay is not a network *change* — without the drop, every
 * collection would re-enumerate immediately and a session would be told its interfaces "changed" the
 * instant it started watching.
 */
internal fun <M> platformMonitorSignals(
    open: () -> M,
    signals: (M) -> List<Flow<Any?>>,
    close: (M) -> Unit,
): Flow<Unit> =
    flow {
        val monitor = open()
        try {
            merge(*signals(monitor).map { it.drop(1) }.toTypedArray()).collect { emit(Unit) }
        } finally {
            close(monitor)
        }
    }

/**
 * The production [NetworkMonitor]: it re-reads [enumerator] whenever [trigger] says the network moved,
 * and emits the interface set when it has actually **changed**.
 *
 * **Push-first.** The trigger is a platform network monitor wherever one exists — socket's
 * `ConnectivityManager` / `NWPathMonitor` / netlink / FFM-routing-socket monitors, consumed through their
 * `StateFlow`s. Polling is the fallback for exactly the configurations with no push path (JDK < 21,
 * Windows, Android with no installed `Context`), and [detection] says which one you got.
 *
 * **Caller-clocked** (standing directive 2): the only time source is `delay` inside the collector's own
 * coroutine — no `Clock.System`, no `Dispatchers.*`, nothing spawned here. The platform callback →
 * `StateFlow` marshalling happens inside socket's own monitor; we only ever *collect*, on the caller's
 * context. So the whole flap-detection behaviour is a deterministic fixture under `runTest`.
 *
 * **A failed probe never emits.** [InterfaceSnapshot.Unavailable] leaves the last successfully read set
 * in place (see [InterfaceSnapshot] for why an empty list would be actively harmful) and is reported on
 * [lastSnapshot] for a caller that wants to log it.
 *
 * [changes] is a **cold** flow that drives its own trigger, so collecting it is what registers with the
 * platform and cancelling it is what unregisters; this is built for the one collector a session has
 * ([IceRestartPolicy.OnNetworkChange] collects it once).
 */
public class SystemNetworkMonitor(
    private val enumerator: InterfaceEnumerator,
    private val trigger: InterfaceChangeTrigger,
    private val coalesceWindow: Duration = DEFAULT_COALESCE_WINDOW,
) : NetworkMonitor {
    // Conflated: N refreshes between two probes are one probe's worth of work, and a refresh that races
    // a signal is never a reason to enumerate twice.
    private val nudges = Channel<Unit>(Channel.CONFLATED)

    private val _lastSnapshot = MutableStateFlow(enumerator.enumerate())

    // The last successfully read set. A StateFlow rather than a plain `var` for its visibility guarantee:
    // refresh() and the collector can sit on different threads, and a torn read here would be a phantom
    // interface change. Nothing observes it — lastSnapshot is the seam a caller reads.
    private val knownInterfaces =
        MutableStateFlow(
            when (val first = _lastSnapshot.value) {
                is InterfaceSnapshot.Enumerated -> first.interfaces
                is InterfaceSnapshot.Unavailable -> emptyList()
            },
        )

    /** How this monitor learns the network moved — signalled by the platform, or polled by us. */
    public val detection: InterfaceChangeDetection
        get() =
            when (trigger) {
                is InterfaceChangeTrigger.Signalled -> InterfaceChangeDetection.PlatformSignalled
                is InterfaceChangeTrigger.Polled -> InterfaceChangeDetection.Polled(trigger.interval)
            }

    /**
     * The most recent reading, successful or not — the diagnostic seam. A caller that wants to know
     * *why* automatic restarts are quiet reads this; it is a sealed [InterfaceSnapshot], so a failure
     * carries its typed reason rather than being inferred from a suspiciously empty interface list.
     */
    public val lastSnapshot: StateFlow<InterfaceSnapshot> get() = _lastSnapshot

    /** The last **successfully** read interface set — a failed probe leaves the previous one standing. */
    override fun interfaces(): List<LocalInterface> = probe()

    override val changes: Flow<List<LocalInterface>> =
        channelFlow {
            // Seed from what is already known, so the first wakeup reports a *change* rather than
            // re-announcing the set the session was established on.
            var known = knownInterfaces.value
            val wakeups =
                when (trigger) {
                    is InterfaceChangeTrigger.Signalled -> trigger.signals
                    is InterfaceChangeTrigger.Polled -> ticks(trigger.interval)
                }
            // Everything that can wake us funnels through the ONE conflated channel — platform signals,
            // poll ticks and refresh() alike. That is what makes coalescing real: a burst of platform
            // callbacks collapses in the channel itself, so it cannot queue up behind the settling window
            // and re-probe once per callback afterwards. (Collecting the signals here, as a child of this
            // flow's scope, is also what ties platform registration and teardown to collection.)
            launch { wakeups.collect { nudges.trySend(Unit) } }
            for (wakeup in nudges) {
                // Coalesce the burst. One physical event (Wi-Fi→cellular) surfaces as several platform
                // callbacks — availability drops, the link id changes, addresses settle — and probing on
                // each would re-enumerate repeatedly and could publish a half-configured interface set as
                // though it were a network change. Tens of milliseconds: a settling window, never a
                // polling interval in disguise, and it rides the collector's virtual clock so a fixture
                // can prove it has not quietly grown into one.
                delay(coalesceWindow)
                while (nudges.tryReceive().isSuccess) {
                    // drain whatever else arrived while the burst was settling
                }
                val current = probe()
                if (current != known) {
                    known = current
                    send(current)
                }
            }
        }

    /**
     * Probe now instead of waiting for the next signal — for a caller that has its own reason to think
     * the network moved. Non-suspending and never blocking; the probe happens on the collector.
     */
    public fun refresh() {
        nudges.trySend(Unit)
    }

    private fun ticks(interval: Duration): Flow<Unit> =
        flow {
            while (true) {
                delay(interval)
                emit(Unit)
            }
        }

    private fun probe(): List<LocalInterface> {
        val snapshot = enumerator.enumerate()
        _lastSnapshot.value = snapshot
        return when (snapshot) {
            is InterfaceSnapshot.Enumerated -> {
                knownInterfaces.value = snapshot.interfaces
                snapshot.interfaces
            }
            // Keep the last known good set: an unreadable table is not evidence that the interface
            // carrying our selected pair went away.
            is InterfaceSnapshot.Unavailable -> knownInterfaces.value
        }
    }
}

/**
 * Whether this platform can watch the OS interface table — sealed, so a caller cannot obtain a monitor
 * on a platform that has no interfaces to watch. That is the whole point: an
 * [IceRestartPolicy.OnNetworkChange] built on a monitor that can never fire is indistinguishable, from
 * the app's side, from automatic restarts being switched off, and the app would never learn which.
 *
 * ```
 * val policy = when (val support = systemNetworkMonitor()) {
 *     is NetworkMonitorSupport.Watching    -> IceRestartPolicy.OnNetworkChange(support.monitor)
 *     is NetworkMonitorSupport.Unavailable -> IceRestartPolicy.Manual   // and log support.reason
 * }
 * ```
 */
public sealed interface NetworkMonitorSupport {
    /** This platform enumerates interfaces; [monitor] is watching them. */
    public data class Watching(
        public val monitor: SystemNetworkMonitor,
    ) : NetworkMonitorSupport

    /** This platform cannot watch interfaces — see the typed [reason]. Automatic restart is off. */
    public data class Unavailable(
        public val reason: InterfaceEnumerationFailure,
    ) : NetworkMonitorSupport
}

/**
 * This platform's production [NetworkMonitor], or a typed reason there is none — one probe of
 * [systemInterfaceEnumerator] decides which, so the answer reflects the machine rather than a compile-time
 * guess. A platform whose *first* read fails ([InterfaceEnumerationFailure.EnumerationFailed]) reports
 * [NetworkMonitorSupport.Unavailable] too; call it again later if you want to retry.
 *
 * [pollInterval] is used **only** where no platform signal exists — read
 * [SystemNetworkMonitor.detection] to see which you got. It is injected, and the monitor is
 * caller-clocked, so a fixture drives either path in virtual time.
 */
public fun systemNetworkMonitor(pollInterval: Duration = DEFAULT_INTERFACE_POLL_INTERVAL): NetworkMonitorSupport {
    // Constructing the monitor IS the probe — it reads the table once and publishes it on lastSnapshot,
    // so deciding support costs one enumeration, not two.
    val monitor = SystemNetworkMonitor(systemInterfaceEnumerator(), platformInterfaceChangeTrigger(pollInterval))
    return when (val first = monitor.lastSnapshot.value) {
        is InterfaceSnapshot.Enumerated -> NetworkMonitorSupport.Watching(monitor)
        is InterfaceSnapshot.Unavailable -> NetworkMonitorSupport.Unavailable(first.reason)
    }
}

/**
 * Settling window after a platform signal, before the table is re-read. One physical network change
 * surfaces as a burst of callbacks; this collapses them into a single enumeration. Tens of milliseconds
 * — long enough to absorb a burst, far too short to be a polling interval in disguise.
 */
public val DEFAULT_COALESCE_WINDOW: Duration = 20.milliseconds

/**
 * Interface re-read cadence for the **fallback** path only — the configurations with no platform signal
 * (JDK < 21, Windows, Android with no installed `Context`). Comfortably inside RFC 7675's 30-second
 * consent lifetime, so a flip is noticed while the old path is still nominally alive. Where a signal
 * exists this is unused, and detection latency is the platform's rather than this number's.
 */
public val DEFAULT_INTERFACE_POLL_INTERVAL: Duration = 5.seconds

/**
 * Build a [LocalInterface] from a platform-rendered IP literal, or null if it is not one we can parse.
 *
 * Three edges the actuals must not each rediscover. The **port is meaningless**: enumerating interfaces
 * tells you nothing about which ephemeral port ICE bound on one, and [IceAgentDriver.pathRidesOneOf]
 * compares IPs for exactly that reason. An RFC 4007 **zone suffix** is dropped: the JVM renders a
 * link-local v6 address as `fe80::1%eth0` and the candidate side never carries a zone, so [LocalInterface]
 * normalizes to the bare literal rather than leaving the two sides textually different — both parsers
 * happen to tolerate the suffix today, so this is hygiene at the boundary, not a matching fix. And
 * [SocketAddress.ofLiteral] **throws** on a literal it cannot parse, so it is caught here: one odd
 * interface must cost that interface, never the enumeration of every other one on the host.
 */
internal fun localInterfaceOrNull(
    networkId: NetworkId,
    ip: String,
): LocalInterface? {
    // Strip an RFC 4007 zone identifier so both sides of the comparison read as the same literal.
    val literal = ip.substringBefore('%')
    if (literal.isEmpty()) return null
    return try {
        LocalInterface(networkId, SocketAddress.ofLiteral(literal, INTERFACE_NO_PORT))
    } catch (_: IllegalArgumentException) {
        null
    }
}

/** An enumerated interface carries no port; 0 is the "none" the comparison side already ignores. */
private const val INTERFACE_NO_PORT = 0

package com.ditchoom.webrtc.ice

import com.ditchoom.socket.InternetAccess
import com.ditchoom.socket.NetworkState
import kotlin.jvm.JvmInline

/**
 * The dimension of socket's [NetworkState] that means *"the set of local addresses may have moved"* —
 * the ladder rung plus the link identity, with the reachability verdict erased.
 *
 * A **key**, never a state: it exists only to be compared by `distinctUntilChanged` inside
 * [platformMonitorSignals], and the erased form it carries is one a `RouteAndInternet` monitor could
 * never actually emit. The value class is what stops it being handed onward as though it were a
 * `NetworkState` — the compiler refuses, which a bare normalized `NetworkState` would not.
 *
 * Why erase the verdict: on real hardware (Realme RMX3933, API 35) Android grants `INTERNET` about
 * 0.7-1s before `VALIDATED` on **every** reassociation, so `Routable(id, Pending) -> Routable(id,
 * Confirmed)` is a distinct `NetworkState` describing the same link with the same addresses. Under the
 * pre-4.0.0 two-flow API that window moved neither `availability` nor `networkId`, so erasing it is what
 * *preserves* behaviour across the bump. Everything else survives: a rung change means a route appeared
 * or vanished, and an `id` change means the link itself was replaced.
 *
 * Duplicated in `nativeMain`, which reads the same type out of `com.ditchoom:socket` rather than
 * `com.ditchoom:network-monitor` (DitchOoM/socket#269) — the same split the `getifaddrs` walk lives
 * under. The two copies differ in exactly one line: `@JvmInline` is an `@OptionalExpectation`, usable
 * only from `commonMain` and the JVM family, so the native copy carries a bare `value class`.
 */
@JvmInline
internal value class LinkTopology(
    private val key: NetworkState,
)

/** Project a [NetworkState] onto the [LinkTopology] that decides whether we re-enumerate. */
internal fun NetworkState.linkTopology(): LinkTopology =
    LinkTopology(
        // `Routable` is the only rung carrying a verdict, and `copy` is exactly the erasure — the
        // exhaustive alternative would name three rungs that all mean "already a topology key".
        if (this is NetworkState.Routable) copy(internet = InternetAccess.Unobserved) else this,
    )

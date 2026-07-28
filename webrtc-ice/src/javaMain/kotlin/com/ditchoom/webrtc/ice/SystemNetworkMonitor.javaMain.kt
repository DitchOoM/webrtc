package com.ditchoom.webrtc.ice

import java.net.NetworkInterface
import java.net.SocketException

/**
 * The JVM / Android [InterfaceEnumerator]: `java.net.NetworkInterface.getNetworkInterfaces()`.
 *
 * Shared by both because it is genuinely the same API — Android's `java.net` is the JVM's, and
 * enumerating interfaces through it needs **no manifest permission** (`ACCESS_NETWORK_STATE` is what
 * `ConnectivityManager` needs, and this deliberately does not use `ConnectivityManager`: taking an
 * Android framework dependency into `webrtc-ice` would buy a lower-latency *notification* and cost the
 * ability to run this code anywhere it can be tested. An Android app that wants callback latency wires
 * its own `NetworkCallback` to [PollingNetworkMonitor.refresh] — the hook exists for exactly this).
 *
 * **Up interfaces only.** A `NetworkInterface` that exists but is down still reports its last addresses
 * on some kernels; counting those would keep a vanished Wi-Fi interface in the set and the flip would
 * never be noticed. Loopback is deliberately **kept**: it never disappears, so it costs nothing, and
 * dropping an address ICE may actually have bound to is how a monitor invents a network change that
 * did not happen.
 */
public actual fun systemInterfaceEnumerator(): InterfaceEnumerator = JavaInterfaceEnumerator

internal object JavaInterfaceEnumerator : InterfaceEnumerator {
    override fun enumerate(): InterfaceSnapshot =
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            if (interfaces == null) {
                // Documented as possible: no interfaces at all on this host.
                InterfaceSnapshot.Enumerated(emptyList())
            } else {
                val found = mutableListOf<LocalInterface>()
                for (nic in interfaces) {
                    if (!nic.isUp) continue
                    val networkId = NetworkId(nic.name)
                    for (address in nic.inetAddresses) {
                        // getHostAddress() renders a scoped v6 literal as `fe80::1%eth0`;
                        // localInterfaceOrNull strips the zone and rejects anything unparseable.
                        val literal = address.hostAddress ?: continue
                        found += localInterfaceOrNull(networkId, literal) ?: continue
                    }
                }
                InterfaceSnapshot.Enumerated(found)
            }
        } catch (e: SocketException) {
            // The one checked failure `getNetworkInterfaces()` / `isUp` declare — a typed Unavailable,
            // never an empty set (which the session would read as "the path's interface went away").
            InterfaceSnapshot.Unavailable(
                InterfaceEnumerationFailure.EnumerationFailed(e.message ?: "NetworkInterface enumeration failed"),
            )
        }
}

package com.ditchoom.webrtc.ice

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import platform.posix.IFF_LOOPBACK
import platform.posix.IFF_RUNNING
import platform.posix.IFF_UP
import platform.posix.errno
import platform.posix.strerror

/**
 * The Kotlin/Native half of the production [NetworkMonitor]: POSIX `getifaddrs(3)` on every native
 * target we ship — linux{X64,Arm64}, macOS, iOS, watchOS, tvOS.
 *
 * **Why the walk itself is not in this file.** `getifaddrs`, `freeifaddrs`, `struct ifaddrs` and
 * `inet_ntop` are *not* in `platform.posix`: Kotlin/Native puts them in `platform.linux` on Linux and in
 * `platform.darwin` on Apple (verified against the Kotlin 2.4.0 platform klibs). A single shared
 * `nativeMain` file cannot import a symbol whose package name depends on the target, so the ~25-line
 * FFI walk lives twice — `SystemNetworkMonitor.linuxMain.kt` and `SystemNetworkMonitor.appleMain.kt`,
 * identical but for those four imports. Everything that is a *decision* rather than a call — which
 * interfaces count, how a failure is reported — is here, shared, so the two walks cannot drift on
 * behaviour. (`IFF_*`, `errno`, `strerror`, `sockaddr*` and `AF_INET*` are all in `platform.posix` on
 * both, so only the four move.)
 */
internal fun getifaddrsUnavailable(): InterfaceSnapshot.Unavailable =
    InterfaceSnapshot.Unavailable(
        InterfaceEnumerationFailure.EnumerationFailed(
            "getifaddrs failed: ${strerrorOrNull(errno) ?: "errno $errno"}",
        ),
    )

@OptIn(ExperimentalForeignApi::class)
private fun strerrorOrNull(code: Int): String? = strerror(code)?.toKString()

/**
 * The interface-selection policy both POSIX actuals apply, given one `ifaddrs` entry's flags, name and
 * rendered IP literal — or null if the entry is not one to gather on.
 *
 * **Up and running.** `getifaddrs` lists every administratively configured interface whether or not it
 * has carrier, and a Wi-Fi interface that keeps its address after the radio drops is precisely the case
 * this monitor exists to notice — so `IFF_UP` alone is not enough. Loopback is exempted from the
 * `IFF_RUNNING` test (some kernels never set it there) and is otherwise deliberately **kept**: it never
 * disappears, so it costs nothing, and dropping an address ICE may actually have bound to is how a
 * monitor manufactures a network change that did not happen.
 */
internal fun posixLocalInterfaceOrNull(
    flags: ULong,
    name: String?,
    literal: String?,
): LocalInterface? {
    if (flags and IFF_UP.toULong() == 0uL) return null
    if (flags and IFF_RUNNING.toULong() == 0uL && flags and IFF_LOOPBACK.toULong() == 0uL) return null
    if (name == null || literal == null) return null
    return localInterfaceOrNull(NetworkId(name), literal)
}

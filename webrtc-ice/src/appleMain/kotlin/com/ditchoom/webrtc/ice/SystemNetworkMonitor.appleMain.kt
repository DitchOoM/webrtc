@file:OptIn(ExperimentalForeignApi::class)

package com.ditchoom.webrtc.ice

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.MemScope
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.toKString
import kotlinx.cinterop.value
import platform.darwin.freeifaddrs
import platform.darwin.getifaddrs
import platform.darwin.ifaddrs
import platform.darwin.inet_ntop
import platform.posix.AF_INET
import platform.posix.AF_INET6
import platform.posix.INET6_ADDRSTRLEN
import platform.posix.sockaddr
import platform.posix.sockaddr_in
import platform.posix.sockaddr_in6

/**
 * The Apple (macOS / iOS / watchOS / tvOS) [InterfaceEnumerator]: POSIX `getifaddrs(3)`.
 *
 * The selection policy and the failure mapping are shared with the Linux actual in
 * `SystemNetworkMonitor.nativeMain.kt` — see its KDoc for why this walk exists twice (`getifaddrs` and
 * `inet_ntop` are in `platform.darwin` here and `platform.linux` there, so no single shared file can
 * import them). Keep the two bodies identical; only the four imports differ.
 *
 * Zero-copy discipline holds at this edge: the `inet_ntop` scratch is a `CPointer<ByteVar>` from
 * `allocArray` inside a `memScoped`, never a `ByteArray` round-trip.
 *
 * This source set registers on a **macOS host only** (`HostManager.hostIsMac` gates the Apple targets in
 * the convention plugin), so it is compiled — and its `nativeTest` fixture, `PosixInterfaceEnumeratorTest`,
 * is run — by the `build-apple` CI job, never on a Linux developer machine.
 */
public actual fun systemInterfaceEnumerator(): InterfaceEnumerator = PosixInterfaceEnumerator

internal object PosixInterfaceEnumerator : InterfaceEnumerator {
    override fun enumerate(): InterfaceSnapshot =
        memScoped {
            val head = alloc<CPointerVar<ifaddrs>>()
            if (getifaddrs(head.ptr) != 0) return getifaddrsUnavailable()
            try {
                val found = mutableListOf<LocalInterface>()
                var node = head.value
                while (node != null) {
                    val entry = node.pointed
                    node = entry.ifa_next // advance first: every skip below is a `continue`
                    val address = entry.ifa_addr ?: continue
                    found +=
                        posixLocalInterfaceOrNull(
                            flags = entry.ifa_flags.toULong(),
                            name = entry.ifa_name?.toKString(),
                            literal = literalOf(address),
                        ) ?: continue
                }
                InterfaceSnapshot.Enumerated(found)
            } finally {
                freeifaddrs(head.value)
            }
        }

    /**
     * Render an `ifa_addr` as an IP literal, or null for an address family that is not IP — `getifaddrs`
     * interleaves link-layer (`AF_LINK`) entries carrying a MAC rather than an address. `inet_ntop`
     * writes a bare literal with no RFC 4007 zone suffix, which is what the ICE candidate side carries.
     */
    private fun MemScope.literalOf(address: CPointer<sockaddr>): String? {
        val scratch = allocArray<ByteVar>(INET6_ADDRSTRLEN)
        val size = INET6_ADDRSTRLEN.toUInt()
        val rendered =
            when (address.pointed.sa_family.toInt()) {
                AF_INET ->
                    inet_ntop(
                        AF_INET,
                        address
                            .reinterpret<sockaddr_in>()
                            .pointed.sin_addr.ptr,
                        scratch,
                        size,
                    )
                AF_INET6 ->
                    inet_ntop(
                        AF_INET6,
                        address
                            .reinterpret<sockaddr_in6>()
                            .pointed.sin6_addr.ptr,
                        scratch,
                        size,
                    )
                else -> null
            } ?: return null
        return rendered.toKString().ifEmpty { null }
    }
}

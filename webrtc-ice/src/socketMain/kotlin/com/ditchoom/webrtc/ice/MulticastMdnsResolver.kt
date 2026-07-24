@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.flow.AddressFamily
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.socket.udp.MulticastInterface
import com.ditchoom.socket.udp.MulticastMembership
import com.ditchoom.socket.udp.UdpSocket
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * The production [MdnsResolver]: resolves a peer's `<uuid>.local` host candidate (RFC 8828 privacy) by
 * issuing a one-shot mDNS query (RFC 6762) over a socket-udp [UdpSocket.bindMulticast] channel and reading
 * back the A / AAAA answer — the real actual behind the seam the sans-io core injects. It lives ONLY on
 * the non-browser targets that have a socket-udp actual (jvm / android / linux / macOS / iOS); browsers
 * (js / wasm) resolve `.local` inside their own `RTCPeerConnection`, so they need no resolver.
 *
 * **mDNS is link-local multicast** (`224.0.0.251` / `[ff02::fb]`, IP TTL 255) — it does not traverse a
 * router or NAT, by design. So this resolves the names of peers on the **same local link** (two devices on
 * one Wi-Fi/LAN — the case where mDNS candidates carry their weight); a peer across the internet is
 * *expected* to be unresolvable, and ICE falls back to server-reflexive / relayed candidates. A resolution
 * that finds no responder within [queryTimeout] returns [MdnsResolution.Unresolved] — the candidate is
 * then simply never checked, never an error.
 *
 * The resolver binds its **own** short-lived multicast socket per query — a side-channel independent of the
 * shared demuxed data socket the ICE/data path rides, so it does not conflict with the single-socket
 * composition rule. All time/entropy ride the caller's coroutine context ([queryTimeout] is the one
 * injected budget), so it establishes under `runTest` virtual time like every other driver.
 */
public class MulticastMdnsResolver(
    private val families: List<AddressFamily> = listOf(AddressFamily.IPv4, AddressFamily.IPv6),
    private val bufferFactory: BufferFactory = BufferFactory.Default,
    private val queryTimeout: Duration = DEFAULT_QUERY_TIMEOUT,
) : MdnsResolver {
    override suspend fun resolve(hostname: String): MdnsResolution {
        if (!hostname.endsWith(MDNS_SUFFIX, ignoreCase = true)) return MdnsResolution.Unresolved
        // Query each configured family (a v4-only lane skips the v6 group, and vice-versa) and take the
        // first responder. Sequential, so at most one multicast socket is open at a time.
        for (family in families) {
            val resolved = queryOnce(hostname, family)
            if (resolved != null) return MdnsResolution.Resolved(resolved)
        }
        return MdnsResolution.Unresolved
    }

    private suspend fun queryOnce(
        hostname: String,
        family: AddressFamily,
    ): SocketAddress? {
        val isV4 = family == AddressFamily.IPv4
        val qType = if (isV4) MdnsMessage.TYPE_A else MdnsMessage.TYPE_AAAA
        // Bind the well-known mDNS port so both a unicast (QU) reply to our source and a multicast reply to
        // the group land on this socket; SO_REUSEADDR/REUSEPORT (set by bindMulticast) makes that safe.
        val channel = UdpSocket.bindMulticast(MDNS_PORT, family, bufferFactory = bufferFactory)
        try {
            val group = UdpSocket.resolve(if (isV4) MDNS_GROUP_V4 else MDNS_GROUP_V6, MDNS_PORT)
            channel.joinGroup(MulticastMembership(group, MulticastInterface.Default))
            channel.setTimeToLive(MDNS_TTL)
            channel.send(MdnsMessage.encodeQuery(hostname, qType, bufferFactory), to = group)
            return withTimeoutOrNull(queryTimeout) {
                while (true) {
                    val datagram =
                        when (val result = channel.receive()) {
                            is DatagramReadResult.Received -> result.datagram
                            is DatagramReadResult.Closed -> return@withTimeoutOrNull null
                        }
                    val address = MdnsMessage.decodeAddress(datagram.payload, qType)
                    // mDNS resolves a NAME → IP; the port belongs to the candidate line, so return the IP
                    // with a placeholder port — the caller (resolveHostCandidate) supplies the real port.
                    if (address != null) return@withTimeoutOrNull SocketAddress.ofLiteral(address.toString(), 0)
                }
                @Suppress("UNREACHABLE_CODE")
                null
            }
        } finally {
            channel.close()
        }
    }

    public companion object {
        /** The mDNS UDP port (RFC 6762 §5). */
        public const val MDNS_PORT: Int = 5353

        /** The IPv4 mDNS link-local group (RFC 6762 §3). */
        public const val MDNS_GROUP_V4: String = "224.0.0.251"

        /** The IPv6 mDNS link-local group (RFC 6762 §3). */
        public const val MDNS_GROUP_V6: String = "ff02::fb"

        /** mDNS datagrams carry IP TTL 255 (RFC 6762 §11) so an on-path router won't silently forward them. */
        public const val MDNS_TTL: Int = 255

        /** Default per-family query budget — a one-shot query answered by an on-link responder is sub-second. */
        public val DEFAULT_QUERY_TIMEOUT: Duration = 2.seconds

        private const val MDNS_SUFFIX = ".local"
    }
}

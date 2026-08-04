@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.flow.AddressFamily
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.socket.udp.MulticastInterface
import com.ditchoom.socket.udp.MulticastMembership
import com.ditchoom.socket.udp.UdpSocket
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlin.random.Random
import kotlin.time.Duration

/**
 * The production two-way mDNS endpoint: an [MdnsEndpoint] over real multicast sockets. It resolves a peer's
 * `<uuid>.local` host candidate (RFC 8828 privacy) *and* answers the peer's queries for the names we mint
 * for our own — [MdnsResolver] and [MdnsAdvertiser] behind one socket per family.
 *
 * This is a *factory*, not a class, because there is nothing platform-specific about the endpoint: the whole
 * protocol — codec, responder, resolver, dispatch loop — is `commonMain` and runs identically over the vnet
 * under `runTest`. All that lives here is the one thing a browser cannot do, [SocketUdpMdnsBinder]: bind UDP
 * 5353 and join the group. It exists only on the non-browser targets that ship a socket-udp actual (jvm /
 * android / linux / macOS / iOS); browsers do both halves inside their own `RTCPeerConnection`.
 *
 * A session that only *resolves* and never advertises can keep using [MulticastMdnsResolver], which holds no
 * socket between queries. A session that advertises must use this for **both** halves — see [MdnsEndpoint]
 * for why two sockets on 5353 would silently split our own resolutions' unicast replies.
 *
 * Capitalized like the constructor it replaces, because that is the one shape a consumer expects to write.
 */
@Suppress("ktlint:standard:function-naming")
public fun MulticastMdnsEndpoint(
    scope: CoroutineScope,
    families: List<AddressFamily> = listOf(AddressFamily.IPv4, AddressFamily.IPv6),
    bufferFactory: BufferFactory = networkBuffer(),
    @Suppress("UnseamedEntropy") random: Random = Random.Default,
    queryTimeout: Duration = DEFAULT_MDNS_QUERY_TIMEOUT,
    onResponse: (MdnsResponse) -> Unit = {},
): MdnsEndpoint =
    MdnsEndpoint(
        scope = scope,
        binder = SocketUdpMdnsBinder(),
        families = families,
        bufferFactory = bufferFactory,
        random = random,
        queryTimeout = queryTimeout,
        onResponse = onResponse,
    )

/**
 * The socket-udp actual behind [MdnsMulticastBinder] — the only platform code in the mDNS story. Binds UDP
 * [MDNS_UDP_PORT] with `SO_REUSEADDR`/`SO_REUSEPORT` (so another mDNS participant on the host, an Avahi or a
 * browser, keeps working), joins the family's link-local group, and sets IP TTL 255 so an on-path router will
 * not silently forward it off the link (RFC 6762 §11).
 *
 * A bind or join that fails is [MdnsGroupBinding.Unavailable], never a throw: a container without the
 * capability, or a host with no multicast route on that family, must cost the session its *privacy*, not its
 * connectivity — the caller then publishes the address in the clear.
 */
public class SocketUdpMdnsBinder : MdnsMulticastBinder {
    override suspend fun bind(family: AddressFamily): MdnsGroupBinding =
        try {
            val isV4 = family == AddressFamily.IPv4
            // No `bufferFactory` argument on purpose — see [MulticastMdnsResolver.queryOnce]: the receive
            // allocation belongs to socket-udp's per-platform factory, and overriding it with ours broke
            // every *inbound* mDNS packet on Linux (io_uring `recvmsg` needs native memory). The
            // constructor parameter still feeds what this endpoint encodes, which it does own.
            val channel = UdpSocket.bindMulticast(MDNS_UDP_PORT, family)
            val group =
                UdpSocket.resolve(
                    if (isV4) MulticastMdnsResolver.MDNS_GROUP_V4 else MulticastMdnsResolver.MDNS_GROUP_V6,
                    MDNS_UDP_PORT,
                )
            channel.joinGroup(MulticastMembership(group, MulticastInterface.Default))
            channel.setTimeToLive(MulticastMdnsResolver.MDNS_TTL)
            MdnsGroupBinding.Bound(MdnsGroupSocket(channel, group))
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            MdnsGroupBinding.Unavailable
        }
}

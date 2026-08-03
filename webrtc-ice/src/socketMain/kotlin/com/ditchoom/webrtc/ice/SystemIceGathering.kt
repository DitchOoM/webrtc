@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.socket.udp.UdpSocket
import kotlin.coroutines.cancellation.CancellationException

/**
 * Something [systemIceGathering] declined to do, reported rather than swallowed. Non-fatal by
 * construction — gathering continues past every one of these — but each explains an absent candidate,
 * which is otherwise indistinguishable from a server that never answered.
 *
 * Sealed and exhaustive (directive 3). `nativePeerConnection()` forwards these into
 * `PeerConnection.diagnostics`; a caller wiring the policy by hand supplies its own sink.
 */
public sealed interface IceGatheringNotice {
    /** A URL that is syntactically understood and still unusable — see [IceServerUrlRejection]. */
    public data class ServerUrlRejected(
        public val url: String,
        public val reason: IceServerUrlRejection,
    ) : IceGatheringNotice

    /** DNS (or a literal parse inside the resolver) did not yield an address for this server. */
    public data class ServerUnresolved(
        public val url: String,
    ) : IceGatheringNotice

    /**
     * A `turn:` URL carrying [IceServerCredentials.None]. Skipped rather than attempted with empty
     * credentials: `TurnAllocation` always sends USERNAME + MESSAGE-INTEGRITY, so a credential-free
     * attempt is a 401 loop that reports itself as "no relay candidate" — the least diagnosable of the
     * available failures.
     */
    public data class ServerCredentialMissing(
        public val url: String,
    ) : IceGatheringNotice

    /**
     * The interface table could not be read, so there is nothing to bind. Host and server-reflexive
     * gathering are both impossible in this state — a wildcard bind would advertise `0.0.0.0` as a host
     * candidate, which is not a place anything lives.
     */
    public data class InterfacesUnavailable(
        public val reason: InterfaceEnumerationFailure,
    ) : IceGatheringNotice

    /** One address could not be bound (it disappeared between enumeration and bind, or is in use). */
    public data class InterfaceUnusable(
        public val address: String,
    ) : IceGatheringNotice
}

/**
 * The **production [IceGatheringPolicy]** (issue #136): enumerate this host's addresses, bind one socket
 * per address through the supplied [binder], and gather host + server-reflexive + relay candidates from
 * the configured [iceServers].
 *
 * ```kotlin
 * val pc = NativePeerConnection(
 *     scope, clock, random,
 *     binder = udpDatagramBinder(pool),
 *     gathering = systemIceGathering(udpDatagramBinder(pool), iceServers),
 *     dtls = PureKotlinDtls(scope, clock, DtlsConfig(bufferFactory = pool)),
 * )
 * ```
 *
 * **It does not own a socket.** Every bind goes through the [binder] the caller supplied, which is the
 * whole reason this is a function taking one rather than a policy that reaches for `udpDatagramBinder()`
 * itself: a WebRTC session and a QUIC-P2P connection are meant to share one demuxed UDP socket
 * (ARCHITECTURE §11.6), and a policy that bound its own could never be composed into that.
 *
 * Ports are always **ephemeral** (`port = 0`). A production policy cannot pin one: gathering runs once
 * per ICE generation, and the outgoing generation's sockets stay bound until the new one nominates, so a
 * pinned port would ask the OS to re-bind an address still in use on every restart.
 *
 * Servers are matched to addresses **by family** — a v4 socket cannot reach a v6 STUN server, and asking
 * it to produces a gathering timeout rather than an error. The first STUN server of a family is used for
 * srflx on that family (a second would only duplicate the candidate); every TURN server of the family is
 * allocated on, which is what a browser does.
 *
 * Loopback is skipped unless [includeLoopback], and IPv6 link-local (`fe80::/10`) always is: a link-local
 * address is meaningless without the scope id that `SocketAddress` does not carry, so a candidate naming
 * one would be unreachable for the peer that received it.
 *
 * Nothing here throws: every refusal is an [IceGatheringNotice] on [onNotice], and gathering continues.
 */
public fun systemIceGathering(
    binder: DatagramBinder,
    iceServers: List<IceServer> = emptyList(),
    enumerator: InterfaceEnumerator = systemInterfaceEnumerator(),
    includeLoopback: Boolean = false,
    onNotice: (IceGatheringNotice) -> Unit = {},
): IceGatheringPolicy =
    IceGatheringPolicy { driver ->
        val servers = resolveServers(iceServers, onNotice)
        // Re-read per gather, not once per policy: a restart exists BECAUSE the interfaces may have moved
        // (RFC 8445 §9), so a set captured at construction would re-bind the addresses that went away.
        val addresses =
            when (val snapshot = enumerator.enumerate()) {
                is InterfaceSnapshot.Unavailable -> {
                    onNotice(IceGatheringNotice.InterfacesUnavailable(snapshot.reason))
                    emptyList()
                }
                is InterfaceSnapshot.Enumerated -> snapshot.interfaces.gatherable(includeLoopback)
            }

        for (local in addresses) {
            val stun = servers.stun.firstOrNull { it.address.family == local.family }
            try {
                driver.gatherHost(local.host, EPHEMERAL_PORT, stunServer = stun?.address)
            } catch (e: CancellationException) {
                throw e
            } catch (
                @Suppress("TooGenericExceptionCaught") e: Exception,
            ) {
                // One address failing must not cost the others theirs — the common case is an interface
                // that went away between enumeration and bind, which is exactly when the remaining
                // addresses matter most.
                onNotice(IceGatheringNotice.InterfaceUnusable(local.host))
                continue
            }
            for (turn in servers.turn) {
                if (turn.address.family != local.family) continue
                try {
                    driver.gatherRelay(turn.address, turn.username, turn.password, local.host, EPHEMERAL_PORT)
                } catch (e: CancellationException) {
                    throw e
                } catch (
                    @Suppress("TooGenericExceptionCaught") e: Exception,
                ) {
                    onNotice(IceGatheringNotice.ServerUnresolved(turn.url))
                }
            }
        }
    }

private const val EPHEMERAL_PORT = 0

/** A resolved TURN endpoint plus the credential its allocation needs. */
private class TurnEndpoint(
    val url: String,
    val address: SocketAddress,
    val username: String,
    val password: String,
)

private class StunEndpoint(
    val address: SocketAddress,
)

private class ResolvedServers(
    val stun: List<StunEndpoint>,
    val turn: List<TurnEndpoint>,
)

/**
 * Parse and resolve every configured URL once per gather. Resolution is repeated per generation on
 * purpose: an ICE restart can follow a network change that also changed what the STUN name resolves to.
 */
private suspend fun resolveServers(
    iceServers: List<IceServer>,
    onNotice: (IceGatheringNotice) -> Unit,
): ResolvedServers {
    val stun = mutableListOf<StunEndpoint>()
    val turn = mutableListOf<TurnEndpoint>()
    for (server in iceServers) {
        for ((index, parsed) in server.parseUrls().withIndex()) {
            val raw = server.urls[index]
            when (parsed) {
                is IceServerUrl.Unsupported -> onNotice(IceGatheringNotice.ServerUrlRejected(parsed.url, parsed.reason))
                is IceServerUrl.Stun -> {
                    val address = resolveOrNotice(raw, parsed.host, parsed.port, onNotice) ?: continue
                    stun += StunEndpoint(address)
                }
                is IceServerUrl.Turn -> {
                    val credentials = server.credentials
                    if (credentials !is IceServerCredentials.LongTerm) {
                        onNotice(IceGatheringNotice.ServerCredentialMissing(raw))
                        continue
                    }
                    val address = resolveOrNotice(raw, parsed.host, parsed.port, onNotice) ?: continue
                    turn += TurnEndpoint(raw, address, credentials.username, credentials.credential)
                }
            }
        }
    }
    return ResolvedServers(stun, turn)
}

private suspend fun resolveOrNotice(
    url: String,
    host: String,
    port: Int,
    onNotice: (IceGatheringNotice) -> Unit,
): SocketAddress? =
    try {
        UdpSocket.resolve(host, port)
    } catch (e: CancellationException) {
        throw e
    } catch (
        @Suppress("TooGenericExceptionCaught") e: Exception,
    ) {
        // A name that does not resolve is a configuration fact, not a crash: the session still has its
        // host candidates, and the caller gets told which server it lost.
        onNotice(IceGatheringNotice.ServerUnresolved(url))
        null
    }

/**
 * The addresses worth gathering on, deduplicated. Two interfaces holding the same address (an alias, or
 * the same address on a bridge and its member) would otherwise bind twice and publish the same candidate
 * twice, which costs the peer a redundant check per pair.
 */
private fun List<LocalInterface>.gatherable(includeLoopback: Boolean): List<SocketAddress> {
    val seen = mutableSetOf<String>()
    val result = mutableListOf<SocketAddress>()
    for (local in this) {
        val host = local.address.host
        if (!includeLoopback && host.isLoopback()) continue
        if (host.isIpv6LinkLocal()) continue
        if (!seen.add(host)) continue
        result += local.address
    }
    return result
}

/**
 * Loopback, whatever spelling the platform's interface table uses. It is **not** always `::1`: the JVM
 * enumerator reports the fully expanded `0:0:0:0:0:0:0:1`, so a literal comparison silently matches
 * nothing and every session publishes a loopback candidate the peer cannot use. (`SystemIceGatheringTest`
 * caught exactly that — the assertion that loopback is absent by default is what makes the
 * `includeLoopback = true` case non-vacuous.) A scope suffix (`%lo`) is stripped first.
 */
private fun String.isLoopback(): Boolean {
    val bare = substringBefore('%').lowercase()
    if (bare.startsWith("127.")) return true
    if (!bare.contains(':')) return false
    val hextets = bare.split(':').filter { it.isNotEmpty() }
    if (hextets.isEmpty()) return false
    return hextets.last().trimStart('0') == "1" && hextets.dropLast(1).all { it.trimStart('0').isEmpty() }
}

// fe80::/10 — the first ten bits, so the leading hextet runs fe80..febf and NOT just the four literal
// prefixes it is tempting to compare against (fe81::1 is link-local too). Matched on the text because
// that is what enumeration hands us; parsing to bytes would want a primitive array (directive 1).
private fun String.isIpv6LinkLocal(): Boolean {
    if (!contains(':')) return false
    val firstHextet = substringBefore(':')
    if (firstHextet.isEmpty() || !firstHextet.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return false
    val value = firstHextet.toIntOrNull(16) ?: return false
    return value in 0xFE80..0xFEBF
}

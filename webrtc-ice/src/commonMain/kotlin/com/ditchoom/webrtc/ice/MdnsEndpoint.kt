@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.flow.AddressFamily
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.stun.IpAddress
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * The one socket an [MdnsEndpoint] speaks mDNS on for a single address family: bound to 5353 and joined to
 * the link-local group, which is also where a shared (multicast) response is sent.
 */
public class MdnsGroupSocket(
    public val channel: AddressedDatagramChannel,
    public val group: SocketAddress,
)

/** The outcome of asking for that socket — sealed, because "the link refused us" is a fact, not an absence. */
public sealed interface MdnsGroupBinding {
    /** The socket is bound and joined; [socket] is live. */
    public data class Bound(
        public val socket: MdnsGroupSocket,
    ) : MdnsGroupBinding

    /** No socket for this family here — no multicast route, no capability, or no actual on this target. */
    public data object Unavailable : MdnsGroupBinding
}

/**
 * The **one** platform seam in the mDNS story: bind UDP 5353 for a family and join `224.0.0.251` /
 * `[ff02::fb]`. Everything else — the codec, the responder, the resolver, the dispatch loop — is
 * `commonMain` and runs identically over the in-memory vnet under `runTest`.
 *
 * Production supplies the socket-udp actual (`MulticastMdnsEndpoint`, non-browser targets only); a test
 * supplies a vnet channel, which is what lets the *real* [MdnsEndpoint] be the thing under test rather than
 * a re-implementation of it.
 */
public fun interface MdnsMulticastBinder {
    /** Bind and join for [family]. */
    public suspend fun bind(family: AddressFamily): MdnsGroupBinding
}

/**
 * The two-way mDNS driver: it resolves a peer's `<uuid>.local` host candidate (RFC 8828 privacy) *and*
 * answers the peer's queries for the names we publish for our own — [MdnsResolver] and [MdnsAdvertiser]
 * behind one socket per family.
 *
 * **One socket, both halves, on purpose.** A responder must bind the well-known port 5353 to hear queries,
 * and [MulticastMdnsResolver] binds 5353 too so that a multicast reply reaches it. Two sockets on 5353 in
 * one process is legal (`SO_REUSEADDR`/`SO_REUSEPORT`) and works for multicast, which the kernel delivers to
 * every joined socket — but a **unicast** reply to that port is delivered to exactly one of them, chosen by
 * a 4-tuple hash. A responder alongside the existing resolver would therefore have silently eaten a share of
 * our own resolutions' replies, which is the kind of 50/50 defect that reads as a flaky lane for a year.
 * Sharing the socket makes the collision unrepresentable rather than unlikely.
 *
 * **mDNS is link-local multicast** — it does not traverse a router or NAT, by design. So we answer for peers
 * on the **same local link**, and a peer across the internet is *expected* to be unable to resolve our name;
 * ICE then falls back to server-reflexive / relayed candidates exactly as it does today when a browser's
 * `.local` reaches us across a NAT.
 *
 * Entropy and concurrency are injected seams (directive #2): [random] mints the names, [scope] carries the
 * per-socket receive loops, and [binder] is the only thing that ever touches a real socket.
 */
public class MdnsEndpoint(
    private val scope: CoroutineScope,
    private val binder: MdnsMulticastBinder,
    private val families: List<AddressFamily> = listOf(AddressFamily.IPv4, AddressFamily.IPv6),
    private val bufferFactory: BufferFactory = networkBuffer(),
    // The name minter. A driver, so an ambient Random is a legitimate production default — but it is a
    // seam, so a deterministic fixture can name what this mints. The name carries no machine-derived
    // material either way (see MdnsHostName.random), so unpredictability is not what the privacy rests on.
    @Suppress("UnseamedEntropy") private val random: Random = Random.Default,
    private val queryTimeout: Duration = DEFAULT_MDNS_QUERY_TIMEOUT,
    /** Observes every responder decision — answers and typed silences alike. Silent by default. */
    private val onResponse: (MdnsResponse) -> Unit = {},
) : MdnsResolver,
    MdnsAdvertiser {
    private val responder = MdnsResponder(bufferFactory)
    private val lock = Mutex()
    private val sockets = HashMap<AddressFamily, BoundFamily>()
    private val names = HashMap<IpAddress, MdnsHostName>()
    private val pending = HashMap<PendingKey, MutableList<CompletableDeferred<IpAddress>>>()
    private var closed = false

    /** The names this endpoint currently answers for — what a session actually published, observably. */
    public val advertisedNames: Set<MdnsHostName> get() = responder.advertisedNames

    /**
     * Mint (or recall) the `<uuid>.local` name for [address] and start answering A / AAAA queries for it.
     *
     * Stable per address for the life of this endpoint: the name is minted once and cached, so a candidate
     * re-signaled after an ICE restart, or a second candidate on the same interface, publishes the *same*
     * name. Two names for one interface would tell an observer they belong to one host as loudly as the
     * address would have.
     */
    override suspend fun advertise(address: IpAddress): MdnsAdvertisement {
        val family = familyOf(address)
        if (family !in families) return MdnsAdvertisement.Declined(MdnsDeclineReason.UnsupportedFamily)
        return lock.withLock {
            if (closed) return@withLock MdnsAdvertisement.Declined(MdnsDeclineReason.NoResponder)
            // Bind FIRST: a name we cannot answer for is worse than an address in the clear, so the group has
            // to be joined before the name is allowed to leave for the signaling server.
            socketFor(family) ?: return@withLock MdnsAdvertisement.Declined(MdnsDeclineReason.GroupUnavailable)
            val name = names.getOrPut(address) { MdnsHostName.random(random) }
            responder.advertise(name, address)
            MdnsAdvertisement.Advertised(name)
        }
    }

    /**
     * Stop answering for [name] and multicast the RFC 6762 §10.1 **goodbye** that retracts it, so peers
     * flush the binding now rather than holding it for the remaining 120 s (see [MdnsResponder.withdraw]
     * for why that window stopped being harmless once network reactivity landed).
     *
     * Best-effort by design: the local withdrawal has already happened by the time the send is attempted,
     * and a group we cannot reach is exactly the case where the record was unreachable anyway. A failed
     * goodbye must never leave us still answering for a name — so the retraction is unconditional and only
     * the announcement of it is not.
     */
    public suspend fun withdraw(name: MdnsHostName) {
        val goodbye =
            lock.withLock {
                names.entries.firstOrNull { it.value == name }?.let { names.remove(it.key) }
                responder.withdraw(name)
            }
        when (goodbye) {
            MdnsWithdrawal.NotAdvertised -> Unit
            is MdnsWithdrawal.Goodbye -> {
                val family = familyOf(goodbye.address)
                // Sent OUTSIDE the lock: it is I/O, and holding the registration lock across a socket send
                // would let a slow group stall an unrelated advertise().
                val bound = lock.withLock { if (closed) null else socketFor(family) }
                try {
                    bound?.socket?.let { runCatching { it.channel.send(goodbye.payload, to = it.group) } }
                } finally {
                    // The responder built this for us and handed it over (see [MdnsResponder.withdraw]);
                    // this is the end of the line for it either way. "Either way" is the point: the
                    // best-effort path above declines to send on a group it cannot reach, and a buffer
                    // built for a send that did not happen is still a buffer we asked for.
                    goodbye.payload.releaseAfterSend()
                }
            }
        }
    }

    override suspend fun resolve(hostname: String): MdnsResolution {
        if (!hostname.endsWith(MdnsHostName.SUFFIX, ignoreCase = true)) return MdnsResolution.Unresolved
        // Query each configured family (a v4-only lane skips the v6 group, and vice-versa) and take the
        // first responder, exactly as the resolve-only actual does.
        for (family in families) {
            val resolved = queryOnce(hostname, family)
            if (resolved != null) {
                // mDNS resolves a NAME → IP; the port belongs to the candidate line, so return the IP with a
                // placeholder port — the caller (resolveHostCandidate) supplies the real port.
                return MdnsResolution.Resolved(SocketAddress.ofLiteral(resolved.toString(), 0))
            }
        }
        return MdnsResolution.Unresolved
    }

    /** Tear down every socket and loop. Idempotent; a pending resolution simply times out unresolved. */
    public fun close() {
        closed = true
        for (bound in sockets.values) {
            bound.loop.cancel()
            bound.socket.channel.close()
        }
        sockets.clear()
    }

    private suspend fun queryOnce(
        hostname: String,
        family: AddressFamily,
    ): IpAddress? {
        val qType = if (family == AddressFamily.IPv4) MdnsMessage.TYPE_A else MdnsMessage.TYPE_AAAA
        val bound = lock.withLock { if (closed) null else socketFor(family) } ?: return null
        val key = PendingKey(hostname.lowercase(), qType)
        val waiter = CompletableDeferred<IpAddress>()
        // Registered BEFORE the query goes out: on a shared socket the answer can be dispatched the moment
        // the loop reads it, which under virtual time is before this coroutine resumes from `send`.
        lock.withLock { pending.getOrPut(key) { mutableListOf() } += waiter }
        val query = MdnsMessage.encodeQuery(hostname, qType, bufferFactory)
        try {
            try {
                bound.socket.channel.send(query, to = bound.socket.group)
            } finally {
                // The moment the send is done with it, rather than at the end of the resolution: the answer
                // arrives on the shared dispatch loop, so nothing here reads the question again, and the
                // wait below can be seconds long. In a `finally` because the `catch` outside swallows a
                // send that threw — and both families are tried in turn, so on a v4+v6 endpoint whose v6
                // group is unreachable, "release only when the send worked" leaks one query per attempt.
                query.releaseAfterSend()
            }
            return withTimeoutOrNull(queryTimeout) { waiter.await() }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return null // the socket went away under the query — no address, never a thrown resolution
        } finally {
            lock.withLock { pending[key]?.remove(waiter) }
        }
    }

    // Bind (once) the socket for [family] and launch its dispatch loop. Null if the platform refuses — a
    // machine with no multicast route on that family, a container without the capability. Callers hold [lock].
    private suspend fun socketFor(family: AddressFamily): BoundFamily? {
        sockets[family]?.let { return it }
        val socket =
            when (val binding = binder.bind(family)) {
                MdnsGroupBinding.Unavailable -> return null
                is MdnsGroupBinding.Bound -> binding.socket
            }
        // Here rather than inside the binder (#131). `SocketUdpMdnsBinder.bind` maps *every* exception to
        // [MdnsGroupBinding.Unavailable] on purpose — a host with no multicast route must cost the session
        // its privacy, not its connectivity — and a misconfigured factory is not that kind of failure. Left
        // in the binder it would be swallowed into "mDNS is unavailable here", which is the same silence
        // #131 exists to end.
        socket.channel.requireSendableWith(bufferFactory, WireBufferSeam.MdnsBufferFactory)
        val loop = scope.launch { dispatch(socket) }
        return BoundFamily(socket, loop).also { sockets[family] = it }
    }

    /**
     * The one receive loop per socket: every datagram on the group is offered to the responder first, and
     * anything it declines as [MdnsSilenceReason.NotAQuery] — i.e. a *response* — is offered to whichever of
     * our own queries is waiting for that name. This is the whole reason the two halves share a socket, and
     * the reason [MdnsMessage.decodeAnswers] carries the owner name: with several resolutions outstanding,
     * "the only responder is answering our exact query" stops being true.
     */
    private suspend fun dispatch(socket: MdnsGroupSocket) {
        while (true) {
            val datagram =
                when (val result = socket.channel.receiveOrClosed()) {
                    is DatagramReadResult.Received -> result.datagram
                    is DatagramReadResult.Closed -> return
                }
            val start = datagram.payload.position()
            try {
                val response = responder.serveOne(socket.channel, datagram, socket.group)
                onResponse(response)
                // After the observer, not before: [MdnsResponder.serveOne] hands the answer's payload back so a
                // caller can look at what it just sent, and this loop is that caller. Nothing refers to it once
                // [onResponse] returns — an observer that wants to keep the bytes has to copy them.
                if (response is MdnsResponse.Answer) response.payload.releaseAfterSend()
                if (response is MdnsResponse.Silent && response.reason == MdnsSilenceReason.NotAQuery) {
                    datagram.payload.position(start)
                    deliver(MdnsMessage.decodeAnswers(datagram.payload))
                }
            } finally {
                // The RECEIVED datagram, distinct from the answer released above: this loop consumes it
                // rather than transferring it, so it is the last reader (see [releaseReceived]). Safe
                // because nothing outlives the iteration — an `AnswerRecord` is a String plus a numeric
                // `IpAddress`, and `deliver` completes its waiters with that value, not with the slice.
                datagram.payload.releaseReceived()
            }
        }
    }

    // Hand each decoded answer to every query waiting on that (name, type). A record nobody asked for is a
    // neighbour's announcement on the shared group — dropped, never cached (we keep no cache to poison).
    private suspend fun deliver(records: List<MdnsMessage.AnswerRecord>) {
        for (record in records) {
            val key = PendingKey(record.name.lowercase(), MdnsMessage.typeOf(record.address))
            val waiters = lock.withLock { pending.remove(key) } ?: continue
            for (waiter in waiters) waiter.complete(record.address)
        }
    }

    private fun familyOf(address: IpAddress): AddressFamily =
        when (address) {
            is IpAddress.V4 -> AddressFamily.IPv4
            is IpAddress.V6 -> AddressFamily.IPv6
        }

    /** One family's live socket and the dispatch loop reading it. */
    private class BoundFamily(
        val socket: MdnsGroupSocket,
        val loop: Job,
    )

    /** What an outstanding resolution is waiting for: a name, in a record type. */
    private data class PendingKey(
        val name: String,
        val qType: Int,
    )
}

/** Default per-family query budget — a one-shot query answered by an on-link responder is sub-second. */
public val DEFAULT_MDNS_QUERY_TIMEOUT: Duration = 2.seconds

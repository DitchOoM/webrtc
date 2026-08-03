@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressFamily
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.Datagram
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.Ecn
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.stun.RawAttribute
import com.ditchoom.webrtc.stun.StunAttributeType
import com.ditchoom.webrtc.stun.StunClass
import com.ditchoom.webrtc.stun.StunDecodeResult
import com.ditchoom.webrtc.stun.StunErrorCode
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.StunMessageBuilder
import com.ditchoom.webrtc.stun.StunMethod
import com.ditchoom.webrtc.stun.TURN_FAMILY_IPV6
import com.ditchoom.webrtc.stun.TransactionId
import com.ditchoom.webrtc.stun.asErrorCode
import com.ditchoom.webrtc.stun.asLifetimeSeconds
import com.ditchoom.webrtc.stun.asText
import com.ditchoom.webrtc.stun.asXorMappedAddress
import com.ditchoom.webrtc.stun.longTermCredentialKey
import com.ditchoom.webrtc.stun.ofLifetime
import com.ditchoom.webrtc.stun.ofRequestedAddressFamily
import com.ditchoom.webrtc.stun.ofRequestedTransport
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * A **TURN relay allocation** (RFC 8656) presented as an ordinary [AddressedDatagramChannel] — the trick that
 * keeps the relay's complexity out of the sans-io [IceAgent] and its driver. The agent gathers a relay
 * candidate whose base is the allocation's relayed address and simply sends from it; this wrapper
 * encapsulates each datagram in a Send indication to the TURN server (creating a permission first) and
 * decapsulates inbound Data indications back into plain [Datagram]s. So `channels[relayedBase] =
 * TurnAllocation` slots into the driver with **no relay-specific code anywhere else**.
 *
 * It owns [underlying] (a dedicated socket carrying only TURN traffic), demultiplexing responses (to
 * pending requests) from Data indications (to the inbound queue) in one loop on [scope]. Auth is the
 * **long-term** credential (RFC 8489 §9.2.2): the first Allocate goes out unauthenticated, and the
 * server's 401 supplies the REALM that MESSAGE-INTEGRITY's key — `MD5(username:realm:password)`, via
 * [longTermCredentialKey] — is derived from. Once allocated it keeps itself alive per [maintenance] —
 * Refresh (§8) at a fraction of the **granted** LIFETIME and CreatePermission (§9) re-installation for
 * every permitted address — and deallocates (Refresh with LIFETIME=0) on [close]. Call [allocate] once
 * before use.
 *
 * ## Every request retransmits, because TURN runs over UDP
 *
 * Each request is (re)transmitted every [retransmitInterval] until its response arrives or the caller's
 * budget elapses — the same "RFC 8489 §6.2.1 spirit" loop [gatherServerReflexive] uses, and for the same
 * reason: a single dropped datagram must not cost the whole exchange. Before this existed, every TURN
 * request was sent exactly once, and each of the three had its own way of failing badly — a lost Allocate
 * cost the relay candidate outright (fatal behind a symmetric NAT, where the relay is the only path); a
 * lost CreatePermission lapsed the permission silently; and a lost **Refresh** ended the maintenance loop
 * for good, which is to say a single lost packet reintroduced exactly the expiry this class exists to
 * prevent.
 *
 * Retransmissions re-slice the *same* encoded request, so every copy is byte-identical: a retransmission
 * carrying a fresh transaction id would be a new transaction, and one re-signed under a rotated nonce
 * would not match the challenge it was built for.
 *
 * ## No outcome is a null
 *
 * [allocate] answers with a sealed [TurnAllocationResult], and every internal exchange with a sealed
 * [TurnExchange], because the distinction that matters here is precisely the one a nullable return
 * erases: **silence is not rejection**. A Refresh that goes unanswered may be sitting behind a lossy
 * path with an allocation still very much alive, and must be retried; a Refresh the server *answers*
 * with an error is an allocation that is genuinely gone, and retrying it forever is pointless. Collapsing
 * both into `null` is what made a single lost datagram terminal, so the type no longer permits it.
 *
 * **Known limitations:** [pending]/[permitted] are plain collections safe under the single-threaded
 * test/driver dispatcher; a genuinely multi-threaded scope would need synchronization. A response's
 * attribute slices are read by the awaiting request before the demux loop's next receive, safe against
 * the vnet's copy-on-receive; a receive-buffer-pooling channel would want it copied too.
 */
public class TurnAllocation(
    private val underlying: AddressedDatagramChannel,
    private val server: SocketAddress,
    private val username: String,
    private val password: String,
    private val random: Random,
    private val scope: CoroutineScope,
    private val bufferFactory: BufferFactory = BufferFactory.Default,
    private val maintenance: TurnMaintenance = TurnMaintenance.Renewing(),
    private val retransmitInterval: Duration = DEFAULT_GATHER_RTO,
) : AddressedDatagramChannel {
    private val pending = HashMap<TransactionId, CompletableDeferred<StunMessage>>()
    private val inbound = Channel<Datagram>(Channel.UNLIMITED)

    // Permitted peers by host, keeping the address itself: a permission has to be RE-installed before it
    // lapses (§9), and XOR-PEER-ADDRESS needs a transport address, not just the host string we key on.
    private val permitted = LinkedHashMap<String, SocketAddress>()
    private var credential: Credential = Credential.Unchallenged
    private var relayed: SocketAddress? = null
    private var closed = false
    private var loopStarted = false
    private var maintenanceJob: Job? = null

    // The relayed address once allocated, else the address we are actually bound to. `underlying` is
    // addressed-mode, so it is bound by construction and its localAddress needs no unwrap — the old
    // `?: server` fallback stood only for a getsockname that could not fail here anyway.
    override val localAddress: SocketAddress get() = relayed ?: underlying.localAddress
    override val capabilities: DatagramCapabilities get() = underlying.capabilities
    override val isOpen: Boolean get() = !closed && underlying.isOpen
    override val maxWritableSize: Int get() = (underlying.maxWritableSize - TURN_OVERHEAD_BYTES).coerceAtLeast(0)

    /**
     * Allocate a relayed transport address (RFC 8656 §7), retrying once with the server's REALM/NONCE if
     * challenged (401). Starts the demultiplex loop — and, on success, the [maintenance] loop — as a side
     * effect. [timeout] bounds each of the two exchanges, within which the request retransmits every
     * [retransmitInterval].
     */
    public suspend fun allocate(timeout: Duration = DEFAULT_GATHER_TIMEOUT): TurnAllocationResult {
        startLoop()
        var exchange = request(timeout) { allocateRequest(it) }
        if (exchange is TurnExchange.Refused) {
            // Only retry once the challenge is actually usable. A 401 missing REALM or NONCE yields no
            // long-term key, so the retry could only repeat the same unauthenticated request — fall
            // through to the failure below instead of burning a second budget on it.
            val challenge = exchange.response.asChallenge()
            if (challenge != null) {
                credential = challenge
                exchange = request(timeout) { allocateRequest(it) }
            }
        }
        val response =
            when (exchange) {
                is TurnExchange.Succeeded -> exchange.response
                is TurnExchange.Refused -> return TurnAllocationResult.Unavailable.Rejected(exchange.error)
                is TurnExchange.Malformed -> return TurnAllocationResult.Unavailable.MalformedResponse
                TurnExchange.Unanswered -> return TurnAllocationResult.Unavailable.NoResponse
            }
        val relayedAddress =
            response.firstOrNull(StunAttributeType.XorRelayedAddress)?.asXorMappedAddress(response.transactionId)?.toSocketAddress()
                ?: return TurnAllocationResult.Unavailable.MalformedResponse
        relayed = relayedAddress
        startMaintenance(response.grantedLifetime() ?: DEFAULT_ALLOCATION_LIFETIME)
        return TurnAllocationResult.Allocated(relayedAddress)
    }

    override suspend fun send(
        payload: ReadBuffer,
        to: SocketAddress,
        options: DatagramSendOptions,
    ) {
        // No `requireNotNull` any more: a relay send needs a destination, and the addressed sink type
        // now says so — the call that used to trip that check no longer parses.
        val peer = to
        ensurePermission(peer)
        val transactionId = TransactionId.random(random)
        val indication =
            StunMessageBuilder
                .of(StunClass.Indication, StunMethod.Send, transactionId, bufferFactory)
                .add(RawAttribute.ofXorAddress(StunAttributeType.XorPeerAddress, peer.toTransportAddress(), transactionId, bufferFactory))
                .add(RawAttribute.ofRaw(StunAttributeType.Data, payload))
                .encode(bufferFactory)
        underlying.send(indication, to = server)
    }

    override suspend fun receive(): DatagramReadResult {
        val datagram = inbound.receiveCatching().getOrNull()
        return if (datagram != null) DatagramReadResult.Received(datagram) else DatagramReadResult.Closed()
    }

    /**
     * Release the relay (RFC 8656 §8.2: Refresh with LIFETIME=0) and then the socket, so a closed session
     * does not hold a relay port for the remainder of its lifetime.
     *
     * The deallocation has to ride a coroutine — [AddressedDatagramChannel.close] is not suspending — but
     * [underlying] must be closed either way, including when [scope] is already cancelled underneath us
     * (the ICE driver retires a generation's relay socket and tears the scope down in the same breath).
     * Hence [CoroutineStart.ATOMIC]: the body always begins, so its `finally` always runs and always
     * releases the transport, whether the Refresh went out or was cancelled at the first suspension.
     */
    @OptIn(DelicateCoroutinesApi::class) // CoroutineStart.ATOMIC — see above; the point IS the un-skippable finally
    override fun close() {
        if (closed) return
        closed = true
        maintenanceJob?.cancel()
        if (relayed == null) {
            releaseTransport()
            return
        }
        scope.launch(start = CoroutineStart.ATOMIC) {
            try {
                requestWithChallengeRetry { refreshRequest(it, Duration.ZERO) }
            } finally {
                releaseTransport()
            }
        }
    }

    private fun releaseTransport() {
        inbound.close()
        underlying.close()
    }

    // Ensure a permission exists for [peer]'s IP so its inbound data reaches us (RFC 8656 §9).
    private suspend fun ensurePermission(peer: SocketAddress) {
        if (peer.host in permitted) return
        if (createPermission(listOf(peer)) is TurnExchange.Succeeded) permitted[peer.host] = peer
    }

    /**
     * Install (or re-install) a permission for every address in [peers] — RFC 8656 §9 lets one
     * CreatePermission carry several XOR-PEER-ADDRESSes, so re-installation costs one round trip
     * regardless of how many peers the session has. Retries once on a stale challenge — see
     * [requestWithChallengeRetry], which is why a re-installation surviving a nonce rotation is free here.
     */
    private suspend fun createPermission(peers: List<SocketAddress>): TurnExchange =
        requestWithChallengeRetry { transactionId -> permissionRequest(transactionId, peers) }

    private fun permissionRequest(
        transactionId: TransactionId,
        peers: List<SocketAddress>,
    ): StunMessageBuilder {
        val builder = builderFor(StunMethod.CreatePermission, transactionId)
        for (peer in peers) {
            builder.add(
                RawAttribute.ofXorAddress(
                    StunAttributeType.XorPeerAddress,
                    peer.toTransportAddress(),
                    transactionId,
                    bufferFactory,
                ),
            )
        }
        return builder
    }

    /**
     * The keep-alive loop: one coroutine holding two independent countdowns — the allocation's (reset
     * from each Refresh's *granted* LIFETIME, so a server that grants less than we asked for shortens our
     * own cadence) and the permission set's (a protocol constant, [TurnMaintenance.Renewing]'s stated
     * assumption). It sleeps to whichever is nearer, which keeps the two schedules independent without a
     * second coroutine or a shared deadline heap.
     *
     * An **unanswered** round re-arms at the policy's retry delay instead of its full one, and the loop
     * survives it. Only a server that answers and refuses ends the loop: that allocation is gone, and
     * ICE consent is the layer that owns noticing.
     */
    private fun startMaintenance(granted: Duration) {
        val policy =
            when (maintenance) {
                is TurnMaintenance.Renewing -> maintenance
                TurnMaintenance.None -> return
            }
        if (maintenanceJob != null) return
        maintenanceJob =
            scope.launch {
                var lifetime = granted
                var untilRefresh = policy.refreshDelayFor(lifetime)
                var untilPermission = policy.permissionRefreshDelay
                while (true) {
                    val sleep = minOf(untilRefresh, untilPermission)
                    delay(sleep)
                    untilRefresh -= sleep
                    untilPermission -= sleep
                    if (untilPermission <= Duration.ZERO) {
                        untilPermission =
                            when (reinstallPermissions()) {
                                PermissionOutcome.Current -> policy.permissionRefreshDelay
                                // The set may already have lapsed, and the next inbound datagram is what
                                // pays for it. Come back sooner rather than in another full cycle.
                                PermissionOutcome.Unanswered -> policy.permissionRetryDelay
                            }
                    }
                    if (untilRefresh <= Duration.ZERO) {
                        when (val outcome = refreshAllocation(lifetime)) {
                            is RefreshOutcome.Renewed -> {
                                lifetime = outcome.lifetime
                                untilRefresh = policy.refreshDelayFor(lifetime)
                            }
                            // The server spoke and said no. Nothing a retry can recover.
                            RefreshOutcome.Gone -> return@launch
                            // Silence. The allocation is probably still there; the margin left by
                            // refreshAt is exactly what this retry is meant to spend.
                            RefreshOutcome.Unanswered -> untilRefresh = policy.refreshRetryDelayFor(lifetime)
                        }
                    }
                }
            }
    }

    // Re-install EVERY permission, not just the one a datagram is headed for — the failure this fixes is
    // silent and inbound-only, so the address that lapses is precisely the one nothing is asking about.
    private suspend fun reinstallPermissions(): PermissionOutcome {
        val peers = permitted.values.toList()
        if (peers.isEmpty()) return PermissionOutcome.Current
        return when (createPermission(peers)) {
            TurnExchange.Unanswered -> PermissionOutcome.Unanswered
            // A refusal is not worth hurrying back for: the server is answering, and the next round at
            // the normal cadence is as likely to succeed as one three seconds from now.
            is TurnExchange.Succeeded, is TurnExchange.Refused, is TurnExchange.Malformed -> PermissionOutcome.Current
        }
    }

    // Refresh the allocation (RFC 8656 §8). Distinguishes "the server refused" from "nobody answered" —
    // see [RefreshOutcome]; conflating them is what used to make one lost datagram terminal.
    private suspend fun refreshAllocation(current: Duration): RefreshOutcome =
        when (val exchange = requestWithChallengeRetry { refreshRequest(it, current) }) {
            is TurnExchange.Succeeded -> RefreshOutcome.Renewed(exchange.response.grantedLifetime() ?: current)
            // Either way the server spoke, and what it said was no. An answer we cannot parse is still
            // an answer: retrying it forever would be the same request meeting the same refusal.
            is TurnExchange.Refused, is TurnExchange.Malformed -> RefreshOutcome.Gone
            TurnExchange.Unanswered -> RefreshOutcome.Unanswered
        }

    private fun refreshRequest(
        transactionId: TransactionId,
        lifetime: Duration,
    ): StunMessageBuilder =
        builderFor(StunMethod.Refresh, transactionId)
            .add(RawAttribute.ofLifetime(lifetime.inWholeSeconds.toUInt(), bufferFactory))

    /**
     * Send a request and, if the server rejects it with a **stale challenge** — 438 Stale Nonce (RFC 8656
     * §8: a long-lived allocation outlives the nonce it was created under) or a 401 carrying a fresh one —
     * adopt the new REALM/NONCE and retry exactly once. Only the challenge material is re-read; the key is
     * re-derived from the new realm by [asChallenge], in the one place that derivation lives.
     */
    private suspend fun requestWithChallengeRetry(build: (TransactionId) -> StunMessageBuilder): TurnExchange {
        val first = request(DEFAULT_GATHER_TIMEOUT, build)
        if (first !is TurnExchange.Refused || !first.error.isStaleChallenge()) return first
        val challenge = first.response.asChallenge() ?: return first
        credential = challenge
        return request(DEFAULT_GATHER_TIMEOUT, build)
    }

    private fun StunErrorCode.isStaleChallenge(): Boolean = code == STALE_NONCE || code == UNAUTHORIZED

    private fun StunMessage.grantedLifetime(): Duration? =
        firstOrNull(StunAttributeType.Lifetime)?.asLifetimeSeconds()?.let { it.toLong().seconds }

    private fun startLoop() {
        if (loopStarted) return
        loopStarted = true
        scope.launch {
            while (true) {
                val datagram =
                    when (val result = underlying.receiveOrClosed()) {
                        is DatagramReadResult.Received -> result.datagram
                        is DatagramReadResult.Closed -> return@launch
                    }
                val message = (StunMessage.decode(datagram.payload) as? StunDecodeResult.Success)?.message ?: continue
                when (message.messageType.stunClass) {
                    StunClass.SuccessResponse, StunClass.ErrorResponse -> pending.remove(message.transactionId)?.complete(message)
                    StunClass.Indication -> if (message.messageType.method == StunMethod.Data) enqueueData(message)
                    StunClass.Request -> Unit
                }
            }
        }
    }

    private fun enqueueData(indication: StunMessage) {
        val peer =
            indication.firstOrNull(StunAttributeType.XorPeerAddress)?.asXorMappedAddress(indication.transactionId)?.toSocketAddress()
                ?: return
        val data = indication.firstOrNull(StunAttributeType.Data)?.value ?: return
        val length = data.remaining()
        val copy: PlatformBuffer = bufferFactory.allocate(maxOf(1, length))
        copy.write(data)
        copy.resetForRead()
        copy.setLimit(length)
        inbound.trySend(Datagram(payload = copy, peer = peer, ecn = Ecn.Unknown))
    }

    /**
     * Send a request built for a fresh transaction id and await its response, retransmitting it every
     * [retransmitInterval] until one arrives or [budget] elapses (RFC 8489 §6.2.1 spirit — the same shape
     * [gatherServerReflexive] uses on the Binding it sends from the same kind of socket).
     *
     * The request is encoded **once** and re-sliced per transmission: a retransmission has to be the same
     * transaction, byte for byte, and a socket write that advances the buffer position would otherwise
     * exhaust the shared request on the second send.
     */
    private suspend fun request(
        budget: Duration,
        build: (TransactionId) -> StunMessageBuilder,
    ): TurnExchange {
        val transactionId = TransactionId.random(random)
        val deferred = CompletableDeferred<StunMessage>()
        pending[transactionId] = deferred
        val builder = build(transactionId)
        // MESSAGE-INTEGRITY only once challenged: before the 401 there is no realm, so no long-term key
        // exists to sign with, and RFC 8656 §7.1 expects that first Allocate to be unauthenticated.
        val authenticated =
            when (val c = credential) {
                Credential.Unchallenged -> builder
                is Credential.Challenged -> builder.addMessageIntegrity(c.key)
            }
        val encoded = authenticated.encode(bufferFactory)
        val response =
            withTimeoutOrNull(budget) {
                while (true) {
                    underlying.send(encoded.slice(), to = server)
                    val answer = withTimeoutOrNull(retransmitInterval) { deferred.await() }
                    // Null here means only "not within this interval" — retransmit and keep waiting. The
                    // budget above is what turns sustained silence into TurnExchange.Unanswered.
                    if (answer != null) return@withTimeoutOrNull answer
                }
                @Suppress("UNREACHABLE_CODE")
                null
            }
        pending.remove(transactionId)
        return response?.classify() ?: TurnExchange.Unanswered
    }

    private fun StunMessage.classify(): TurnExchange =
        when (messageType.stunClass) {
            StunClass.SuccessResponse -> TurnExchange.Succeeded(this)
            else ->
                firstOrNull(StunAttributeType.ErrorCode)?.asErrorCode()?.let { TurnExchange.Refused(this, it) }
                    ?: TurnExchange.Malformed(this)
        }

    private fun allocateRequest(transactionId: TransactionId): StunMessageBuilder {
        val builder =
            authed(StunMessageBuilder.of(StunClass.Request, StunMethod.Allocate, transactionId, bufferFactory))
                .add(RawAttribute.ofRequestedTransport(factory = bufferFactory))
        // RFC 8656 §7.2: without REQUESTED-ADDRESS-FAMILY the server allocates an IPv4 relay. A v6 TURN
        // server has no usable v4 relay address (it falls back to loopback → an unreachable relay candidate
        // → ICE AllPairsFailed), so ask for the family that matches the server we are allocating on. v4 is
        // left to the default (attribute omitted), so the v4 path is wire-unchanged.
        if (server.family == AddressFamily.IPv6) {
            builder.add(RawAttribute.ofRequestedAddressFamily(TURN_FAMILY_IPV6, bufferFactory))
        }
        return builder
    }

    private fun builderFor(
        method: StunMethod,
        transactionId: TransactionId,
    ): StunMessageBuilder = authed(StunMessageBuilder.of(StunClass.Request, method, transactionId, bufferFactory))

    // Add USERNAME and, once challenged, REALM/NONCE (RFC 8656 long-term-credential form).
    private fun authed(builder: StunMessageBuilder): StunMessageBuilder {
        builder.add(RawAttribute.ofText(StunAttributeType.Username, username, bufferFactory))
        when (val c = credential) {
            Credential.Unchallenged -> Unit
            is Credential.Challenged -> {
                builder.add(RawAttribute.ofText(StunAttributeType.Realm, c.realm, bufferFactory))
                builder.add(RawAttribute.ofText(StunAttributeType.Nonce, c.nonce, bufferFactory))
            }
        }
        return builder
    }

    // A 401 carrying both REALM and NONCE is a usable challenge; anything else leaves us unchallenged.
    private fun StunMessage.asChallenge(): Credential.Challenged? {
        val realm = firstOrNull(StunAttributeType.Realm)?.asText() ?: return null
        val nonce = firstOrNull(StunAttributeType.Nonce)?.asText() ?: return null
        return Credential.Challenged(realm, nonce, longTermCredentialKey(username, realm, password))
    }

    /**
     * Where this allocation stands with the server's long-term credential (RFC 8656 §7.1). The key is
     * derivable **only** from a realm we have been challenged with, so realm, nonce and key travel as
     * one value rather than as three separately-nullable fields that could disagree — "authenticated
     * but with no realm" is not representable. The key is derived once per challenge and reused: it
     * depends on nothing per-request, and HMAC reads it non-destructively.
     */
    private sealed interface Credential {
        /** Before the server's 401. No realm ⇒ no key ⇒ requests go out unauthenticated. */
        data object Unchallenged : Credential

        /** Not a `data class`: [key] is a buffer, so generated structural equality would be meaningless. */
        class Challenged(
            val realm: String,
            val nonce: String,
            val key: ReadBuffer,
        ) : Credential
    }

    /**
     * The outcome of one request/response exchange with the TURN server, after the retransmission chain
     * has run to its end. The reason this is not `StunMessage?` is [Unanswered] versus [Refused]: they
     * are the difference between a path that dropped our datagrams and a server that turned us down, and
     * every caller in this class treats them differently.
     */
    private sealed interface TurnExchange {
        /** The server answered with a success response. */
        class Succeeded(
            val response: StunMessage,
        ) : TurnExchange

        /** The server answered with an error response carrying a decodable ERROR-CODE. */
        class Refused(
            val response: StunMessage,
            val error: StunErrorCode,
        ) : TurnExchange

        /** The server answered with an error response we could not read an ERROR-CODE out of. */
        class Malformed(
            val response: StunMessage,
        ) : TurnExchange

        /** Every transmission went unanswered within the budget. Says nothing about the allocation. */
        data object Unanswered : TurnExchange
    }

    /** What one Refresh round establishes about the allocation's fate — see [startMaintenance]. */
    private sealed interface RefreshOutcome {
        /** Renewed; the server granted [lifetime], which re-arms the next Refresh. */
        class Renewed(
            val lifetime: Duration,
        ) : RefreshOutcome

        /** The server answered and refused. The allocation is gone; stop maintaining it. */
        data object Gone : RefreshOutcome

        /** Nobody answered. The allocation is probably alive — retry inside the margin. */
        data object Unanswered : RefreshOutcome
    }

    /**
     * What one permission re-installation round establishes. Two cases, not three: the only question the
     * maintenance loop asks is *how soon to come back*, and a refusal answers that the same way a success
     * does — the server is reachable and talking, so the normal cadence applies.
     */
    private sealed interface PermissionOutcome {
        /** The set is installed, or there was nothing to install. Normal cadence. */
        data object Current : PermissionOutcome

        /** Nobody answered; the set may already have lapsed. Come back sooner. */
        data object Unanswered : PermissionOutcome
    }

    private companion object {
        const val TURN_OVERHEAD_BYTES = 40 // Send-indication STUN header + XOR-PEER-ADDRESS + DATA TLV
    }
}

/**
 * The outcome of [TurnAllocation.allocate] — a sealed result rather than a nullable address, mirroring
 * [ServerReflexiveResult] for the same reason: a relay that allocated always carries its relayed
 * transport address, and the reasons one did not are protocol-distinct rather than a single lumped
 * sentinel. It is what makes "your credentials were rejected" ([Unavailable.Rejected] with a 401)
 * distinguishable from "the relay never answered" ([Unavailable.NoResponse]); as a nullable return both
 * surfaced identically, as "no relay candidate".
 */
public sealed interface TurnAllocationResult {
    /** The server allocated [relayed] for us. */
    public data class Allocated(
        public val relayed: SocketAddress,
    ) : TurnAllocationResult

    /** No relayed address was allocated — see the exhaustive cause. */
    public sealed interface Unavailable : TurnAllocationResult {
        /** No response arrived within the budget, retransmissions included: silent server or lossy path. */
        public data object NoResponse : Unavailable

        /** The server answered and declined — [error] carries the code (401 credentials, 486 quota, …). */
        public data class Rejected(
            public val error: StunErrorCode,
        ) : Unavailable

        /** A response we could not act on: an error without an ERROR-CODE, or a success without a relay. */
        public data object MalformedResponse : Unavailable
    }
}

// File-private, not companion constants: a `const val` in the companion is emitted as a PUBLIC static
// field on TurnAllocation (see the one above, which predates this), and an error code is not API.
private const val UNAUTHORIZED = 401
private const val STALE_NONCE = 438 // RFC 8656 §18: the nonce a long-lived allocation was created under expired

/** RFC 8656 §7.2's default allocation lifetime, used only when a server omits LIFETIME entirely. */
private val DEFAULT_ALLOCATION_LIFETIME: Duration = 600.seconds

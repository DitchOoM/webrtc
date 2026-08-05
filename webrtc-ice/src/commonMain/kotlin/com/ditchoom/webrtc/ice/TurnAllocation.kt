@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
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
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
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
    private val bufferFactory: BufferFactory = networkBuffer(),
    private val maintenance: TurnMaintenance = TurnMaintenance.Renewing(),
    private val retransmitInterval: Duration = DEFAULT_GATHER_RTO,
) : AddressedDatagramChannel {
    private val pending = HashMap<TransactionId, CompletableDeferred<ReceivedStunMessage>>()
    private val inbound = Channel<Datagram>(Channel.UNLIMITED)

    // Permitted peers by host, keeping the address itself: a permission has to be RE-installed before it
    // lapses (§9), and XOR-PEER-ADDRESS needs a transport address, not just the host string we key on.
    private val permitted = LinkedHashMap<String, SocketAddress>()

    private val permissionRefusals =
        Channel<TurnPermissionRefusal>(PERMISSION_REFUSAL_DIAGNOSTIC_BUFFER, BufferOverflow.DROP_OLDEST)

    private var credential: Credential = Credential.Unchallenged
    private var relayed: SocketAddress? = null
    private var closed = false
    private var loopStarted = false
    private var maintenanceJob: Job? = null

    // The relayed address once allocated, else the address we are actually bound to. `underlying` is
    // addressed-mode, so it is bound by construction and its localAddress needs no unwrap — the old
    // `?: server` fallback stood only for a getsockname that could not fail here anyway.
    override val localAddress: SocketAddress get() = relayed ?: underlying.localAddress

    /**
     * CreatePermissions this server **answered and refused** (RFC 8656 §9) — a relay path that will not
     * carry traffic for that peer, said in the one place that knows why.
     *
     * Never silence: an unanswered request is absorbed by the retransmit loop and is not reported here.
     * See [TurnPermissionRefusal] for what a refusal costs and which codes to expect.
     *
     * **Bounded and lossy**, matching [IceAgentDriver.transmitFailed]: the producer is the send path, so an
     * allocation whose permissions are all refused produces one of these per relayed datagram, and neither
     * growing the heap for a collector nobody must attach nor stalling the send path on a rendezvous
     * channel is acceptable. The newest are the ones describing what the server is refusing *now*.
     */
    public val permissionRefused: Flow<TurnPermissionRefusal> get() = permissionRefusals.receiveAsFlow()
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
            // `asChallenge` derives realm/nonce Strings and a fresh key, so nothing it returns outlives
            // the payload this discards — which it must, since the retry replaces the exchange entirely.
            val challenge = exchange.response.asChallenge()
            if (challenge != null) {
                exchange.release()
                credential = challenge
                exchange = request(timeout) { allocateRequest(it) }
            }
        }
        return exchange.consuming { settled ->
            val response =
                when (settled) {
                    is TurnExchange.Succeeded -> settled.response
                    is TurnExchange.Refused -> return@consuming TurnAllocationResult.Unavailable.Rejected(settled.error)
                    is TurnExchange.Malformed -> return@consuming TurnAllocationResult.Unavailable.MalformedResponse
                    TurnExchange.Unanswered -> return@consuming TurnAllocationResult.Unavailable.NoResponse
                    is TurnExchange.NeverSent -> return@consuming TurnAllocationResult.Unavailable.SendFailed(settled.cause)
                }
            // Both reads below produce values — a SocketAddress and a Duration — so the payload is
            // finished with by the time `consuming` releases it.
            val relayedAddress =
                response.firstOrNull(StunAttributeType.XorRelayedAddress)?.asXorMappedAddress(response.transactionId)?.toSocketAddress()
                    ?: return@consuming TurnAllocationResult.Unavailable.MalformedResponse
            relayed = relayedAddress
            startMaintenance(response.grantedLifetime() ?: DEFAULT_ALLOCATION_LIFETIME)
            TurnAllocationResult.Allocated(relayedAddress)
        }
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
        try {
            // Unguarded on purpose, matching `IceDataTransport.send`: this is the relayed *application*
            // data path, so a failure is the caller's to see rather than ours to absorb. The buffer is
            // still released on every exit by the `finally` below, which is the half that must not
            // depend on the send succeeding.
            underlying.send(indication, to = server)
        } finally {
            // The Send indication is a fresh buffer wrapping a COPY of [payload] (`ofRaw` copies into the
            // padded value), so it is ours alone and its last read is the send. One of these per relayed
            // datagram is the hottest allocation in the stack — leaking it grows a relayed session
            // without bound, which is a different and worse thing than leaking one per gather.
            indication.freeNativeMemory()
        }
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
        createPermission(listOf(peer)).consuming { exchange ->
            when (exchange) {
                is TurnExchange.Succeeded -> permitted[peer.host] = peer
                // The server spoke and said no. Left un-permitted on purpose — the next send retries,
                // which is right for a refusal that a re-derived nonce or a peer's own re-gather could
                // clear — but reported, because a refusal that only manifests as an unreachable relay is
                // indistinguishable from a peer that never answered. See [TurnPermissionRefusal].
                is TurnExchange.Refused -> reportRefusal(peer, exchange.error)
                // Silence, a malformed answer, or nothing ever sent: all three are "no permission yet,
                // try again", and none of them is the server refusing. Conflating them here would report
                // a lossy path as a policy decision.
                TurnExchange.Unanswered, is TurnExchange.Malformed, is TurnExchange.NeverSent -> Unit
            }
        }
    }

    // The refusal channel's producer side. `localAddress` rather than `relayed` because it is the same
    // address once allocated and never null — and a permission cannot be refused before an allocation
    // exists to refuse it on.
    private fun reportRefusal(
        peer: SocketAddress,
        error: StunErrorCode,
    ) {
        permissionRefusals.trySend(
            TurnPermissionRefusal(
                relay = localAddress.toTransportAddress(),
                peer = peer.toTransportAddress(),
                error = error,
            ),
        )
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
        return createPermission(peers).consuming { exchange ->
            when (exchange) {
                // Treated as silence on purpose: the maintenance loop's only question is *how soon to come
                // back*, and both answers are "sooner". The distinction is preserved where it changes a
                // caller's conclusion — `allocate()` above — not where it would only add an unused arm.
                TurnExchange.Unanswered, is TurnExchange.NeverSent -> PermissionOutcome.Unanswered
                // A refusal is not worth hurrying back for: the server is answering, and the next round at
                // the normal cadence is as likely to succeed as one three seconds from now. It IS worth
                // reporting: one refusal here lapses a permission that was working, so the path stops
                // carrying inbound traffic with nothing else to show for it. §9 refuses the whole request, so
                // every peer in it lost its permission — one observation each, naming the peers by address
                // rather than making a collector infer the set.
                is TurnExchange.Refused -> {
                    for (peer in peers) reportRefusal(peer, exchange.error)
                    PermissionOutcome.Current
                }
                is TurnExchange.Succeeded, is TurnExchange.Malformed -> PermissionOutcome.Current
            }
        }
    }

    // Refresh the allocation (RFC 8656 §8). Distinguishes "the server refused" from "nobody answered" —
    // see [RefreshOutcome]; conflating them is what used to make one lost datagram terminal.
    private suspend fun refreshAllocation(current: Duration): RefreshOutcome =
        requestWithChallengeRetry { refreshRequest(it, current) }.consuming { exchange ->
            when (exchange) {
                // `grantedLifetime()` is a Duration read out of the slice, not the slice itself.
                is TurnExchange.Succeeded -> RefreshOutcome.Renewed(exchange.response.grantedLifetime() ?: current)
                // Either way the server spoke, and what it said was no. An answer we cannot parse is
                // still an answer: retrying it forever would be the same request meeting the same refusal.
                is TurnExchange.Refused, is TurnExchange.Malformed -> RefreshOutcome.Gone
                TurnExchange.Unanswered, is TurnExchange.NeverSent -> RefreshOutcome.Unanswered
            }
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
        // Returned rather than consumed on both of these paths: the caller still has to read it, so it
        // stays the owner. Only the branch that DISCARDS `first` for a retry releases it here.
        val challenge = first.response.asChallenge() ?: return first
        first.release()
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
                val message = (StunMessage.decode(datagram.payload) as? StunDecodeResult.Success)?.message
                if (message == null) {
                    // Undecodable: this loop is its only reader (see [releaseReceived]).
                    datagram.payload.releaseReceived()
                    continue
                }
                when (message.messageType.stunClass) {
                    StunClass.SuccessResponse, StunClass.ErrorResponse -> {
                        // TRANSFER to the awaiting [request] call, which owns it from here. Its attributes
                        // are slices of this payload and are read on that coroutine, so releasing here
                        // would hand the awaiter reclaimed memory. A response nobody is waiting for — a
                        // duplicate, or one that arrived after its budget unwound — has no new owner, so
                        // this loop is still the last reader of it.
                        val waiter = pending.remove(message.transactionId)
                        val transferred = ReceivedStunMessage(message, datagram.payload)
                        if (waiter == null || !waiter.complete(transferred)) datagram.payload.releaseReceived()
                    }
                    // [enqueueData] copies the DATA attribute into a buffer of its own, so the datagram
                    // it was sliced from is finished with either way — including when the copy is refused.
                    StunClass.Indication -> {
                        if (message.messageType.method == StunMethod.Data) enqueueData(message)
                        datagram.payload.releaseReceived()
                    }
                    StunClass.Request -> datagram.payload.releaseReceived()
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
     * The request is encoded **once** and that same buffer rides every transmission: a retransmission has
     * to be the same transaction, byte for byte. It does not need a fresh slice per attempt — socket's
     * datagram channels are contractually *send-does-not-consume*, and every backend honours it (io_uring
     * reads `nativeAddress + position()`; the NIO, Node and Apple paths take their own internal view).
     * Slicing per attempt would be actively wrong on a pooled factory, where a slice takes a reference on
     * the chunk: one per retransmission, none of them released, pins the buffer for good.
     *
     * The `finally` covers all three exits — answered (returns from inside the loop), silent (unwound by
     * [budget]) and cancelled — because each of them owes the same single release.
     */
    private suspend fun request(
        budget: Duration,
        build: (TransactionId) -> StunMessageBuilder,
    ): TurnExchange {
        val transactionId = TransactionId.random(random)
        val deferred = CompletableDeferred<ReceivedStunMessage>()
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
        // Remembers a refused transmission so an exchange in which *nothing* was ever sent can say so,
        // rather than reporting the TURN server as silent. See [TurnExchange.NeverSent].
        var lastSendFailure: Throwable? = null
        var everSent = false
        try {
            val response =
                withTimeoutOrNull(budget) {
                    while (true) {
                        // Same reasoning as `gatherServerReflexive`: a refused send is this attempt, not
                        // the request. Retransmission is what makes a lost Allocate/CreatePermission/
                        // Refresh survivable at all (#137), and a raised `sendto` would have skipped
                        // straight past it — losing the relay candidate outright behind a symmetric NAT,
                        // where it is the only path. Sustained failure still ends at [budget] as
                        // `TurnExchange.Unanswered`, which callers already handle.
                        when (val sent = underlying.sendOrFailure(encoded, to = server)) {
                            IceTransmitResult.Sent -> everSent = true
                            is IceTransmitResult.Failed -> {
                                lastSendFailure = sent.cause
                                // As in `gatherServerReflexive`: an oversized request cannot become
                                // sendable by being sent again, so the budget is not spent on it.
                                if (sent.reason is IceTransmitFailureReason.PayloadTooLarge) {
                                    return@withTimeoutOrNull null
                                }
                            }
                        }
                        val answer = withTimeoutOrNull(retransmitInterval) { deferred.await() }
                        // Null here means only "not within this interval" — retransmit and keep waiting. The
                        // budget above is what turns sustained silence into TurnExchange.Unanswered.
                        if (answer != null) return@withTimeoutOrNull answer
                    }
                    @Suppress("UNREACHABLE_CODE")
                    null
                }
            response?.let { return it.classify() }
            val neverSent = lastSendFailure
            return if (!everSent && neverSent != null) TurnExchange.NeverSent(neverSent) else TurnExchange.Unanswered
        } finally {
            // Both of these are owed on every exit, cancellation included: an un-removed entry keeps a
            // dead transaction's deferred in the map for the life of the allocation, and the loop above
            // outlives its caller often enough (close() cancels the maintenance job mid-Refresh) for
            // "only on the paths that return" to be a real difference.
            // A response can land between the budget unwinding and this removal, which completes a
            // deferred nobody will ever await. That transfer has no other reader, so it is released here.
            // `getCompleted` is the only synchronous read of a settled Deferred; guarded by `isCompleted`
            // on the line above, and this is a non-suspending `finally`, so awaiting is not an option.
            pending.remove(transactionId)?.let { orphan ->
                @OptIn(ExperimentalCoroutinesApi::class)
                if (orphan.isCompleted) orphan.getCompleted().payload.releaseReceived()
            }
            encoded.freeNativeMemory()
        }
    }

    /**
     * A decoded STUN response **and the datagram it was decoded from**, moved together because they
     * cannot be separated: the message's attributes are slices of the payload. The same shape, and the
     * same reason, as `IceGathering`'s `MatchedResponse`.
     */
    private class ReceivedStunMessage(
        val message: StunMessage,
        val payload: ReadBuffer,
    )

    private fun ReceivedStunMessage.classify(): TurnExchange =
        when (message.messageType.stunClass) {
            StunClass.SuccessResponse -> TurnExchange.Succeeded(message, payload)
            else ->
                message.firstOrNull(StunAttributeType.ErrorCode)?.asErrorCode()?.let { TurnExchange.Refused(message, it, payload) }
                    ?: TurnExchange.Malformed(message, payload)
        }

    /**
     * Read [this] exchange and give its datagram back afterwards, on every exit including a throw.
     *
     * Every consumer of a [TurnExchange] goes through here, which is what makes "released exactly once"
     * a property of the shape rather than of remembering. The block may only extract **values** — a
     * `SocketAddress`, a `Duration`, a realm/nonce `String`, a `StunErrorCode` — because anything it
     * kept a reference to would be a slice of the payload this releases.
     */
    private inline fun <R> TurnExchange.consuming(block: (TurnExchange) -> R): R =
        try {
            block(this)
        } finally {
            release()
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
        /**
         * The datagram [response] was parsed out of, owned by whoever holds this exchange.
         *
         * It has to travel with the message rather than be released where the message was decoded: every
         * attribute a consumer reads — REALM, NONCE, XOR-RELAYED-ADDRESS, LIFETIME — is a *slice* of this
         * payload, so the last reader is the consumer, not the demux loop. Null on the two variants that
         * carry no response at all, which is why [release] is on the interface rather than the classes.
         */
        val payload: ReadBuffer? get() = null

        /**
         * Give the datagram back. Idempotent only in the sense that each exchange is consumed once —
         * every consumer below runs it through [consuming], which is what makes "once" structural.
         */
        fun release() {
            payload?.releaseReceived()
        }

        /** The server answered with a success response. */
        class Succeeded(
            val response: StunMessage,
            override val payload: ReadBuffer,
        ) : TurnExchange

        /** The server answered with an error response carrying a decodable ERROR-CODE. */
        class Refused(
            val response: StunMessage,
            val error: StunErrorCode,
            override val payload: ReadBuffer,
        ) : TurnExchange

        /** The server answered with an error response we could not read an ERROR-CODE out of. */
        class Malformed(
            val response: StunMessage,
            override val payload: ReadBuffer,
        ) : TurnExchange

        /** Every transmission went unanswered within the budget. Says nothing about the allocation. */
        data object Unanswered : TurnExchange

        /**
         * **Nothing was ever transmitted** — every attempt was refused locally, so the server was never
         * asked and [Unanswered] would blame it for our own fault.
         *
         * The same distinction `ServerReflexiveResult.Unavailable.SendFailed` draws, and it matters more
         * here: behind a symmetric NAT the relay is the only path, so "the TURN server is unreachable" is
         * the conclusion an operator acts on, and it is the wrong one when the real cause is a local
         * socket or a `bufferFactory` this platform cannot send from (webrtc#125).
         */
        class NeverSent(
            val cause: Throwable,
        ) : TurnExchange
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

        /**
         * **Not one request left the socket** — every transmission was refused locally, so the server was
         * never asked and its silence says nothing about it.
         *
         * Distinct from [NoResponse] because they send an operator in opposite directions, and here the
         * stakes are highest: behind a symmetric NAT the relay is the only path, so a session that reports
         * an unreachable TURN server when the real cause is a local socket — or a `bufferFactory` this
         * platform cannot send from (webrtc#125) — sends the investigation to the wrong machine entirely.
         *
         * Surfaces to an application as `IceGatheringNotice.RelayUnavailable`, like every other
         * [Unavailable].
         */
        public data class SendFailed(
            /** What the socket raised on the last refused attempt. Diagnostic payload, never a discriminant. */
            public val cause: Throwable,
        ) : Unavailable
    }
}

// File-private, not companion constants: a `const val` in the companion is emitted as a PUBLIC static
// field on TurnAllocation (see the one above, which predates this), and an error code is not API.
private const val UNAUTHORIZED = 401
private const val STALE_NONCE = 438 // RFC 8656 §18: the nonce a long-lived allocation was created under expired

/**
 * How many refused permissions [TurnAllocation.permissionRefused] holds for a collector that has not
 * caught up. Sized like `TRANSMIT_FAILURE_DIAGNOSTIC_BUFFER` and for the same reason: a refusal is a
 * condition to notice, not evidence to count, and a server that refuses one CreatePermission refuses the
 * next — the eighth identical refusal tells a collector nothing the first did not.
 */
private const val PERMISSION_REFUSAL_DIAGNOSTIC_BUFFER = 8

/** RFC 8656 §7.2's default allocation lifetime, used only when a server omits LIFETIME entirely. */
private val DEFAULT_ALLOCATION_LIFETIME: Duration = 600.seconds

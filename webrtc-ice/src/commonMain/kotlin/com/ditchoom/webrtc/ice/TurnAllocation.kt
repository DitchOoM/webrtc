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
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.StunMessageBuilder
import com.ditchoom.webrtc.stun.StunMethod
import com.ditchoom.webrtc.stun.TURN_FAMILY_IPV6
import com.ditchoom.webrtc.stun.TransactionId
import com.ditchoom.webrtc.stun.asText
import com.ditchoom.webrtc.stun.asXorMappedAddress
import com.ditchoom.webrtc.stun.longTermCredentialKey
import com.ditchoom.webrtc.stun.ofRequestedAddressFamily
import com.ditchoom.webrtc.stun.ofRequestedTransport
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.time.Duration
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
 * server's 401 supplies the REALM that MESSAGE-INTEGRITY's key —
 * `MD5(username:realm:password)`, via [longTermCredentialKey] — is derived from. Call [allocate] once
 * before use.
 *
 * **Known limitations (tracked; not exercised by the vnet, which models no expiry):** no allocation
 * Refresh (RFC 8656 §8) or permission re-installation (§9), so a session outliving the server LIFETIME
 * loses its relay — an interop follow-up. [pending]/[permitted] are plain collections safe under the
 * single-threaded test/driver dispatcher; a genuinely multi-threaded scope would need synchronization.
 * A response's attribute slices are read by the awaiting request before the demux loop's next receive,
 * safe against the vnet's copy-on-receive; a receive-buffer-pooling channel would want it copied too.
 */
public class TurnAllocation(
    private val underlying: AddressedDatagramChannel,
    private val server: SocketAddress,
    private val username: String,
    private val password: String,
    private val random: Random,
    private val scope: CoroutineScope,
    private val bufferFactory: BufferFactory = BufferFactory.Default,
) : AddressedDatagramChannel {
    private val pending = HashMap<TransactionId, CompletableDeferred<StunMessage>>()
    private val inbound = Channel<Datagram>(Channel.UNLIMITED)
    private val permitted = HashSet<String>()
    private var credential: Credential = Credential.Unchallenged
    private var relayed: SocketAddress? = null
    private var closed = false
    private var loopStarted = false

    // The relayed address once allocated, else the address we are actually bound to. `underlying` is
    // addressed-mode, so it is bound by construction and its localAddress needs no unwrap — the old
    // `?: server` fallback stood only for a getsockname that could not fail here anyway.
    override val localAddress: SocketAddress get() = relayed ?: underlying.localAddress
    override val capabilities: DatagramCapabilities get() = underlying.capabilities
    override val isOpen: Boolean get() = !closed && underlying.isOpen
    override val maxWritableSize: Int get() = (underlying.maxWritableSize - TURN_OVERHEAD_BYTES).coerceAtLeast(0)

    /**
     * Allocate a relayed transport address (RFC 8656 §7), retrying once with the server's REALM/NONCE if
     * challenged (401). Returns the relayed address, or null if the allocation fails. Starts the
     * demultiplex loop as a side effect.
     */
    public suspend fun allocate(timeout: Duration = DEFAULT_GATHER_TIMEOUT): SocketAddress? {
        startLoop()
        var response = request(timeout) { allocateRequest(it) }
        if (response != null && response.messageType.stunClass == StunClass.ErrorResponse) {
            // Only retry once the challenge is actually usable. A 401 missing REALM or NONCE yields no
            // long-term key, so the retry could only repeat the same unauthenticated request — fall
            // through to the failure below instead of burning a second timeout on it.
            val challenge = response.asChallenge()
            if (challenge != null) {
                credential = challenge
                response = request(timeout) { allocateRequest(it) }
            }
        }
        if (response == null || response.messageType.stunClass != StunClass.SuccessResponse) return null
        val relayedAddress =
            response.firstOrNull(StunAttributeType.XorRelayedAddress)?.asXorMappedAddress(response.transactionId)?.toSocketAddress()
                ?: return null
        relayed = relayedAddress
        return relayedAddress
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

    override fun close() {
        closed = true
        inbound.close()
        underlying.close()
    }

    // Ensure a permission exists for [peer]'s IP so its inbound data reaches us (RFC 8656 §9).
    private suspend fun ensurePermission(peer: SocketAddress) {
        if (peer.host in permitted) return
        val response =
            request(DEFAULT_GATHER_TIMEOUT) { transactionId ->
                builderFor(StunMethod.CreatePermission, transactionId)
                    .add(
                        RawAttribute.ofXorAddress(
                            StunAttributeType.XorPeerAddress,
                            peer.toTransportAddress(),
                            transactionId,
                            bufferFactory,
                        ),
                    )
            }
        if (response?.messageType?.stunClass == StunClass.SuccessResponse) permitted += peer.host
    }

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

    // Send a request built for a fresh transaction id and await its response (or null on timeout).
    private suspend fun request(
        timeout: Duration,
        build: (TransactionId) -> StunMessageBuilder,
    ): StunMessage? {
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
        underlying.send(authenticated.encode(bufferFactory), to = server)
        return withTimeoutOrNull(timeout) { deferred.await() }.also { pending.remove(transactionId) }
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

    private companion object {
        const val TURN_OVERHEAD_BYTES = 40 // Send-indication STUN header + XOR-PEER-ADDRESS + DATA TLV
    }
}

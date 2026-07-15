@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Datagram
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramChannel
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
import com.ditchoom.webrtc.stun.TransactionId
import com.ditchoom.webrtc.stun.asText
import com.ditchoom.webrtc.stun.asXorMappedAddress
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
 * A **TURN relay allocation** (RFC 8656) presented as an ordinary [DatagramChannel] — the trick that
 * keeps the relay's complexity out of the sans-io [IceAgent] and its driver. The agent gathers a relay
 * candidate whose base is the allocation's relayed address and simply sends from it; this wrapper
 * encapsulates each datagram in a Send indication to the TURN server (creating a permission first) and
 * decapsulates inbound Data indications back into plain [Datagram]s. So `channels[relayedBase] =
 * TurnAllocation` slots into the driver with **no relay-specific code anywhere else**.
 *
 * It owns [underlying] (a dedicated socket carrying only TURN traffic), demultiplexing responses (to
 * pending requests) from Data indications (to the inbound queue) in one loop on [scope]. Auth is the
 * short-term-credential MESSAGE-INTEGRITY the vnet server understands (MD5-free); the long-term-key
 * (real-coturn) derivation is a W7-interop concern. Call [allocate] once before use.
 *
 * **Known W3 limitations (tracked; not exercised by the vnet, which models no expiry):** no allocation
 * Refresh (RFC 8656 §8) or permission re-installation (§9), so a session outliving the server LIFETIME
 * loses its relay — a W7-interop follow-up. [pending]/[permitted] are plain collections safe under the
 * single-threaded test/driver dispatcher; a genuinely multi-threaded scope would need synchronization.
 * A response's attribute slices are read by the awaiting request before the demux loop's next receive,
 * safe against the vnet's copy-on-receive; a receive-buffer-pooling channel would want it copied too.
 */
public class TurnAllocation(
    private val underlying: DatagramChannel,
    private val server: SocketAddress,
    private val username: String,
    private val password: String,
    private val random: Random,
    private val scope: CoroutineScope,
    private val bufferFactory: BufferFactory = BufferFactory.Default,
) : DatagramChannel {
    private val pending = HashMap<TransactionId, CompletableDeferred<StunMessage>>()
    private val inbound = Channel<Datagram>(Channel.UNLIMITED)
    private val permitted = HashSet<String>()
    private var realm: String? = null
    private var nonce: String? = null
    private var relayed: SocketAddress? = null
    private var closed = false
    private var loopStarted = false

    override val localAddress: SocketAddress get() = relayed ?: underlying.localAddress ?: server
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
            realm = response.firstOrNull(StunAttributeType.Realm)?.asText()
            nonce = response.firstOrNull(StunAttributeType.Nonce)?.asText()
            response = request(timeout) { allocateRequest(it) }
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
        to: SocketAddress?,
        options: DatagramSendOptions,
    ) {
        val peer = requireNotNull(to) { "a relay send needs a destination" }
        ensurePermission(peer)
        val transactionId = TransactionId.random(random)
        val indication =
            StunMessageBuilder
                .of(StunClass.Indication, StunMethod.Send, transactionId)
                .add(RawAttribute.ofXorAddress(StunAttributeType.XorPeerAddress, peer.toTransportAddress(), transactionId))
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
                    .add(RawAttribute.ofXorAddress(StunAttributeType.XorPeerAddress, peer.toTransportAddress(), transactionId))
            }
        if (response?.messageType?.stunClass == StunClass.SuccessResponse) permitted += peer.host
    }

    private fun startLoop() {
        if (loopStarted) return
        loopStarted = true
        scope.launch {
            while (true) {
                val datagram =
                    when (val result = underlying.receive()) {
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
        val datagram = build(transactionId).addMessageIntegrity(key()).encode(bufferFactory)
        underlying.send(datagram, to = server)
        return withTimeoutOrNull(timeout) { deferred.await() }.also { pending.remove(transactionId) }
    }

    private fun allocateRequest(transactionId: TransactionId): StunMessageBuilder =
        authed(StunMessageBuilder.of(StunClass.Request, StunMethod.Allocate, transactionId)).add(RawAttribute.ofRequestedTransport())

    private fun builderFor(
        method: StunMethod,
        transactionId: TransactionId,
    ): StunMessageBuilder = authed(StunMessageBuilder.of(StunClass.Request, method, transactionId))

    // Add USERNAME and, once challenged, REALM/NONCE (RFC 8656 long-term-credential form).
    private fun authed(builder: StunMessageBuilder): StunMessageBuilder {
        builder.add(RawAttribute.ofText(StunAttributeType.Username, username))
        realm?.let { builder.add(RawAttribute.ofText(StunAttributeType.Realm, it)) }
        nonce?.let { builder.add(RawAttribute.ofText(StunAttributeType.Nonce, it)) }
        return builder
    }

    private fun key(): ReadBuffer {
        val buffer = bufferFactory.allocate(maxOf(1, password.length * MAX_UTF8_PER_CHAR), ByteOrder.BIG_ENDIAN)
        buffer.writeString(password, Charset.UTF8)
        buffer.resetForRead()
        return buffer
    }

    private companion object {
        const val TURN_OVERHEAD_BYTES = 40 // Send-indication STUN header + XOR-PEER-ADDRESS + DATA TLV
        const val MAX_UTF8_PER_CHAR = 3
    }
}

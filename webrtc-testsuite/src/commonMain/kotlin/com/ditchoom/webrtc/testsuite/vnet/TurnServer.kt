@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.testsuite.vnet

import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.buffer.use
import com.ditchoom.webrtc.stun.RawAttribute
import com.ditchoom.webrtc.stun.StunAttributeType
import com.ditchoom.webrtc.stun.StunClass
import com.ditchoom.webrtc.stun.StunDecodeResult
import com.ditchoom.webrtc.stun.StunErrorCode
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.StunMessageBuilder
import com.ditchoom.webrtc.stun.StunMethod
import com.ditchoom.webrtc.stun.TransactionId
import com.ditchoom.webrtc.stun.asText
import com.ditchoom.webrtc.stun.asXorMappedAddress
import com.ditchoom.webrtc.stun.ofLifetime
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlin.random.Random

/**
 * A **virtual TURN server** (RFC 8656) — a faithful relay bound as an ordinary [Vnet] endpoint: it
 * speaks the same [AddressedDatagramChannel] seam as everything else, so a peer behind a symmetric NAT reaches
 * it exactly as it would reach real coturn. It is the load-bearing piece of the canonical
 * `dual-symmetric-NAT → relay` fixture (ARCHITECTURE §5.2): when srflx candidates are useless, the relay is the
 * only path that connects.
 *
 * Implemented: the long-term-credential challenge (401 + REALM + NONCE), Allocate, CreatePermission,
 * Refresh, and Send/Data indication relaying — including relaying **between two allocations on this same
 * server**, precisely the relay↔relay ICE check the dual-NAT fixture exercises.
 *
 * Auth is RFC 8489 §9.2's **long-term** credential: the key is `MD5(username:realm:password)`, exactly
 * what coturn computes from its user table. [keyProvider] is the injected seam and
 * [Vnets.turnKeyProvider] supplies the real derivation.
 */
internal class TurnServer(
    /** The public control transport address clients send Allocate/Refresh/Send to. */
    val address: SocketAddress,
    private val vnet: Vnet,
    private val scope: CoroutineScope,
    /** MESSAGE-INTEGRITY key for a USERNAME, or null to reject it (RFC 8489 §9.2.2 long-term key). */
    private val keyProvider: (username: String) -> ReadBuffer?,
    seed: Long = DEFAULT_SEED,
    private val realm: String = DEFAULT_REALM,
    private val nonce: String = DEFAULT_NONCE,
    private val lifetimeSeconds: UInt = DEFAULT_LIFETIME_SECONDS,
    private val relayIp: String = address.ip,
    firstRelayPort: Int = FIRST_RELAY_PORT,
) {
    @Suppress("UnseamedEntropy") // test-only seam; the seed is the injected entropy (Data-indication txids)
    private val rng = Random(seed)
    private val control: AddressedDatagramChannel = vnet.bind(address)
    private var nextRelayPort = firstRelayPort

    // Allocations keyed by the client's reflexive address as the server observes it (its 5-tuple).
    private val allocations = HashMap<SocketAddress, Allocation>()

    private class Allocation(
        val client: SocketAddress,
        val relayed: SocketAddress,
        val relayChannel: AddressedDatagramChannel,
        val permissions: MutableSet<String> = HashSet(),
    )

    /** Launch the control loop; returns the [Job] so a fixture can cancel the server. */
    fun start(): Job = scope.launch { controlLoop() }

    private suspend fun controlLoop() {
        while (true) {
            val received =
                when (val result = control.receive()) {
                    is DatagramReadResult.Received -> result
                    is DatagramReadResult.Closed -> return
                }
            // The control loop is the LAST READER of every datagram it takes. [handle] reads borrows of it
            // (a decoded attribute is a slice of this payload) and, on the Send-indication path, hands the
            // DATA borrow straight to `relayChannel.send`, which the vnet copies synchronously — so by the
            // time `handle` returns nothing holds a view of it, and `use` releases it before the next
            // iteration. Consuming here is what lets a consumer's
            // [com.ditchoom.webrtc.testsuite.harness.BufferCensus] read zero.
            received.datagram.payload.use { payload ->
                val message =
                    when (val decoded = StunMessage.decode(payload)) {
                        is StunDecodeResult.Success -> decoded.message
                        is StunDecodeResult.Reject -> return@use // not STUN — a real server would 400; the vnet drops
                    }
                // Decoding takes a REFERENCE per attribute — on a pooled payload each `RawAttribute` is an
                // `addRef`'d slice — so freeing the datagram is not enough: without this the chunk stays
                // pinned, invisible to every free-counting check and visible only to the pool.
                try {
                    handle(message, received.datagram.peer)
                } finally {
                    message.release()
                }
            }
        }
    }

    private suspend fun handle(
        message: StunMessage,
        client: SocketAddress,
    ) {
        val method = message.messageType.method
        val stunClass = message.messageType.stunClass
        when {
            stunClass == StunClass.Indication && method == StunMethod.Send -> relayOutbound(message, client)
            stunClass == StunClass.Request && method == StunMethod.Allocate -> onAllocate(message, client)
            stunClass == StunClass.Request && method == StunMethod.CreatePermission -> onCreatePermission(message, client)
            stunClass == StunClass.Request && method == StunMethod.Refresh -> onRefresh(message, client)
            else -> Unit // ChannelBind and the rest are out of the vnet's scope
        }
    }

    private suspend fun onAllocate(
        request: StunMessage,
        client: SocketAddress,
    ) {
        val user = authenticatedUser(request, client) ?: return
        val allocation =
            allocations.getOrPut(client) {
                val relayed = vnetAddress(relayIp, nextRelayPort++)
                Allocation(client, relayed, vnet.bind(relayed)).also { launchRelayLoop(it) }
            }
        val response =
            StunMessageBuilder
                .of(StunClass.SuccessResponse, StunMethod.Allocate, request.transactionId)
                .add(
                    RawAttribute.ofXorAddress(
                        StunAttributeType.XorRelayedAddress,
                        allocation.relayed.toTransportAddress(),
                        request.transactionId,
                    ),
                ).add(RawAttribute.ofXorMappedAddress(client.toTransportAddress(), request.transactionId))
                .add(RawAttribute.ofLifetime(lifetimeSeconds))
                .addMessageIntegrity(keyFor(user))
                .encode()
        reply(response, to = client)
    }

    private suspend fun onCreatePermission(
        request: StunMessage,
        client: SocketAddress,
    ) {
        val user = authenticatedUser(request, client) ?: return
        val allocation = allocations[client] ?: return
        request.attributes
            .filter { it.type == StunAttributeType.XorPeerAddress }
            .mapNotNull { it.asXorMappedAddress(request.transactionId) }
            .forEach { allocation.permissions += it.toSocketAddress().ip }
        val response =
            StunMessageBuilder
                .of(StunClass.SuccessResponse, StunMethod.CreatePermission, request.transactionId)
                .addMessageIntegrity(keyFor(user))
                .encode()
        reply(response, to = client)
    }

    private suspend fun onRefresh(
        request: StunMessage,
        client: SocketAddress,
    ) {
        val user = authenticatedUser(request, client) ?: return
        val response =
            StunMessageBuilder
                .of(StunClass.SuccessResponse, StunMethod.Refresh, request.transactionId)
                .add(RawAttribute.ofLifetime(lifetimeSeconds))
                .addMessageIntegrity(keyFor(user))
                .encode()
        reply(response, to = client)
    }

    // Client → peer: a Send indication carries XOR-PEER-ADDRESS + DATA; the data leaves from the
    // allocation's relay channel (source = the relayed address), gated by a prior CreatePermission.
    private suspend fun relayOutbound(
        indication: StunMessage,
        client: SocketAddress,
    ) {
        val allocation = allocations[client] ?: return
        val peer =
            indication.firstOrNull(StunAttributeType.XorPeerAddress)?.asXorMappedAddress(indication.transactionId)?.toSocketAddress()
                ?: return
        val data = indication.firstOrNull(StunAttributeType.Data)?.value ?: return
        if (peer.ip !in allocation.permissions) return
        allocation.relayChannel.send(data, to = peer)
    }

    // Peer → client: traffic arriving at the relay channel is wrapped as a Data indication and sent to
    // the client on the control 5-tuple (RFC 8656 §11.4), gated by a permission for the peer's IP.
    private fun launchRelayLoop(allocation: Allocation) {
        scope.launch {
            while (true) {
                val received =
                    when (val result = allocation.relayChannel.receive()) {
                        is DatagramReadResult.Received -> result
                        is DatagramReadResult.Closed -> return@launch
                    }
                // Last reader, like the control loop: `encode()` copies the DATA attribute's bytes into
                // the indication, so this payload is spent once the encoding exists — and it is spent on
                // the no-permission path too, which is why the release is the block's exit and not a
                // statement someone can step around.
                received.datagram.payload.use { payload ->
                    val peer = received.datagram.peer
                    if (peer.ip !in allocation.permissions) return@use
                    val txid = TransactionId.random(rng)
                    StunMessageBuilder
                        .of(StunClass.Indication, StunMethod.Data, txid)
                        .add(RawAttribute.ofXorAddress(StunAttributeType.XorPeerAddress, peer.toTransportAddress(), txid))
                        .add(RawAttribute.ofRaw(StunAttributeType.Data, payload))
                        .encode()
                        .use { control.send(it, to = allocation.client) }
                }
            }
        }
    }

    // Send an encoded response and release it. `send` has finished reading by the time it returns — the
    // vnet copies the payload synchronously on the delivery path — so the encoding is spent at the call
    // and holding it any longer is just a chunk out of circulation.
    private suspend fun reply(
        response: PlatformBuffer,
        to: SocketAddress,
    ) = response.use { control.send(it, to = to) }

    // A fresh key buffer per use — HMAC reads the buffer, so verify and each response MI need their own.
    private fun keyFor(username: String): ReadBuffer = requireNotNull(keyProvider(username)) { "no key for $username" }

    // Returns the authenticated USERNAME if the request carries a valid MESSAGE-INTEGRITY AND echoes the
    // server's REALM/NONCE (RFC 8656 long-term credential, like coturn); otherwise sends a 401 challenge
    // (REALM + NONCE) and returns null.
    private suspend fun authenticatedUser(
        request: StunMessage,
        client: SocketAddress,
    ): String? {
        val username = request.firstOrNull(StunAttributeType.Username)?.asText()
        val key = username?.let(keyProvider)
        val presentedRealm = request.firstOrNull(StunAttributeType.Realm)?.asText()
        val presentedNonce = request.firstOrNull(StunAttributeType.Nonce)?.asText()
        if (username != null && key != null && presentedRealm == realm && presentedNonce == nonce && request.verifyMessageIntegrity(key)) {
            return username
        }
        val challenge =
            StunMessageBuilder
                .of(StunClass.ErrorResponse, request.messageType.method, request.transactionId)
                .add(RawAttribute.ofErrorCode(StunErrorCode(UNAUTHORIZED, "Unauthorized")))
                .add(RawAttribute.ofText(StunAttributeType.Realm, realm))
                .add(RawAttribute.ofText(StunAttributeType.Nonce, nonce))
                .encode()
        reply(challenge, to = client)
        return null
    }

    companion object {
        const val DEFAULT_REALM = "vnet"
        const val DEFAULT_NONCE = "vnetnonce0000"
        const val DEFAULT_LIFETIME_SECONDS: UInt = 600u
        const val FIRST_RELAY_PORT = 50000
        private const val DEFAULT_SEED = 0x7247_4E00L // "rGN\0"
        private const val UNAUTHORIZED = 401
    }
}

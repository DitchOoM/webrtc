@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.toSocketAddress
import com.ditchoom.webrtc.ice.toTransportAddress
import com.ditchoom.webrtc.stun.RawAttribute
import com.ditchoom.webrtc.stun.StunAttributeType
import com.ditchoom.webrtc.stun.StunClass
import com.ditchoom.webrtc.stun.StunDecodeResult
import com.ditchoom.webrtc.stun.StunErrorCode
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.StunMessageBuilder
import com.ditchoom.webrtc.stun.StunMethod
import com.ditchoom.webrtc.stun.TURN_FAMILY_IPV4
import com.ditchoom.webrtc.stun.TURN_FAMILY_IPV6
import com.ditchoom.webrtc.stun.TransactionId
import com.ditchoom.webrtc.stun.asRequestedAddressFamily
import com.ditchoom.webrtc.stun.asText
import com.ditchoom.webrtc.stun.asXorMappedAddress
import com.ditchoom.webrtc.stun.ofLifetime
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlin.random.Random

/**
 * A **virtual TURN server** (RFC 8656) — a faithful relay bound as an ordinary [Vnet] endpoint, not a
 * router hack: it speaks the same [DatagramChannel] seam as everything else, so a peer behind a
 * symmetric NAT reaches it exactly as it would reach real coturn. It is the load-bearing piece of the
 * canonical `dual-symmetric-NAT → relay` fixture (RFC §5.2): when srflx candidates are useless (a
 * symmetric NAT gives a fresh mapping per destination), the relay is the only path that connects.
 *
 * Implemented: the long-term-credential challenge (401 + REALM + NONCE), Allocate (→ a fresh relayed
 * transport address on the server's public IP, XOR-MAPPED-ADDRESS reflexive echo, LIFETIME),
 * CreatePermission, Refresh, and Send/Data indication relaying (a Send from one allocation to a
 * permitted peer emerges from that allocation's relay channel; peer traffic arriving there returns to
 * the client as a Data indication). Relaying **between two allocations on this same server** works —
 * which is precisely the relay↔relay ICE check the dual-NAT fixture exercises.
 *
 * Auth uses RFC 8489 §9.1.1 **short-term** MESSAGE-INTEGRITY (key = the UTF-8 password) rather than
 * §9.2's long-term `MD5(user:realm:pass)` — wire-identical (USERNAME + MESSAGE-INTEGRITY), MD5-free
 * (buffer-crypto ships no MD5), and deterministic. [keyProvider] is the injected seam; the real TURN
 * client's long-term key derivation is a W7-interop concern, out of the vnet's scope.
 */
internal class TurnServer(
    /** The public control transport address clients send Allocate/Refresh/Send to. */
    val address: SocketAddress,
    private val vnet: Vnet,
    private val scope: CoroutineScope,
    /** MESSAGE-INTEGRITY key for a USERNAME, or null to reject it (RFC 8489 §9.1.1 short-term key). */
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
    private val control: DatagramChannel = vnet.bind(address)
    private var nextRelayPort = firstRelayPort

    // Allocations keyed by the client's reflexive address as the server observes it (its 5-tuple).
    private val allocations = HashMap<SocketAddress, Allocation>()

    private class Allocation(
        val client: SocketAddress,
        val relayed: SocketAddress,
        val relayChannel: DatagramChannel,
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
            val message =
                when (val decoded = StunMessage.decode(received.datagram.payload)) {
                    is StunDecodeResult.Success -> decoded.message
                    is StunDecodeResult.Reject -> continue // not STUN — a real server would 400; the vnet drops
                }
            handle(message, received.datagram.peer)
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
        // coturn-faithful family selection (RFC 8656 §7.2 / §18.9): serve the requested relay family,
        // defaulting to IPv4 when REQUESTED-ADDRESS-FAMILY is absent. This server relays only in its own
        // relayIp family, so a request for a family it cannot serve is refused 440 — reproducing coturn
        // handing a v6 client an unusable relay when the client forgets to ask for IPv6 (the AllPairsFailed bug).
        val requestedFamily = request.firstOrNull(StunAttributeType.RequestedAddressFamily)?.asRequestedAddressFamily() ?: TURN_FAMILY_IPV4
        val relayFamily = if (':' in relayIp) TURN_FAMILY_IPV6 else TURN_FAMILY_IPV4
        if (requestedFamily != relayFamily) {
            val refusal =
                StunMessageBuilder
                    .of(StunClass.ErrorResponse, StunMethod.Allocate, request.transactionId)
                    .add(RawAttribute.ofErrorCode(StunErrorCode(ADDRESS_FAMILY_NOT_SUPPORTED, "Address Family not Supported")))
                    .addMessageIntegrity(keyFor(user))
                    .encode()
            control.send(refusal, to = client)
            return
        }
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
        control.send(response, to = client)
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
        control.send(response, to = client)
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
        control.send(response, to = client)
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
                val peer = received.datagram.peer
                if (peer.ip !in allocation.permissions) continue
                val txid = TransactionId.random(rng)
                val indication =
                    StunMessageBuilder
                        .of(StunClass.Indication, StunMethod.Data, txid)
                        .add(RawAttribute.ofXorAddress(StunAttributeType.XorPeerAddress, peer.toTransportAddress(), txid))
                        .add(RawAttribute.ofRaw(StunAttributeType.Data, received.datagram.payload))
                        .encode()
                control.send(indication, to = allocation.client)
            }
        }
    }

    // A fresh key buffer per use — HMAC reads the buffer, so verify and each response MI need their own.
    private fun keyFor(username: String): ReadBuffer = requireNotNull(keyProvider(username)) { "no key for $username" }

    // Returns the authenticated USERNAME if the request carries a valid MESSAGE-INTEGRITY AND echoes the
    // server's REALM/NONCE (RFC 8656 long-term credential, like coturn); otherwise sends a 401 challenge
    // (REALM + NONCE) and returns null. Requiring the nonce is what surfaces a real client bug where it
    // fails to copy the challenge into its authed retry — a lenient server would hide it.
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
        control.send(challenge, to = client)
        return null
    }

    companion object {
        const val DEFAULT_REALM = "vnet"
        const val DEFAULT_NONCE = "vnetnonce0000"
        const val DEFAULT_LIFETIME_SECONDS: UInt = 600u
        const val FIRST_RELAY_PORT = 50000
        private const val DEFAULT_SEED = 0x7247_4E00L // "rGN\0"
        private const val UNAUTHORIZED = 401
        private const val ADDRESS_FAMILY_NOT_SUPPORTED = 440 // RFC 8656 §18
    }
}

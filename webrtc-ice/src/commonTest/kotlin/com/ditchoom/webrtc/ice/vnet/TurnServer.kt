@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
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
import com.ditchoom.webrtc.stun.asLifetimeSeconds
import com.ditchoom.webrtc.stun.asRequestedAddressFamily
import com.ditchoom.webrtc.stun.asText
import com.ditchoom.webrtc.stun.asXorMappedAddress
import com.ditchoom.webrtc.stun.ofLifetime
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

/**
 * How the [TurnServer] ages its NONCE. A real server expires nonces on its own schedule, which is why RFC
 * 8656 §8 makes 438 Stale Nonce a normal event in the life of a long-lived allocation rather than an
 * error — and why a client that cannot re-read the NONCE and retry loses its relay at the first rotation.
 */
internal sealed interface NoncePolicy {
    /** One NONCE for the server's whole life: the historical behaviour, and what most fixtures want. */
    data object Fixed : NoncePolicy

    /** Rotate after every [afterRequests] granted requests, so the next one in flight is answered 438. */
    data class RotateEvery(
        val afterRequests: Int,
    ) : NoncePolicy {
        init {
            require(afterRequests > 0) { "afterRequests must be positive, was $afterRequests" }
        }
    }
}

/**
 * A **virtual TURN server** (RFC 8656) — a faithful relay bound as an ordinary [Vnet] endpoint, not a
 * router hack: it speaks the same [AddressedDatagramChannel] seam as everything else, so a peer behind a
 * symmetric NAT reaches it exactly as it would reach real coturn. It is the load-bearing piece of the
 * canonical `dual-symmetric-NAT → relay` fixture (ARCHITECTURE §5.2): when srflx candidates are useless (a
 * symmetric NAT gives a fresh mapping per destination), the relay is the only path that connects.
 *
 * Implemented: the long-term-credential challenge (401 + REALM + NONCE), Allocate (→ a fresh relayed
 * transport address on the server's public IP, XOR-MAPPED-ADDRESS reflexive echo, LIFETIME),
 * CreatePermission, Refresh, and Send/Data indication relaying (a Send from one allocation to a
 * permitted peer emerges from that allocation's relay channel; peer traffic arriving there returns to
 * the client as a Data indication). Relaying **between two allocations on this same server** works —
 * which is precisely the relay↔relay ICE check the dual-NAT fixture exercises.
 *
 * Auth is RFC 8489 §9.2's **long-term** credential — the key is `MD5(username:realm:password)`, exactly
 * what coturn computes from its user table. [keyProvider] is the injected seam and [Vnets.turnKeyProvider]
 * supplies the real derivation, so a client that gets the key wrong fails here too rather than at the
 * first real server it meets. (This deliberately no longer accepts the short-term key: the whole point
 * of the vnet lane is to be the cheap, deterministic mirror of the coturn lane.)
 *
 * **Expiry is modelled** (issue #137). An allocation lives [lifetimeSeconds] from its last Allocate or
 * Refresh, and each permission lives [permissionLifetimeSeconds] from its last CreatePermission — both
 * as `delay()`-armed jobs on [scope], so they are exact under `runTest` virtual time. When a permission
 * lapses the peer's datagrams are dropped in **both** directions (§9), which is the silent inbound-only
 * failure the issue is about; when the allocation lapses its relay channel closes, Send indications stop
 * relaying, and a Refresh for it is answered 437 the way coturn answers one for an allocation it no
 * longer has. A Refresh with LIFETIME=0 deallocates (§8.2). [refreshes] and [permissionInstalls] are
 * exposed so a fixture can assert the client actually did the work rather than inferring it from silence.
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
    private val permissionLifetimeSeconds: UInt = DEFAULT_PERMISSION_LIFETIME_SECONDS,
    private val noncePolicy: NoncePolicy = NoncePolicy.Fixed,
    private val relayIp: String = address.ip,
    firstRelayPort: Int = FIRST_RELAY_PORT,
) {
    @Suppress("UnseamedEntropy") // test-only seam; the seed is the injected entropy (Data-indication txids)
    private val rng = Random(seed)
    private val control: AddressedDatagramChannel = vnet.bind(address)
    private var nextRelayPort = firstRelayPort
    private var currentNonce = nonce
    private var grantedRequests = 0

    /** How many Refresh requests this server has granted — the client's keep-alive, counted. */
    var refreshes: Int = 0
        private set

    /** How many CreatePermission requests this server has granted (the first install and every renewal). */
    var permissionInstalls: Int = 0
        private set

    /** How many requests this server rejected 438 because their NONCE had aged out (RFC 8656 §8). */
    var staleNonceChallenges: Int = 0
        private set

    /** Allocations this server is currently holding — 0 again once a client deallocates (§8.2). */
    val activeAllocations: Int get() = allocations.size

    // Allocations keyed by the client's reflexive address as the server observes it (its 5-tuple).
    private val allocations = HashMap<SocketAddress, Allocation>()

    private class Allocation(
        val client: SocketAddress,
        val relayed: SocketAddress,
        val relayChannel: AddressedDatagramChannel,
        val permissions: MutableMap<String, Job> = HashMap(),
    ) {
        var expiry: Job? = null
    }

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
        armAllocationExpiry(allocation)
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
            .forEach { armPermissionExpiry(allocation, it.toSocketAddress().ip) }
        permissionInstalls++
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
        // 437 for an allocation this server no longer holds — coturn's answer, and the one that makes the
        // anti-vacuity direction of the refresh fixture fail loudly instead of hanging.
        val allocation = allocations[client]
        if (allocation == null) {
            val mismatch =
                StunMessageBuilder
                    .of(StunClass.ErrorResponse, StunMethod.Refresh, request.transactionId)
                    .add(RawAttribute.ofErrorCode(StunErrorCode(ALLOCATION_MISMATCH, "Allocation Mismatch")))
                    .addMessageIntegrity(keyFor(user))
                    .encode()
            control.send(mismatch, to = client)
            return
        }
        // RFC 8656 §8.2: LIFETIME=0 is a deallocation, answered with a success carrying LIFETIME=0.
        val requested = request.firstOrNull(StunAttributeType.Lifetime)?.asLifetimeSeconds()
        val granted = if (requested == 0u) 0u else lifetimeSeconds
        if (granted == 0u) release(allocation) else armAllocationExpiry(allocation)
        refreshes++
        val response =
            StunMessageBuilder
                .of(StunClass.SuccessResponse, StunMethod.Refresh, request.transactionId)
                .add(RawAttribute.ofLifetime(granted))
                .addMessageIntegrity(keyFor(user))
                .encode()
        control.send(response, to = client)
    }

    // ── expiry (RFC 8656 §8 allocation LIFETIME, §9 permission lifetime) ─────────────────────────
    // Modelled as delay()-armed jobs rather than a clock the fixture has to advance: under `runTest` the
    // two are the same thing, and this keeps the server's timekeeping on the scope it already owns.

    private fun armAllocationExpiry(allocation: Allocation) {
        allocation.expiry?.cancel()
        allocation.expiry =
            scope.launch {
                delay(lifetimeSeconds.toLong().seconds)
                allocation.expiry = null // we ARE the expiry job; do not let release() cancel us mid-run
                release(allocation)
            }
    }

    private fun armPermissionExpiry(
        allocation: Allocation,
        ip: String,
    ) {
        allocation.permissions.remove(ip)?.cancel()
        allocation.permissions[ip] =
            scope.launch {
                delay(permissionLifetimeSeconds.toLong().seconds)
                allocation.permissions -= ip
            }
    }

    private fun release(allocation: Allocation) {
        allocation.expiry?.cancel()
        allocation.permissions.values.forEach { it.cancel() }
        allocation.permissions.clear()
        allocations.remove(allocation.client)
        allocation.relayChannel.close()
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

    /**
     * Returns the authenticated USERNAME if the request carries a valid MESSAGE-INTEGRITY AND echoes the
     * server's REALM and its **current** NONCE (RFC 8656 long-term credential, like coturn); otherwise
     * answers a challenge and returns null. Requiring the nonce is what surfaces a real client bug where
     * it fails to copy the challenge into its authed retry — a lenient server would hide it.
     *
     * The challenge is **438 Stale Nonce** when the credentials themselves are good and only the nonce is
     * out of date (which is what [NoncePolicy.RotateEvery] manufactures, and what a real server does to a
     * long-lived allocation), and 401 Unauthorized otherwise. The two are different bugs on the client
     * side and a server that conflated them would let a broken retry pass for a working one.
     */
    private suspend fun authenticatedUser(
        request: StunMessage,
        client: SocketAddress,
    ): String? {
        val username = request.firstOrNull(StunAttributeType.Username)?.asText()
        val key = username?.let(keyProvider)
        val presentedRealm = request.firstOrNull(StunAttributeType.Realm)?.asText()
        val presentedNonce = request.firstOrNull(StunAttributeType.Nonce)?.asText()
        val credentialsValid = username != null && key != null && presentedRealm == realm && request.verifyMessageIntegrity(key)
        if (credentialsValid && presentedNonce == currentNonce) {
            rotateNonceIfDue()
            return username
        }
        val error =
            if (credentialsValid) {
                staleNonceChallenges++
                StunErrorCode(STALE_NONCE, "Stale Nonce")
            } else {
                StunErrorCode(UNAUTHORIZED, "Unauthorized")
            }
        val challenge =
            StunMessageBuilder
                .of(StunClass.ErrorResponse, request.messageType.method, request.transactionId)
                .add(RawAttribute.ofErrorCode(error))
                .add(RawAttribute.ofText(StunAttributeType.Realm, realm))
                .add(RawAttribute.ofText(StunAttributeType.Nonce, currentNonce))
                .encode()
        control.send(challenge, to = client)
        return null
    }

    private fun rotateNonceIfDue() {
        when (val policy = noncePolicy) {
            NoncePolicy.Fixed -> Unit
            is NoncePolicy.RotateEvery -> {
                grantedRequests++
                if (grantedRequests % policy.afterRequests == 0) currentNonce = "$nonce-$grantedRequests"
            }
        }
    }

    companion object {
        const val DEFAULT_REALM = "vnet"
        const val DEFAULT_NONCE = "vnetnonce0000"
        const val DEFAULT_LIFETIME_SECONDS: UInt = 600u

        /** RFC 8656 §9's fixed permission lifetime — coturn's 300 s, and the one the client assumes. */
        const val DEFAULT_PERMISSION_LIFETIME_SECONDS: UInt = 300u
        const val FIRST_RELAY_PORT = 50000
        private const val DEFAULT_SEED = 0x7247_4E00L // "rGN\0"
        private const val UNAUTHORIZED = 401
        private const val STALE_NONCE = 438 // RFC 8656 §18 — good credentials, aged-out NONCE
        private const val ALLOCATION_MISMATCH = 437 // RFC 8656 §18 — no allocation for this 5-tuple
        private const val ADDRESS_FAMILY_NOT_SUPPORTED = 440 // RFC 8656 §18
    }
}

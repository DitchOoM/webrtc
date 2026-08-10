@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.toSocketAddress
import com.ditchoom.webrtc.ice.toTransportAddress
import com.ditchoom.webrtc.stun.IpAddress
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
 * How the [TurnServer] ages its REALM — the seam that distinguishes a client which **re-derives** its
 * long-term key from one which merely re-reads the NONCE.
 *
 * A rotated realm is a strictly harder event than a rotated nonce, and the difference is the whole point
 * of this policy. The NONCE is an opaque token the client copies back verbatim, so surviving a 438 needs
 * no cryptography at all. The REALM is an *input to the key*: RFC 8489 §9.2.2 makes MESSAGE-INTEGRITY
 * `HMAC(MD5(username:realm:password), …)`, so a server that answers with a new realm has invalidated
 * every key the client holds. A client that copies the new realm into its attributes but keeps signing
 * with the old key authenticates against nothing — and, because the realm it *presents* is now correct,
 * it fails in the one way that looks like a wrong password rather than a stale challenge.
 *
 * Sealed rather than a nullable "newRealm", so "rotate" and "do not rotate" are different shapes rather
 * than the same shape with a null in it.
 */
internal sealed interface RealmPolicy {
    /** One REALM for the server's whole life: coturn's own behaviour, and what every other fixture wants. */
    data object Fixed : RealmPolicy

    /**
     * Adopt [replacement] once [afterRequests] requests have been granted, so the next request — which
     * still carries the old realm and is signed with the old key — is challenged **401 Unauthorized**
     * carrying the new realm, exactly as a real server does when its realm changes underneath a
     * long-lived allocation. 401 rather than 438 is deliberate and RFC-correct: the credentials really
     * are invalid now, and conflating that with a stale nonce is precisely the client bug this catches.
     */
    data class RotateAfter(
        val afterRequests: Int,
        val replacement: String = ROTATED_REALM,
    ) : RealmPolicy {
        init {
            require(afterRequests > 0) { "afterRequests must be positive, was $afterRequests" }
            require(replacement.isNotEmpty()) { "replacement realm must not be empty" }
        }
    }

    companion object {
        /** Deliberately unlike [TurnServer.DEFAULT_REALM], so a key derived from the wrong one cannot verify. */
        const val ROTATED_REALM = "vnet-rotated"
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
    /**
     * MESSAGE-INTEGRITY key for a USERNAME **under a given realm**, or null to reject it (RFC 8489 §9.2.2
     * long-term key).
     *
     * The realm is a parameter rather than something the provider closes over because the server's realm
     * can change ([RealmPolicy]), and the key is a function of it. A provider that ignored the realm would
     * happily verify a client still signing with the pre-rotation key, which is exactly the bug a rotation
     * fixture exists to catch — the seam would agree with the client on a simplification no real server
     * makes. coturn derives per (username, realm) from its user table for the same reason.
     */
    private val keyProvider: (username: String, realm: String) -> ReadBuffer?,
    seed: Long = DEFAULT_SEED,
    private val realm: String = DEFAULT_REALM,
    private val nonce: String = DEFAULT_NONCE,
    private val lifetimeSeconds: UInt = DEFAULT_LIFETIME_SECONDS,
    private val permissionLifetimeSeconds: UInt = DEFAULT_PERMISSION_LIFETIME_SECONDS,
    private val noncePolicy: NoncePolicy = NoncePolicy.Fixed,
    private val realmPolicy: RealmPolicy = RealmPolicy.Fixed,
    /**
     * Refuse every CreatePermission **once this many have been granted** — 403 Forbidden, the answer a real
     * server gives when its policy or quota turns against a peer it was previously relaying to.
     *
     * The seam exists because the two refusal paths in the client are reachable only from opposite sides of
     * it: `0` refuses the very first install (the send path), while `1` lets the permission establish and
     * refuses its **re-installation** (the maintenance path, §9), which is the arm where a permission that
     * was working silently lapses. The 443 family rule below needs no seam — it is unconditional.
     */
    private val refusePermissionsAfter: Int = Int.MAX_VALUE,
    /**
     * Refuse an Allocate for a client this server is not already holding one for, once it holds this many
     * — **486 Allocation Quota Reached** (RFC 8656 §7.2), the answer a real server gives when a username
     * has used up its concurrent-allocation budget.
     *
     * Distinct from [refusePermissionsAfter] in the arm it reaches: a quota refusal lands on the very
     * first exchange of the relay's life, before any relayed address exists, so it is the one refusal a
     * client must survive by **gathering without a relay** rather than by losing one it already had.
     * Modelled here because coturn's own default is *unlimited*, which is why this code path shipped with
     * a KDoc and no test — the container harness's `turn-quota` lane sets `user-quota=1` to reach the
     * same arm against real coturn.
     */
    private val allocationQuota: Int = Int.MAX_VALUE,
    private val relayIp: String = address.ip,
    firstRelayPort: Int = FIRST_RELAY_PORT,
) {
    @Suppress("UnseamedEntropy") // test-only seam; the seed is the injected entropy (Data-indication txids)
    private val rng = Random(seed)
    private val control: AddressedDatagramChannel = vnet.bind(address)
    private var nextRelayPort = firstRelayPort
    private var currentNonce = nonce
    private var currentRealm = realm
    private var grantedRequests = 0

    /** How many Refresh requests this server has granted — the client's keep-alive, counted. */
    var refreshes: Int = 0
        private set

    /**
     * How many times this server has changed its REALM out from under the client. Counted so a rotation
     * fixture can assert the rotation *happened* — "the session survived" is satisfied just as well by a
     * server that never rotated, which is the vacuous pass this counter closes.
     */
    var realmRotations: Int = 0
        private set

    /**
     * How many requests were refused **401 Unauthorized while presenting a realm this server has since
     * replaced** — i.e. the client signed with a key derived from a dead realm. Distinct from the ordinary
     * unauthorized count because it is the one refusal a correct client answers by *re-deriving* rather
     * than by retrying, and a fixture wants to know it reached that arm specifically.
     */
    var staleRealmChallenges: Int = 0
        private set

    /** How many CreatePermission requests this server has granted (the first install and every renewal). */
    var permissionInstalls: Int = 0
        private set

    /** How many CreatePermissions this server refused 443 for a peer of the wrong family (RFC 6156 §9.1). */
    var permissionRefusals: Int = 0
        private set

    /** How many requests this server rejected 438 because their NONCE had aged out (RFC 8656 §8). */
    var staleNonceChallenges: Int = 0
        private set

    /** How many Allocates this server refused 486 for exceeding [allocationQuota] (RFC 8656 §7.2). */
    var quotaRefusals: Int = 0
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
        // Quota is checked only for a client we are not already holding an allocation for: a repeat
        // Allocate on the same 5-tuple is that client's own allocation being re-requested, not a new one
        // against the budget (RFC 8656 §7.2 — and coturn counts the same way).
        if (client !in allocations && allocations.size >= allocationQuota) {
            quotaRefusals++
            val refusal =
                StunMessageBuilder
                    .of(StunClass.ErrorResponse, StunMethod.Allocate, request.transactionId)
                    .add(RawAttribute.ofErrorCode(StunErrorCode(ALLOCATION_QUOTA_REACHED, "Allocation Quota Reached")))
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
        val peers =
            request.attributes
                .filter { it.type == StunAttributeType.XorPeerAddress }
                .mapNotNull { it.asXorMappedAddress(request.transactionId) }
        // RFC 6156 §9.1, and coturn does exactly this: a peer whose family differs from the RELAYED
        // address's is refused 443, and the refusal covers the whole request rather than the offending
        // attribute. Unconditional rather than a policy seam — a test server that permits what every real
        // server refuses is not a mirror, it is a way to ship a bug. This is the arm that reproduces the
        // dual-stack relay failure: a v6 allocation asked to permit a v4 peer.
        val relayIsV6 = ':' in allocation.relayed.ip
        val error =
            when {
                peers.any { (it.ip is IpAddress.V6) != relayIsV6 } ->
                    StunErrorCode(PEER_ADDRESS_FAMILY_MISMATCH, "Peer Address Family Mismatch")
                permissionInstalls >= refusePermissionsAfter -> StunErrorCode(FORBIDDEN, "Forbidden")
                else -> null
            }
        if (error != null) {
            permissionRefusals++
            val refusal =
                StunMessageBuilder
                    .of(StunClass.ErrorResponse, StunMethod.CreatePermission, request.transactionId)
                    .add(RawAttribute.ofErrorCode(error))
                    .addMessageIntegrity(keyFor(user))
                    .encode()
            control.send(refusal, to = client)
            return
        }
        peers.forEach { armPermissionExpiry(allocation, it.toSocketAddress().ip) }
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
    private fun keyFor(username: String): ReadBuffer =
        requireNotNull(keyProvider(username, currentRealm)) { "no key for $username in realm $currentRealm" }

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
        // Keyed against the realm the server holds NOW, so a client still signing under a replaced realm
        // fails verification here exactly as it would against coturn's user table.
        val key = username?.let { keyProvider(it, currentRealm) }
        val presentedRealm = request.firstOrNull(StunAttributeType.Realm)?.asText()
        val presentedNonce = request.firstOrNull(StunAttributeType.Nonce)?.asText()
        val credentialsValid = username != null && key != null && presentedRealm == currentRealm && request.verifyMessageIntegrity(key)
        if (credentialsValid && presentedNonce == currentNonce) {
            onRequestGranted()
            return username
        }
        val error =
            if (credentialsValid) {
                staleNonceChallenges++
                StunErrorCode(STALE_NONCE, "Stale Nonce")
            } else {
                // A realm this server has replaced is the specific failure a rotation manufactures: the
                // credentials are not merely unrecognised, they are correctly derived from a dead realm.
                if (presentedRealm != null && presentedRealm != currentRealm) staleRealmChallenges++
                StunErrorCode(UNAUTHORIZED, "Unauthorized")
            }
        val challenge =
            StunMessageBuilder
                .of(StunClass.ErrorResponse, request.messageType.method, request.transactionId)
                .add(RawAttribute.ofErrorCode(error))
                .add(RawAttribute.ofText(StunAttributeType.Realm, currentRealm))
                .add(RawAttribute.ofText(StunAttributeType.Nonce, currentNonce))
                .encode()
        control.send(challenge, to = client)
        return null
    }

    /**
     * Age the challenge material one granted request onward. [grantedRequests] counts unconditionally so
     * the two policies read the same clock; when both are [NoncePolicy.Fixed] / [RealmPolicy.Fixed] this
     * is a counter nobody reads, and every existing fixture keeps the behaviour it had.
     */
    private fun onRequestGranted() {
        grantedRequests++
        when (val policy = noncePolicy) {
            NoncePolicy.Fixed -> Unit
            is NoncePolicy.RotateEvery ->
                if (grantedRequests % policy.afterRequests == 0) currentNonce = "$nonce-$grantedRequests"
        }
        when (val policy = realmPolicy) {
            RealmPolicy.Fixed -> Unit
            is RealmPolicy.RotateAfter ->
                // Once, not every N: a realm that changed on a cadence would let a client that re-derives
                // only sometimes still look correct, and the property under test is that it re-derives on
                // the transition it is shown.
                if (grantedRequests == policy.afterRequests) {
                    currentRealm = policy.replacement
                    realmRotations++
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
        private const val ALLOCATION_QUOTA_REACHED = 486 // RFC 8656 §18 — the username's budget is spent
        private const val ALLOCATION_MISMATCH = 437 // RFC 8656 §18 — no allocation for this 5-tuple
        private const val ADDRESS_FAMILY_NOT_SUPPORTED = 440 // RFC 8656 §18
        private const val PEER_ADDRESS_FAMILY_MISMATCH = 443 // RFC 6156 §10.2 — peer family ≠ relayed family
        private const val FORBIDDEN = 403 // RFC 8656 §18 — the server's policy refuses this peer
    }
}

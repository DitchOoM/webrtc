@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.ice.IceAttributes.asPriority
import com.ditchoom.webrtc.ice.IceAttributes.asTieBreaker
import com.ditchoom.webrtc.stun.IpAddress
import com.ditchoom.webrtc.stun.RawAttribute
import com.ditchoom.webrtc.stun.StunAttributeType
import com.ditchoom.webrtc.stun.StunClass
import com.ditchoom.webrtc.stun.StunDecodeResult
import com.ditchoom.webrtc.stun.StunErrorCode
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.StunMessageBuilder
import com.ditchoom.webrtc.stun.StunMethod
import com.ditchoom.webrtc.stun.StunRetransmitPolicy
import com.ditchoom.webrtc.stun.StunTransaction
import com.ditchoom.webrtc.stun.StunTransactionEvent
import com.ditchoom.webrtc.stun.StunTransactionOutput
import com.ditchoom.webrtc.stun.TransactionId
import com.ditchoom.webrtc.stun.TransportAddress
import com.ditchoom.webrtc.stun.asErrorCode
import com.ditchoom.webrtc.stun.asText
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Timing and buffer seams for an [IceAgent] (all RFC defaults). Injected so a test can compress or
 * stretch the schedule and assert observable state, never a wall-clock budget (directive #4).
 */
public data class IceConfig(
    /** Pacing interval Ta (RFC 8445 §14.2) — one new connectivity check is started per tick. */
    public val ta: Duration = 50.milliseconds,
    /** Retransmission policy for each check (RFC 8489 §6.2.1, via the W1 [StunTransaction]). */
    public val checkPolicy: StunRetransmitPolicy = StunRetransmitPolicy(),
    /** How often to refresh consent on the selected pair (RFC 7675 §5.1). */
    public val consentInterval: Duration = 5.seconds,
    /** How long without a consent response before the pair is declared dead (RFC 7675 §5.1). */
    public val consentTimeout: Duration = 30.seconds,
    public val bufferFactory: BufferFactory = BufferFactory.Default,
)

/**
 * The **sans-io ICE agent** (RFC 8445 + trickle 8838 + consent 7675) — a pure
 * `handle(event, now): List<Output>` plus [nextDeadline], with **no dispatcher, clock, RNG, or socket
 * inside** (RFC §5.1). It owns the checklist, the connectivity-check state machine (driven by the W1
 * [StunTransaction] for retransmission), regular nomination, RFC 7675 consent, role-conflict
 * resolution, and ICE restart. The driver ([IceEvent.DatagramReceived] in, [IceOutput.Transmit] out)
 * owns all I/O; the same machine therefore establishes a full session under `runTest` virtual time on
 * every platform, and a 90-second field saga replays in milliseconds.
 *
 * Entropy is injected once (the [random] seam, directive #2): it seeds the tie-breaker, the local
 * credentials, and every STUN transaction id, so a scenario replays bit-for-bit — the precondition a
 * timeline shrinker needs. Production wires `CryptoRandom`; tests wire a seeded [Random].
 */
public class IceAgent(
    initialRole: IceRole,
    private val random: Random,
    private val config: IceConfig = IceConfig(),
) {
    private var _role: IceRole = initialRole
    private var _localCredentials: IceCredentials = IceCredentials.random(random)
    private var tieBreaker: TieBreaker = TieBreaker.random(random)

    /** This agent's role (may flip once on a role conflict, RFC 8445 §7.3.1.1). */
    public val role: IceRole get() = _role

    /** The credentials this agent advertises in its SDP (regenerated on [IceEvent.Restart]). */
    public val localCredentials: IceCredentials get() = _localCredentials

    private var remoteCredentials: IceCredentials? = null
    private val localCandidates = mutableListOf<IceCandidate>()
    private val remoteCandidates = mutableListOf<IceCandidate>()
    private val checklist = mutableListOf<PairEntry>()
    private val byTransaction = HashMap<TransactionId, PairEntry>()

    private var _state: IceConnectionState = IceConnectionState.New

    /** The current connection state (RFC 8445 §6.1.2.6). */
    public val state: IceConnectionState get() = _state

    private var selected: PairEntry? = null
    private var nominationInFlight = false

    private var nextPacingAt: Instant? = null
    private var nextConsentAt: Instant? = null
    private var lastConsentResponseAt: Instant? = null

    /**
     * The earliest instant the driver must call `handle(TimerFired)` — the min of the pacing tick, every
     * in-flight check's retransmit deadline, and the consent refresh/expiry. Null means no timer armed.
     */
    public fun nextDeadline(now: Instant): Instant? {
        var earliest: Instant? = null

        fun consider(instant: Instant?) {
            if (instant != null && (earliest == null || instant < earliest!!)) earliest = instant
        }
        if (remoteCredentials != null && checklist.any { it.state == CandidatePairState.Waiting }) consider(nextPacingAt)
        for (entry in checklist) consider(entry.transaction?.nextDeadline())
        val chosen = selected
        if (chosen != null) {
            // Only arm the next consent refresh when no consent check is already in flight — otherwise
            // nextConsentAt sits in the past (we can't send a second) and the driver would spin without
            // advancing virtual time; the in-flight transaction's own deadline carries the schedule.
            if (chosen.transaction == null) consider(nextConsentAt)
            consider(lastConsentResponseAt?.plus(config.consentTimeout))
        }
        return earliest
    }

    public fun handle(
        event: IceEvent,
        now: Instant,
    ): List<IceOutput> {
        val out = mutableListOf<IceOutput>()
        when (event) {
            is IceEvent.AddLocalCandidate -> onAddLocalCandidate(event.candidate, now, out)
            is IceEvent.AddRemoteCandidate -> onAddRemoteCandidate(event.candidate, now, out)
            is IceEvent.SetRemoteCredentials -> onSetRemoteCredentials(event.credentials, now, out)
            is IceEvent.DatagramReceived -> onDatagram(event, now, out)
            IceEvent.TimerFired -> onTimer(now, out)
            IceEvent.Restart -> onRestart(now, out)
        }
        return out
    }

    // ---- candidate + credential intake --------------------------------------------------------------

    private fun onAddLocalCandidate(
        candidate: IceCandidate,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        if (localCandidates.any { it.address == candidate.address && it.type == candidate.type }) return
        localCandidates += candidate
        formPairs(now, out)
    }

    private fun onAddRemoteCandidate(
        candidate: IceCandidate,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        if (remoteCandidates.any { it.address == candidate.address && it.type == candidate.type }) return
        remoteCandidates += candidate
        formPairs(now, out)
    }

    private fun onSetRemoteCredentials(
        credentials: IceCredentials,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        remoteCredentials = credentials
        formPairs(now, out)
    }

    // Pair every compatible (local, remote); RFC 8445 §6.1.2.2/§6.1.2.4. Runs on each intake so trickled
    // candidates extend the checklist incrementally.
    private fun formPairs(
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        if (remoteCredentials == null) return
        for (local in localCandidates) {
            for (remote in remoteCandidates) {
                if (!compatible(local, remote)) continue
                if (checklist.any { it.pair.local == local && it.pair.remote == remote }) continue
                checklist += PairEntry(CandidatePair(local, remote))
            }
        }
        pruneRedundant()
        sortChecklist()
        if (checklist.isNotEmpty() && nextPacingAt == null) nextPacingAt = now
        if (_state is IceConnectionState.New && checklist.isNotEmpty()) transition(IceConnectionState.Checking, out)
    }

    // A redundant pair (RFC 8445 §6.1.2.4): same base and same remote address — keep the highest priority.
    private fun pruneRedundant() {
        val seen = HashSet<Pair<TransportAddress, TransportAddress>>()
        val ordered = checklist.sortedByDescending { it.pair.priority(_role) }
        checklist.clear()
        for (entry in ordered) {
            val key = entry.pair.local.base to entry.pair.remote.address
            if (seen.add(key)) checklist += entry
        }
    }

    private fun sortChecklist() = checklist.sortByDescending { it.pair.priority(_role) }

    private fun compatible(
        local: IceCandidate,
        remote: IceCandidate,
    ): Boolean = local.component == remote.component && local.transport == remote.transport && sameFamily(local.address, remote.address)

    // ---- the pacing / retransmit / consent tick -----------------------------------------------------

    private fun onTimer(
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        // 1. Retransmit or fail every check whose transaction deadline has arrived.
        for (entry in checklist.toList()) {
            val txn = entry.transaction ?: continue
            val deadline = txn.nextDeadline() ?: continue
            if (deadline <= now) driveTransaction(entry, txn.handle(StunTransactionEvent.TimerExpired, now), now, out)
        }
        // 2. Pace one new ordinary check per Ta, highest priority first (RFC 8445 §6.1.4.2).
        val pacingAt = nextPacingAt
        if (remoteCredentials != null && pacingAt != null && now >= pacingAt) {
            val next = checklist.firstOrNull { it.state == CandidatePairState.Waiting }
            if (next != null) startCheck(next, nominate = false, consent = false, now = now, out = out)
            nextPacingAt = if (checklist.any { it.state == CandidatePairState.Waiting }) now + config.ta else null
        }
        // 3. Consent freshness on the selected pair (RFC 7675).
        driveConsent(now, out)
        maybeComplete(out)
    }

    private fun driveConsent(
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        val chosen = selected ?: return
        val lastResponse = lastConsentResponseAt
        // `>=`, not `>`: nextDeadline arms exactly `lastResponse + consentTimeout`, so at that instant the
        // check must fire — a strict `>` would leave the deadline in the past and spin the driver.
        if (lastResponse != null && now - lastResponse >= config.consentTimeout) {
            selected = null
            transition(IceConnectionState.Failed(IceFailureReason.ConsentExpired), out)
            return
        }
        val consentAt = nextConsentAt
        if (consentAt != null && now >= consentAt && chosen.transaction == null) {
            startCheck(chosen, nominate = false, consent = true, now = now, out = out)
            nextConsentAt = now + config.consentInterval
        }
    }

    // ---- inbound datagrams --------------------------------------------------------------------------

    private fun onDatagram(
        event: IceEvent.DatagramReceived,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        val message = (StunMessage.decode(event.data) as? StunDecodeResult.Success)?.message ?: return
        if (message.messageType.method != StunMethod.Binding) return
        when (message.messageType.stunClass) {
            StunClass.Request -> onInboundCheck(message, event.localBase, event.source, now, out)
            StunClass.SuccessResponse, StunClass.ErrorResponse -> onInboundResponse(message, event.source, now, out)
            StunClass.Indication -> Unit
        }
    }

    private fun onInboundCheck(
        request: StunMessage,
        localBase: TransportAddress,
        source: TransportAddress,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        // Authenticate with our own password (RFC 8445 §7.3): USERNAME `<ourUfrag>:<theirUfrag>` + MI.
        if (!request.verifyMessageIntegrity(localKey())) return
        val username = request.firstOrNull(StunAttributeType.Username)?.asText() ?: return
        if (username.substringBefore(':') != _localCredentials.ufrag.value) return
        val localCandidate = localCandidates.firstOrNull { it.base == localBase } ?: return

        // Role-conflict resolution (RFC 8445 §7.3.1.1): if the peer claims our role, the larger
        // tie-breaker keeps it; the loser switches, and the winner rejects this check with 487.
        val peerControlling = request.firstOrNull(IceAttributes.ICE_CONTROLLING)?.asTieBreaker()
        val peerControlled = request.firstOrNull(IceAttributes.ICE_CONTROLLED)?.asTieBreaker()
        if (_role == IceRole.Controlling && peerControlling != null) {
            if (tieBreaker >= peerControlling) {
                out += transmit(localBase, source, roleConflictResponse(request.transactionId))
                return
            }
            switchRole(IceRole.Controlled, out)
        } else if (_role == IceRole.Controlled && peerControlled != null) {
            if (tieBreaker >= peerControlled) {
                out += transmit(localBase, source, roleConflictResponse(request.transactionId))
                return
            }
            switchRole(IceRole.Controlling, out)
        }

        // Learn a peer-reflexive remote candidate for an unknown source (RFC 8445 §7.3.1.3).
        val remoteCandidate =
            remoteCandidates.firstOrNull { it.address == source }
                ?: learnPeerReflexive(source, request.firstOrNull(IceAttributes.PRIORITY)?.asPriority(), localCandidate.component, now, out)

        // Reply with a success response echoing the mapped (source) address (RFC 8445 §7.3.1.2).
        out += transmit(localBase, source, bindingSuccess(request.transactionId, source))

        val entry = checklist.firstOrNull { it.pair.local == localCandidate && it.pair.remote == remoteCandidate }
        val nominatedByPeer = request.firstOrNull(IceAttributes.USE_CANDIDATE) != null
        if (entry == null) return

        // A triggered check (RFC 8445 §7.3.1.4): (re)schedule this pair, promptly.
        if (nominatedByPeer && _role == IceRole.Controlled) entry.nominatedByPeer = true
        when (entry.state) {
            CandidatePairState.Succeeded -> if (entry.nominatedByPeer) selectPair(entry, now, out)
            CandidatePairState.InProgress -> Unit
            CandidatePairState.Waiting, CandidatePairState.Frozen, CandidatePairState.Failed ->
                startCheck(entry, nominate = false, consent = false, now = now, out = out)
        }
        maybeComplete(out)
    }

    private fun onInboundResponse(
        message: StunMessage,
        source: TransportAddress,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        val entry = byTransaction[message.transactionId] ?: return
        val txn = entry.transaction ?: return
        driveTransaction(entry, txn.handle(StunTransactionEvent.ResponseReceived(message), now), now, out)
        if (entry.transaction != null) return // response ignored (id mismatch) — nothing completed

        val wasConsent = entry.consentCheck
        val wasNominating = entry.nominating
        entry.consentCheck = false
        entry.nominating = false

        if (message.messageType.stunClass == StunClass.ErrorResponse) {
            if (message.firstOrNull(StunAttributeType.ErrorCode)?.asErrorCode()?.code == ROLE_CONFLICT) {
                switchRole(_role.opposite, out)
                entry.state = CandidatePairState.Waiting // retry under the corrected role
            } else {
                failCheck(entry, out)
            }
            return
        }
        // Success. Authenticate with the remote's password and require a symmetric transport address.
        if (!message.verifyMessageIntegrity(remoteKey())) {
            failCheck(entry, out)
            return
        }
        if (source != entry.pair.remote.address) {
            failCheck(entry, out)
            return
        }
        entry.state = CandidatePairState.Succeeded
        entry.valid = true

        if (wasConsent) {
            lastConsentResponseAt = now
            return
        }
        if (wasNominating && _role == IceRole.Controlling) {
            selectPair(entry, now, out)
            return
        }
        if (_role == IceRole.Controlled && entry.nominatedByPeer) {
            selectPair(entry, now, out)
            return
        }
        if (_role == IceRole.Controlling && selected == null && !nominationInFlight) {
            nominationInFlight = true
            startCheck(entry, nominate = true, consent = false, now = now, out = out)
        }
        maybeComplete(out)
    }

    // ---- check + response construction --------------------------------------------------------------

    private fun startCheck(
        entry: PairEntry,
        nominate: Boolean,
        consent: Boolean,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        val remote = remoteCredentials ?: return
        val txid = TransactionId.random(random)
        val prflxPriority = IceCandidate.computePriority(CandidateType.PeerReflexive, entry.pair.local.component)
        val builder =
            StunMessageBuilder
                .of(StunClass.Request, StunMethod.Binding, txid)
                .add(RawAttribute.ofText(StunAttributeType.Username, "${remote.ufrag.value}:${_localCredentials.ufrag.value}"))
                .add(IceAttributes.priority(prflxPriority))
                .add(if (_role == IceRole.Controlling) IceAttributes.controlling(tieBreaker) else IceAttributes.controlled(tieBreaker))
        if (nominate && _role == IceRole.Controlling) builder.add(IceAttributes.useCandidate())
        val datagram = builder.addMessageIntegrity(remoteKey()).addFingerprint().encode(config.bufferFactory)

        val transaction = StunTransaction(txid, datagram, config.checkPolicy)
        entry.transaction = transaction
        entry.nominating = nominate
        entry.consentCheck = consent
        entry.state = CandidatePairState.InProgress
        byTransaction[txid] = entry
        driveTransaction(entry, transaction.handle(StunTransactionEvent.Start, now), now, out)
    }

    private fun driveTransaction(
        entry: PairEntry,
        outputs: List<StunTransactionOutput>,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        for (output in outputs) {
            when (output) {
                is StunTransactionOutput.SendRequest ->
                    out += transmit(entry.pair.local.base, entry.pair.remote.address, output.datagram)
                is StunTransactionOutput.Completed -> clearTransaction(entry)
                is StunTransactionOutput.Failed -> {
                    clearTransaction(entry)
                    if (!entry.consentCheck) failCheck(entry, out)
                }
            }
        }
    }

    private fun clearTransaction(entry: PairEntry) {
        val transaction = entry.transaction ?: return
        byTransaction.remove(transaction.transactionId)
        entry.transaction = null
    }

    private fun failCheck(
        entry: PairEntry,
        out: MutableList<IceOutput>,
    ) {
        if (entry.nominating) nominationInFlight = false
        entry.state = CandidatePairState.Failed
        val allDone =
            checklist.none {
                it.state == CandidatePairState.Waiting ||
                    it.state == CandidatePairState.InProgress ||
                    it.state == CandidatePairState.Frozen
            }
        if (selected == null && allDone && checklist.isNotEmpty() && checklist.none { it.valid }) {
            transition(IceConnectionState.Failed(IceFailureReason.AllPairsFailed(checklist.size)), out)
        }
    }

    private fun selectPair(
        entry: PairEntry,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        if (selected === entry) return
        selected = entry
        entry.nominated = true
        nominationInFlight = false
        lastConsentResponseAt = now
        nextConsentAt = now + config.consentInterval
        out += IceOutput.SelectedPairChanged(entry.pair)
        transition(IceConnectionState.Connected(entry.pair), out)
        maybeComplete(out)
    }

    private fun maybeComplete(out: MutableList<IceOutput>) {
        val chosen = selected ?: return
        val pending = checklist.any { it.state == CandidatePairState.Waiting || it.state == CandidatePairState.InProgress }
        val current = _state
        if (!pending && current is IceConnectionState.Connected) transition(IceConnectionState.Completed(chosen.pair), out)
    }

    private fun learnPeerReflexive(
        source: TransportAddress,
        priorityHint: Long?,
        component: ComponentId,
        now: Instant,
        out: MutableList<IceOutput>,
    ): IceCandidate {
        val prflx =
            IceCandidate(
                type = CandidateType.PeerReflexive,
                transport = IceTransport.Udp,
                address = source,
                base = source,
                foundation = Foundation.of(CandidateType.PeerReflexive, source.ip(), serverIp = null, transport = IceTransport.Udp),
                component = component,
                priority = priorityHint ?: IceCandidate.computePriority(CandidateType.PeerReflexive, component),
            )
        remoteCandidates += prflx
        formPairs(now, out)
        return prflx
    }

    // ---- role, restart, state -----------------------------------------------------------------------

    private fun switchRole(
        to: IceRole,
        out: MutableList<IceOutput>,
    ) {
        if (_role == to) return
        _role = to
        sortChecklist()
    }

    private fun onRestart(
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        _localCredentials = IceCredentials.random(random)
        tieBreaker = TieBreaker.random(random)
        remoteCredentials = null
        remoteCandidates.clear()
        localCandidates.clear()
        checklist.clear()
        byTransaction.clear()
        selected = null
        nominationInFlight = false
        nextPacingAt = null
        nextConsentAt = null
        lastConsentResponseAt = null
        transition(IceConnectionState.New, out)
    }

    private fun transition(
        newState: IceConnectionState,
        out: MutableList<IceOutput>,
    ) {
        if (_state == newState) return
        _state = newState
        out += IceOutput.ConnectionStateChanged(newState)
    }

    // ---- STUN message helpers -----------------------------------------------------------------------

    private fun bindingSuccess(
        transactionId: TransactionId,
        mapped: TransportAddress,
    ): ReadBuffer =
        StunMessageBuilder
            .of(StunClass.SuccessResponse, StunMethod.Binding, transactionId)
            .add(RawAttribute.ofXorMappedAddress(mapped, transactionId))
            .addMessageIntegrity(localKey())
            .addFingerprint()
            .encode(config.bufferFactory)

    private fun roleConflictResponse(transactionId: TransactionId): ReadBuffer =
        StunMessageBuilder
            .of(StunClass.ErrorResponse, StunMethod.Binding, transactionId)
            .add(RawAttribute.ofErrorCode(StunErrorCode(ROLE_CONFLICT, "Role Conflict")))
            .addMessageIntegrity(localKey())
            .addFingerprint()
            .encode(config.bufferFactory)

    private fun transmit(
        fromBase: TransportAddress,
        to: TransportAddress,
        data: ReadBuffer,
    ): IceOutput.Transmit = IceOutput.Transmit(fromBase, to, data)

    private fun localKey(): ReadBuffer = passwordKey(_localCredentials.password)

    private fun remoteKey(): ReadBuffer = passwordKey(remoteCredentials!!.password)

    private fun passwordKey(password: IcePassword): ReadBuffer {
        val text = password.value
        val buffer = config.bufferFactory.allocate(maxOf(1, text.length * MAX_UTF8_PER_CHAR), ByteOrder.BIG_ENDIAN)
        buffer.writeString(text, Charset.UTF8)
        buffer.resetForRead()
        return buffer
    }

    private fun sameFamily(
        a: TransportAddress,
        b: TransportAddress,
    ): Boolean = (a.ip is IpAddress.V4) == (b.ip is IpAddress.V4)

    /**
     * Mutable checklist state for a pair (RFC 8445 §6.1.2.6). Kept separate from the immutable
     * [CandidatePair] identity so the identity stays a clean map key and a diffable fixture value.
     */
    private class PairEntry(
        val pair: CandidatePair,
    ) {
        var state: CandidatePairState = CandidatePairState.Waiting
        var transaction: StunTransaction? = null
        var nominating: Boolean = false
        var consentCheck: Boolean = false
        var nominatedByPeer: Boolean = false
        var valid: Boolean = false
        var nominated: Boolean = false
    }

    private companion object {
        const val ROLE_CONFLICT = 487
        const val MAX_UTF8_PER_CHAR = 3
    }
}

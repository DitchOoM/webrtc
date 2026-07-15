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
    /**
     * The global establishment failsafe: once checking has begun, if no pair is nominated within this
     * budget the agent gives up with a typed failure rather than hanging. This is the liveness backstop
     * (RFC §5.3 #5) that guarantees a terminal state even when the peer wedges nomination, never
     * nominates, or offers no compatible candidate.
     */
    public val establishmentTimeout: Duration = 30.seconds,
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

    // Derived, not a stored latch: a nominating check is in flight iff some pair currently holds one.
    // Making it a projection of the checklist means it can never wedge stale (the bug a stored flag hit).
    private val nominationInFlight: Boolean
        get() = checklist.any { it.inFlight?.purpose == CheckPurpose.Nomination }

    // A role conflict is resolved AT MOST ONCE per ICE generation (RFC 8445 §7.3.1.1): the inbound-check
    // path and the 487-response path must not both flip the role, or a glare oscillates. Reset on restart.
    private var roleConflictResolved = false

    private var nextPacingAt: Instant? = null
    private var nextConsentAt: Instant? = null
    private var lastConsentResponseAt: Instant? = null
    private var establishmentDeadline: Instant? = null

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
        } else if (_state !is IceConnectionState.Failed) {
            // The liveness backstop keeps a deadline armed even when nothing else is (a wedged nomination,
            // a peer that never nominates, or an empty checklist), so the driver always reaches a terminal.
            consider(establishmentDeadline)
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
        // Arm the liveness backstop once we have credentials and something to try (even if pairing yields
        // an empty checklist — the "zero compatible candidates" case must still fail, not hang).
        if (localCandidates.isNotEmpty() && establishmentDeadline == null) establishmentDeadline = now + config.establishmentTimeout
        if (_state is IceConnectionState.New && checklist.isNotEmpty()) transition(IceConnectionState.Checking, out)
    }

    // A redundant pair (RFC 8445 §6.1.2.4): same base and same remote address — keep the highest priority.
    // Only *unstarted* pairs (Waiting/Frozen) are ever pruned; a pair that is checking, valid, failed, or
    // selected is kept regardless, so pruning can never delete an in-flight/selected pair or orphan its
    // transaction (a trickled higher-priority candidate must not evict a pair already doing work).
    private fun pruneRedundant() {
        val keptKeys = HashSet<Pair<TransportAddress, TransportAddress>>()
        val kept = mutableListOf<PairEntry>()
        for (entry in checklist) {
            val started = entry.state != CandidatePairState.Waiting && entry.state != CandidatePairState.Frozen
            if (entry === selected || started) {
                kept += entry
                keptKeys += entry.pair.local.base to entry.pair.remote.address
            }
        }
        for (entry in checklist.filter { it !in kept }.sortedByDescending { it.pair.priority(_role) }) {
            if (keptKeys.add(entry.pair.local.base to entry.pair.remote.address)) kept += entry
        }
        checklist.clear()
        checklist += kept
    }

    private fun sortChecklist() = checklist.sortByDescending { it.pair.priority(_role) }

    // Ensure a pacing tick is scheduled — call whenever a pair (re)enters Waiting outside formPairs
    // (e.g. a 487 retry), so a checklist that had gone idle picks the pair back up.
    private fun armPacing(now: Instant) {
        if (nextPacingAt == null) nextPacingAt = now
    }

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
            if (next != null) startCheck(next, CheckPurpose.Connectivity, now, out)
            nextPacingAt = if (checklist.any { it.state == CandidatePairState.Waiting }) now + config.ta else null
        }
        // 3. Nomination retry (controlling): if a nominating check failed and left no nomination in flight,
        // nominate the best remaining valid pair — otherwise a valid-but-unnominated pair would hang.
        if (_role == IceRole.Controlling && selected == null && !nominationInFlight) {
            val best = checklist.filter { it.state == CandidatePairState.Succeeded }.maxByOrNull { it.pair.priority(_role) }
            if (best != null) startCheck(best, CheckPurpose.Nomination, now, out)
        }
        // 4. Consent freshness on the selected pair (RFC 7675).
        driveConsent(now, out)
        // 5. Liveness backstop: never hang — fail with a typed reason if unselected by the deadline.
        val backstop = establishmentDeadline
        if (selected == null && backstop != null && now >= backstop && _state !is IceConnectionState.Failed) {
            establishmentDeadline = null
            val reason = if (checklist.isEmpty()) IceFailureReason.NoCandidatePairs else IceFailureReason.AllPairsFailed(checklist.size)
            transition(IceConnectionState.Failed(reason), out)
        }
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
            clearTransaction(chosen) // stop retransmitting a consent check on the now-dead pair
            selected = null
            transition(IceConnectionState.Failed(IceFailureReason.ConsentExpired), out)
            return
        }
        val consentAt = nextConsentAt
        if (consentAt != null && now >= consentAt && chosen.transaction == null) {
            startCheck(chosen, CheckPurpose.Consent, now, out)
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
        // Then read attributes ONLY from the MI-covered prefix (RFC 8489 §14.5): a MITM who does not know
        // the password can splice attributes (e.g. USE-CANDIDATE) after a valid MI and fix the unkeyed
        // FINGERPRINT — both checks still pass — so trusting the tail would let it hijack nomination/role.
        if (!request.verifyMessageIntegrity(localKey())) return
        val covered = request.attributesCoveredByMessageIntegrity() ?: return
        val username = covered.firstOrNull { it.type == StunAttributeType.Username }?.asText() ?: return
        if (username.substringBefore(':') != _localCredentials.ufrag.value) return
        val localCandidate = localCandidates.firstOrNull { it.base == localBase } ?: return

        // Role-conflict resolution (RFC 8445 §7.3.1.1): the agent with the larger tie-breaker ends up
        // CONTROLLING in both directions — the controlling agent keeps its role (487s the peer) or switches
        // to controlled; the controlled agent switches to controlling or 487s the peer.
        val peerControlling = covered.firstOrNull { it.type == IceAttributes.ICE_CONTROLLING }?.asTieBreaker()
        val peerControlled = covered.firstOrNull { it.type == IceAttributes.ICE_CONTROLLED }?.asTieBreaker()
        if (!roleConflictResolved && _role == IceRole.Controlling && peerControlling != null) {
            roleConflictResolved = true
            if (tieBreaker >= peerControlling) {
                out += transmit(localBase, source, roleConflictResponse(request.transactionId))
                return
            }
            switchRole(IceRole.Controlled, out)
        } else if (!roleConflictResolved && _role == IceRole.Controlled && peerControlled != null) {
            roleConflictResolved = true
            if (tieBreaker >= peerControlled) {
                switchRole(IceRole.Controlling, out)
            } else {
                out += transmit(localBase, source, roleConflictResponse(request.transactionId))
                return
            }
        }

        // Learn a peer-reflexive remote candidate for an unknown source (RFC 8445 §7.3.1.3).
        val remoteCandidate =
            remoteCandidates.firstOrNull { it.address == source }
                ?: learnPeerReflexive(
                    source,
                    covered.firstOrNull { it.type == IceAttributes.PRIORITY }?.asPriority(),
                    localCandidate.component,
                    now,
                    out,
                )

        // Reply with a success response echoing the mapped (source) address (RFC 8445 §7.3.1.2).
        out += transmit(localBase, source, bindingSuccess(request.transactionId, source))

        val entry = checklist.firstOrNull { it.pair.local == localCandidate && it.pair.remote == remoteCandidate }
        val nominatedByPeer = covered.firstOrNull { it.type == IceAttributes.USE_CANDIDATE } != null
        if (entry == null) return

        // A triggered check (RFC 8445 §7.3.1.4): (re)schedule this pair, promptly.
        if (nominatedByPeer && _role == IceRole.Controlled) entry.nominatedByPeer = true
        when (entry.state) {
            CandidatePairState.Succeeded -> if (entry.nominatedByPeer) selectPair(entry, now, out)
            CandidatePairState.InProgress -> Unit
            CandidatePairState.Waiting, CandidatePairState.Frozen, CandidatePairState.Failed ->
                startCheck(entry, CheckPurpose.Connectivity, now, out)
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
        val purpose = entry.inFlight?.purpose // capture before driveTransaction clears it on Completed
        driveTransaction(entry, txn.handle(StunTransactionEvent.ResponseReceived(message), now), now, out)
        if (entry.inFlight != null) return // response ignored (id mismatch) — nothing completed

        // The nomination "latch" is derived from the checklist, and driveTransaction already cleared this
        // pair's in-flight check — so on any nominating-check outcome nominationInFlight is already false.
        val wasConsent = purpose == CheckPurpose.Consent
        val wasNominating = purpose == CheckPurpose.Nomination

        if (message.messageType.stunClass == StunClass.ErrorResponse) {
            if (message.firstOrNull(StunAttributeType.ErrorCode)?.asErrorCode()?.code == ROLE_CONFLICT) {
                // Switch only if this conflict hasn't already been resolved by the inbound-check path
                // (else we'd flip back and oscillate); either way, retry the pair under the settled role.
                if (!roleConflictResolved) {
                    roleConflictResolved = true
                    switchRole(_role.opposite, out)
                }
                entry.state = CandidatePairState.Waiting
                armPacing(now) // re-arm pacing so the retry is actually scheduled (it may have gone idle)
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
            startCheck(entry, CheckPurpose.Nomination, now, out)
        }
        maybeComplete(out)
    }

    // ---- check + response construction --------------------------------------------------------------

    private fun startCheck(
        entry: PairEntry,
        purpose: CheckPurpose,
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
                .add(IceAttributes.priority(prflxPriority, config.bufferFactory))
                .add(
                    if (_role == IceRole.Controlling) {
                        IceAttributes.controlling(tieBreaker, config.bufferFactory)
                    } else {
                        IceAttributes.controlled(tieBreaker, config.bufferFactory)
                    },
                )
        if (purpose == CheckPurpose.Nomination &&
            _role == IceRole.Controlling
        ) {
            builder.add(IceAttributes.useCandidate(config.bufferFactory))
        }
        val datagram = builder.addMessageIntegrity(remoteKey()).addFingerprint().encode(config.bufferFactory)

        val transaction = StunTransaction(txid, datagram, config.checkPolicy)
        entry.inFlight = InFlightCheck(transaction, purpose)
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
                    val wasConsent = entry.inFlight?.purpose == CheckPurpose.Consent
                    clearTransaction(entry)
                    if (!wasConsent) failCheck(entry, out) // a lost consent check doesn't fail the pair (RFC 7675)
                }
            }
        }
    }

    private fun clearTransaction(entry: PairEntry) {
        val inFlight = entry.inFlight ?: return
        byTransaction.remove(inFlight.transaction.transactionId)
        entry.inFlight = null
    }

    private fun failCheck(
        entry: PairEntry,
        out: MutableList<IceOutput>,
    ) {
        entry.state = CandidatePairState.Failed
        entry.valid = false // a failed pair is no longer valid — don't let a stale latch veto AllPairsFailed
        val allDone =
            checklist.none {
                it.state == CandidatePairState.Waiting ||
                    it.state == CandidatePairState.InProgress ||
                    it.state == CandidatePairState.Frozen
            }
        if (selected == null && allDone && checklist.isNotEmpty() && checklist.none { it.valid }) {
            establishmentDeadline = null
            transition(IceConnectionState.Failed(IceFailureReason.AllPairsFailed(checklist.size)), out)
        }
    }

    private fun selectPair(
        entry: PairEntry,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        if (selected != null) return // first nomination wins; never regress a Connected/Completed component
        selected = entry
        establishmentDeadline = null
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
        roleConflictResolved = false
        nextPacingAt = null
        nextConsentAt = null
        lastConsentResponseAt = null
        establishmentDeadline = null
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

    /** Why the single in-flight check on a pair is being sent (RFC 8445 §7). Mutually exclusive by
     *  construction, so "nominating AND consent" — an old boolean-soup hazard — is unrepresentable. */
    private enum class CheckPurpose { Connectivity, Nomination, Consent }

    /** A pair's one in-flight STUN transaction bundled with its [purpose] — a purpose cannot exist
     *  without a live transaction, so a stale "nominating but nothing in flight" latch can't occur. */
    private class InFlightCheck(
        val transaction: StunTransaction,
        val purpose: CheckPurpose,
    )

    /**
     * Mutable checklist state for a pair (RFC 8445 §6.1.2.6). Kept separate from the immutable
     * [CandidatePair] identity so the identity stays a clean map key and a diffable fixture value.
     * State is a [CandidatePairState] plus exactly two orthogonal facts ([valid] — has ever succeeded a
     * check; [nominatedByPeer] — the peer sent USE-CANDIDATE) and the unified [inFlight] check; there is
     * no derivable/overlapping boolean (nomination-in-flight and selection are read off the checklist).
     */
    private class PairEntry(
        val pair: CandidatePair,
    ) {
        var state: CandidatePairState = CandidatePairState.Waiting
        var inFlight: InFlightCheck? = null
        var nominatedByPeer: Boolean = false
        var valid: Boolean = false

        val transaction: StunTransaction? get() = inFlight?.transaction
    }

    private companion object {
        const val ROLE_CONFLICT = 487
        const val MAX_UTF8_PER_CHAR = 3
    }
}

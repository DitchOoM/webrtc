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
    /**
     * Retransmission policy for each *connectivity* check (RFC 8489 §6.2.1, via the W1 [StunTransaction]).
     *
     * Consent checks deliberately do **not** use it: RFC 7675 §4.1 transmits each consent request once
     * and paces the next independently, rather than retransmitting one request into a backoff chain.
     */
    public val checkPolicy: StunRetransmitPolicy = StunRetransmitPolicy(),
    /**
     * The base period between consent checks on the selected pair (RFC 7675 §4.1). Each actual interval is
     * randomized to 0.8–1.2× this, so the RFC's own default of 5 s yields the 4–6 s spacing it specifies.
     *
     * §4.1 also says an implementation MUST NOT configure a period below 4 s. That is a *deployment*
     * bound, not one this core can enforce: it is a caller-injected seam precisely so a fixture can
     * compress the whole schedule and still assert observable state under virtual time (directive #4).
     * The production default is the RFC's.
     */
    public val consentInterval: Duration = 5.seconds,
    /** How long without a consent response before the pair is declared dead (RFC 7675 §4.1). */
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
 * **Generations.** All checklist state lives in one [Generation] object, and an ICE restart (RFC 8445
 * §9) *swaps* it rather than clearing fields: the outgoing generation is **retained** — credentials,
 * checklist, nominated pair — until the new one nominates. Making the generation an object rather than
 * a dozen fields is what makes retention correct by construction; a hand-written snapshot that forgets
 * one field is exactly the bug that survives review. Retention buys §9's three guarantees at once:
 * data continues on the old pair ([IcePath.Restarting]), a rolled-back restart offer restores real
 * credentials ([IceEvent.RollbackRestart]), and the peer's checks against the old credentials are still
 * answered so its consent (RFC 7675) does not expire mid-restart.
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
    private var current: Generation = newGeneration(initialRole)
    private var retained: RetainedGeneration = RetainedGeneration.None

    // What the driver has last been told. Kept apart from the generation's own fields so a restart
    // (which installs a fresh generation already sitting at New) still emits the transition, and a
    // rollback (which reinstalls an old generation) re-publishes whatever that generation was at.
    private var publishedState: IceConnectionState = IceConnectionState.New
    private var publishedPath: IcePath = IcePath.Unnominated

    /** This agent's role. It may flip once on a role conflict (RFC 8445 §7.3.1.1), but an ICE restart
     *  never redetermines it (§9 → §6.1.1) — the new generation inherits it by construction. */
    public val role: IceRole get() = current.role

    /** The credentials this agent advertises in its SDP (regenerated on [IceEvent.Restart]). */
    public val localCredentials: IceCredentials get() = current.localCredentials

    /** The current connection state (RFC 8445 §6.1.2.6). */
    public val state: IceConnectionState get() = current.state

    /** Where application traffic rides right now (RFC 8445 §9 — see [IcePath]). */
    public val path: IcePath get() = pathNow()

    /**
     * The earliest instant the driver must call `handle(TimerFired)` — the min of the pacing tick, every
     * in-flight check's retransmit deadline, and the consent refresh/expiry. Null means no timer armed.
     *
     * Only the *current* generation is clocked: a retained generation is frozen for the restart window
     * (it carries data, it does not run checks), so it contributes no deadline.
     */
    public fun nextDeadline(now: Instant): Instant? {
        // A generation whose consent was revoked is finished (RFC 7675 §5.1), so it clocks nothing — and
        // this is the single choke point that makes that true. Without it a late trickled candidate could
        // re-arm pacing on a dead generation, and any deadline left armed on a generation whose `onTimer`
        // does nothing is a driver that spins without advancing time.
        if (current.consentRevoked) return null
        var earliest: Instant? = null

        fun consider(instant: Instant?) {
            if (instant != null && (earliest == null || instant < earliest!!)) earliest = instant
        }
        if (current.remoteCredentials != null &&
            current.checklist.any { it.state == CandidatePairState.Waiting }
        ) {
            consider(current.nextPacingAt)
        }
        for (entry in current.checklist) consider(entry.transaction?.nextDeadline())
        val chosen = current.selected
        if (chosen != null) {
            // Consent has two independent deadlines and neither gates the other (RFC 7675 §4.1): the next
            // check goes out on its own cadence whether or not an earlier one is still unanswered, and
            // revocation is measured from the last *response*. Gating the cadence on an in-flight check —
            // which is what modelling consent as a retransmitting transaction forced — is what let a single
            // backoff chain span the whole revocation window and leave it undefended.
            consider(current.nextConsentAt)
            consider(current.lastConsentResponseAt?.plus(config.consentTimeout))
        } else if (current.state !is IceConnectionState.Failed) {
            // The liveness backstop keeps a deadline armed even when nothing else is (a wedged nomination,
            // a peer that never nominates, or an empty checklist), so the driver always reaches a terminal.
            consider(current.establishmentDeadline)
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
            IceEvent.Restart -> onRestart(out)
            IceEvent.RollbackRestart -> onRollbackRestart(now, out)
        }
        return out
    }

    // ---- candidate + credential intake --------------------------------------------------------------

    private fun onAddLocalCandidate(
        candidate: IceCandidate,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        if (current.localCandidates.any { it.address == candidate.address && it.type == candidate.type }) return
        current.localCandidates += candidate
        formPairs(now, out)
    }

    private fun onAddRemoteCandidate(
        candidate: IceCandidate,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        if (current.remoteCandidates.any { it.address == candidate.address && it.type == candidate.type }) return
        current.remoteCandidates += candidate
        formPairs(now, out)
    }

    private fun onSetRemoteCredentials(
        credentials: IceCredentials,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        current.remoteCredentials = credentials
        formPairs(now, out)
    }

    // Pair every compatible (local, remote); RFC 8445 §6.1.2.2/§6.1.2.4. Runs on each intake so trickled
    // candidates extend the checklist incrementally.
    private fun formPairs(
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        val generation = current
        if (generation.remoteCredentials == null) return
        for (local in generation.localCandidates) {
            for (remote in generation.remoteCandidates) {
                if (!compatible(local, remote)) continue
                if (generation.checklist.any { it.pair.local == local && it.pair.remote == remote }) continue
                generation.checklist += PairEntry(CandidatePair(local, remote))
            }
        }
        pruneRedundant()
        sortChecklist()
        if (generation.checklist.isNotEmpty() && generation.nextPacingAt == null) generation.nextPacingAt = now
        // Arm the liveness backstop once we have credentials and something to try (even if pairing yields
        // an empty checklist — the "zero compatible candidates" case must still fail, not hang).
        if (generation.localCandidates.isNotEmpty() && generation.establishmentDeadline == null) {
            generation.establishmentDeadline = now + config.establishmentTimeout
        }
        if (generation.state is IceConnectionState.New && generation.checklist.isNotEmpty()) {
            transition(IceConnectionState.Checking, out)
        }
    }

    // A redundant pair (RFC 8445 §6.1.2.4): same base and same remote address — keep the highest priority.
    // Only *unstarted* pairs (Waiting/Frozen) are ever pruned; a pair that is checking, valid, failed, or
    // selected is kept regardless, so pruning can never delete an in-flight/selected pair or orphan its
    // transaction (a trickled higher-priority candidate must not evict a pair already doing work).
    private fun pruneRedundant() {
        val generation = current
        val keptKeys = HashSet<Pair<TransportAddress, TransportAddress>>()
        val kept = mutableListOf<PairEntry>()
        for (entry in generation.checklist) {
            val started = entry.state != CandidatePairState.Waiting && entry.state != CandidatePairState.Frozen
            if (entry === generation.selected || started) {
                kept += entry
                keptKeys += entry.pair.local.base to entry.pair.remote.address
            }
        }
        for (entry in generation.checklist.filter { it !in kept }.sortedByDescending { it.pair.priority(generation.role) }) {
            if (keptKeys.add(entry.pair.local.base to entry.pair.remote.address)) kept += entry
        }
        generation.checklist.clear()
        generation.checklist += kept
    }

    private fun sortChecklist() = current.checklist.sortByDescending { it.pair.priority(current.role) }

    // Ensure a pacing tick is scheduled — call whenever a pair (re)enters Waiting outside formPairs
    // (e.g. a 487 retry), so a checklist that had gone idle picks the pair back up.
    private fun armPacing(now: Instant) {
        if (current.nextPacingAt == null) current.nextPacingAt = now
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
        val generation = current
        // 0. RFC 7675 §5.1: a revoked generation is terminal. It retransmits nothing, paces nothing,
        // nominates nothing and refreshes nothing — recovery is an ICE restart, which installs a *new*
        // generation, never more work on this one. Paired with [nextDeadline] returning null, this leaves
        // the driver genuinely quiet rather than looping over a corpse.
        if (generation.consentRevoked) return
        // 1. Retransmit or fail every check whose transaction deadline has arrived.
        for (entry in generation.checklist.toList()) {
            val txn = entry.transaction ?: continue
            val deadline = txn.nextDeadline() ?: continue
            if (deadline <= now) driveTransaction(entry, txn.handle(StunTransactionEvent.TimerExpired, now), now, out)
        }
        // 2. Pace one new ordinary check per Ta, highest priority first (RFC 8445 §6.1.4.2).
        val pacingAt = generation.nextPacingAt
        if (generation.remoteCredentials != null && pacingAt != null && now >= pacingAt) {
            val next = generation.checklist.firstOrNull { it.state == CandidatePairState.Waiting }
            if (next != null) startCheck(next, CheckPurpose.Connectivity, now, out)
            generation.nextPacingAt =
                if (generation.checklist.any { it.state == CandidatePairState.Waiting }) now + config.ta else null
        }
        // 3. Nomination retry (controlling): if a nominating check failed and left no nomination in flight,
        // nominate the best remaining valid pair — otherwise a valid-but-unnominated pair would hang.
        // `is None`, not "selected == null": a revoked generation also has no selected pair, and this is
        // the controlling-side door the resurrection came through — re-nominating some other Succeeded
        // pair under credentials RFC 7675 §5.1 has already retired.
        if (generation.role == IceRole.Controlling &&
            generation.selection is Selection.None &&
            !generation.nominationInFlight
        ) {
            val best =
                generation.checklist
                    .filter { it.state == CandidatePairState.Succeeded }
                    .maxByOrNull { it.pair.priority(generation.role) }
            if (best != null) startCheck(best, CheckPurpose.Nomination, now, out)
        }
        // 4. Consent freshness on the selected pair (RFC 7675).
        driveConsent(now, out)
        // 5. Liveness backstop: never hang — fail with a typed reason if unselected by the deadline.
        val backstop = generation.establishmentDeadline
        if (generation.selected == null && backstop != null && now >= backstop && generation.state !is IceConnectionState.Failed) {
            generation.establishmentDeadline = null
            val reason =
                if (generation.checklist.isEmpty()) {
                    IceFailureReason.NoCandidatePairs
                } else {
                    IceFailureReason.AllPairsFailed(generation.checklist.size)
                }
            transition(IceConnectionState.Failed(reason), out)
        }
        maybeComplete(out)
    }

    private fun driveConsent(
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        val generation = current
        val chosen = generation.selected ?: return
        val lastResponse = generation.lastConsentResponseAt
        // `>=`, not `>`: nextDeadline arms exactly `lastResponse + consentTimeout`, so at that instant the
        // check must fire — a strict `>` would leave the deadline in the past and spin the driver.
        if (lastResponse != null && now - lastResponse >= config.consentTimeout) {
            generation.outstandingConsent.clear() // no answer to these can matter now
            // Every check in the generation, not just the one on the dead pair: consent is revoked for
            // these credentials, so no outstanding transaction can lead anywhere, and leaving one armed
            // would leave a deadline behind on a generation that will never service it again.
            for (entry in generation.checklist) clearTransaction(entry)
            generation.selection = Selection.Revoked(chosen)
            transition(IceConnectionState.Failed(IceFailureReason.ConsentExpired), out)
            publishPath(out) // the pair is dead: app data has nowhere to go, and must not keep flowing there
            return
        }
        val consentAt = generation.nextConsentAt
        if (consentAt != null && now >= consentAt) {
            sendConsentCheck(chosen, out)
            generation.nextConsentAt = now + nextConsentDelay()
        }
    }

    /**
     * Send one RFC 7675 §4.1 consent check: a fresh Binding request with a **new transaction id**,
     * *"transmitted once only"* — explicitly not retransmitted per RFC 8489.
     *
     * So it is deliberately not a [StunTransaction] and does not occupy the pair's [PairEntry.inFlight]
     * slot. Making consent a pair transaction conflated two unrelated things and cost three defects at
     * once: the retransmit chain outlived the revocation window it was supposed to defend (7 requests over
     * 39.5 s at the RFC defaults, versus a 30 s window) and front-loaded its probes so the last ~16 s
     * before revocation had nothing in flight at all; the "one check per pair" slot meant a check still
     * backing off blocked the next one from ever starting; and because [startCheck] marks the pair
     * `InProgress`, a pair with an unanswered consent check sat in a checking state forever, which
     * silently changed how inbound checks and completion were handled. A consent check asks one question —
     * *is the peer still there* — and now touches only the clock that answers it.
     */
    private fun sendConsentCheck(
        entry: PairEntry,
        out: MutableList<IceOutput>,
    ) {
        val generation = current
        val txid = TransactionId.random(random)
        val outstanding = generation.outstandingConsent
        // An unanswered check older than the revocation window can never refresh consent — the pair is
        // revoked by then — so the set is bounded by how many checks fit in that window. Evicting the
        // oldest keeps it from being an unbounded ledger on a peer that never answers.
        while (outstanding.size >= maxOutstandingConsentChecks()) outstanding.remove(outstanding.first())
        outstanding += txid
        out += transmit(entry.pair.local.base, entry.pair.remote.address, bindingRequest(entry, txid, nominate = false))
    }

    /**
     * The delay to the next consent check. RFC 7675 §4.1: *"each interval MUST be randomized from between
     * 0.8 and 1.2 times the basic period"*, so a fleet of agents does not synchronize its probes into a
     * thundering herd against a shared relay. The jitter is drawn from the injected [random] seam
     * (directive #2), so a scenario still replays bit-for-bit.
     */
    private fun nextConsentDelay(): Duration =
        config.consentInterval * (MIN_CONSENT_JITTER + random.nextDouble() * (MAX_CONSENT_JITTER - MIN_CONSENT_JITTER))

    private fun maxOutstandingConsentChecks(): Int {
        val closestSpacing = config.consentInterval * MIN_CONSENT_JITTER
        if (closestSpacing <= Duration.ZERO) return CONSENT_OUTSTANDING_CEILING
        return ((config.consentTimeout / closestSpacing).toInt() + 1).coerceIn(1, CONSENT_OUTSTANDING_CEILING)
    }

    /**
     * A response to one of our consent checks, if that is what this is — reported so the caller can stop.
     *
     * Matched off [Generation.outstandingConsent] rather than [Generation.byTransaction] because consent
     * checks are not transactions (see [sendConsentCheck]). Several may be outstanding at once and a late
     * one still counts: RFC 7675 §4.1 has the agent await responses on the estimated RTT, and on a slow
     * path the RTT genuinely exceeds one interval — dropping a check the moment we paced the next would
     * mean a path with RTT > interval could never refresh consent at all.
     */
    private fun onConsentResponse(
        message: StunMessage,
        source: TransportAddress,
        now: Instant,
    ): Boolean {
        val generation = current
        val chosen = generation.selected ?: return false
        if (message.transactionId !in generation.outstandingConsent) return false
        // It is ours; from here the only question is whether it proves the peer is still there. An error
        // response does not (a 487 is a role statement, not liveness), and neither does one that fails to
        // authenticate or arrives from somewhere other than the pair's remote address (RFC 8445 §7.2.5.2.1).
        if (message.messageType.stunClass != StunClass.SuccessResponse) return true
        if (!message.verifyMessageIntegrity(remoteKey())) return true
        if (source != chosen.pair.remote.address) return true
        // This response proves the path, so every check it overtook is moot — including ones still
        // outstanding, whose answers would tell us nothing this one has not already.
        generation.outstandingConsent.clear()
        generation.lastConsentResponseAt = now
        return true
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
        val generation = current
        // RFC 7675 §5.1: once consent is revoked, nothing arriving on this generation may revive it — and
        // §5.1's "MUST cease transmission on that 5-tuple" means we do not even answer. A *retained*
        // generation is a different matter: it is alive, deliberately still carrying data across a restart,
        // and its consent checks must still be answered. Delegating rather than returning outright keeps
        // that true without relying on an argument about which combinations are reachable.
        if (generation.consentRevoked) {
            answerRetainedGenerationCheck(request, localBase, source, out)
            return
        }
        // Authenticate with our own password (RFC 8445 §7.3): USERNAME `<ourUfrag>:<theirUfrag>` + MI.
        // Then read attributes ONLY from the MI-covered prefix (RFC 8489 §14.5): a MITM who does not know
        // the password can splice attributes (e.g. USE-CANDIDATE) after a valid MI and fix the unkeyed
        // FINGERPRINT — both checks still pass — so trusting the tail would let it hijack nomination/role.
        if (!request.verifyMessageIntegrity(keyOf(generation.localCredentials.password))) {
            answerRetainedGenerationCheck(request, localBase, source, out)
            return
        }
        val covered = request.attributesCoveredByMessageIntegrity() ?: return
        val username = covered.firstOrNull { it.type == StunAttributeType.Username }?.asText() ?: return
        if (username.substringBefore(':') != generation.localCredentials.ufrag.value) return
        val localCandidate = generation.localCandidates.firstOrNull { it.base == localBase } ?: return

        // Role-conflict resolution (RFC 8445 §7.3.1.1): the agent with the larger tie-breaker ends up
        // CONTROLLING in both directions — the controlling agent keeps its role (487s the peer) or switches
        // to controlled; the controlled agent switches to controlling or 487s the peer.
        val peerControlling = covered.firstOrNull { it.type == IceAttributes.ICE_CONTROLLING }?.asTieBreaker()
        val peerControlled = covered.firstOrNull { it.type == IceAttributes.ICE_CONTROLLED }?.asTieBreaker()
        if (!generation.roleConflictResolved && generation.role == IceRole.Controlling && peerControlling != null) {
            generation.roleConflictResolved = true
            if (generation.tieBreaker >= peerControlling) {
                out += transmit(localBase, source, roleConflictResponse(request.transactionId))
                return
            }
            switchRole(IceRole.Controlled)
        } else if (!generation.roleConflictResolved && generation.role == IceRole.Controlled && peerControlled != null) {
            generation.roleConflictResolved = true
            if (generation.tieBreaker >= peerControlled) {
                switchRole(IceRole.Controlling)
            } else {
                out += transmit(localBase, source, roleConflictResponse(request.transactionId))
                return
            }
        }

        // Learn a peer-reflexive remote candidate for an unknown source (RFC 8445 §7.3.1.3).
        val remoteCandidate =
            generation.remoteCandidates.firstOrNull { it.address == source }
                ?: learnPeerReflexive(
                    source,
                    covered.firstOrNull { it.type == IceAttributes.PRIORITY }?.asPriority(),
                    localCandidate.component,
                    now,
                    out,
                )

        // Reply with a success response echoing the mapped (source) address (RFC 8445 §7.3.1.2).
        out += transmit(localBase, source, bindingSuccess(request.transactionId, source, generation.localCredentials.password))

        val entry = generation.checklist.firstOrNull { it.pair.local == localCandidate && it.pair.remote == remoteCandidate }
        val nominatedByPeer = covered.firstOrNull { it.type == IceAttributes.USE_CANDIDATE } != null
        if (entry == null) return

        // A triggered check (RFC 8445 §7.3.1.4): (re)schedule this pair, promptly.
        if (nominatedByPeer && generation.role == IceRole.Controlled) entry.nominatedByPeer = true
        when (entry.state) {
            CandidatePairState.Succeeded -> if (entry.nominatedByPeer) selectPair(entry, now, out)
            CandidatePairState.InProgress -> Unit
            CandidatePairState.Waiting, CandidatePairState.Frozen, CandidatePairState.Failed ->
                startCheck(entry, CheckPurpose.Connectivity, now, out)
        }
        maybeComplete(out)
    }

    /**
     * A check that does not authenticate against the current generation may still belong to the
     * **retained** one: the peer has not learned our new credentials yet (its answer is still in
     * signaling) and is refreshing consent on the pair we are deliberately still carrying data over. Its
     * consent clock (RFC 7675 §5.1) would otherwise expire mid-restart and tear down exactly the session
     * RFC 8445 §9 promises to keep alive, so we answer it — and *only* answer it. No checklist entry, no
     * peer-reflexive learning, no role conflict: the retained generation is frozen, not running checks.
     */
    private fun answerRetainedGenerationCheck(
        request: StunMessage,
        localBase: TransportAddress,
        source: TransportAddress,
        out: MutableList<IceOutput>,
    ) {
        val previous = (retained as? RetainedGeneration.Retained)?.generation ?: return
        val password = previous.localCredentials.password
        if (!request.verifyMessageIntegrity(keyOf(password))) return
        val covered = request.attributesCoveredByMessageIntegrity() ?: return
        val username = covered.firstOrNull { it.type == StunAttributeType.Username }?.asText() ?: return
        if (username.substringBefore(':') != previous.localCredentials.ufrag.value) return
        if (previous.localCandidates.none { it.base == localBase }) return
        out += transmit(localBase, source, bindingSuccess(request.transactionId, source, password))
    }

    private fun onInboundResponse(
        message: StunMessage,
        source: TransportAddress,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        val generation = current
        // RFC 7675 consent checks are not transactions and are not on the checklist, so they are matched
        // first, off their own outstanding set. Ordering matters only for clarity — the two id spaces are
        // disjoint — but asking the cheap, specific question first keeps the pair path free of consent.
        if (onConsentResponse(message, source, now)) return
        val entry = generation.byTransaction[message.transactionId] ?: return
        val txn = entry.transaction ?: return
        val purpose = entry.inFlight?.purpose // capture before driveTransaction clears it on Completed
        driveTransaction(entry, txn.handle(StunTransactionEvent.ResponseReceived(message), now), now, out)
        if (entry.inFlight != null) return // response ignored (id mismatch) — nothing completed

        // The nomination "latch" is derived from the checklist, and driveTransaction already cleared this
        // pair's in-flight check — so on any nominating-check outcome nominationInFlight is already false.
        val wasNominating = purpose == CheckPurpose.Nomination

        if (message.messageType.stunClass == StunClass.ErrorResponse) {
            if (message.firstOrNull(StunAttributeType.ErrorCode)?.asErrorCode()?.code == ROLE_CONFLICT) {
                // Switch only if this conflict hasn't already been resolved by the inbound-check path
                // (else we'd flip back and oscillate); either way, retry the pair under the settled role.
                if (!generation.roleConflictResolved) {
                    generation.roleConflictResolved = true
                    switchRole(generation.role.opposite)
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

        if (wasNominating && generation.role == IceRole.Controlling) {
            selectPair(entry, now, out)
            return
        }
        if (generation.role == IceRole.Controlled && entry.nominatedByPeer) {
            selectPair(entry, now, out)
            return
        }
        if (generation.role == IceRole.Controlling && generation.selected == null && !generation.nominationInFlight) {
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
        val generation = current
        if (generation.remoteCredentials == null) return
        val txid = TransactionId.random(random)
        val nominate = purpose == CheckPurpose.Nomination && generation.role == IceRole.Controlling
        val transaction = StunTransaction(txid, bindingRequest(entry, txid, nominate), config.checkPolicy)
        entry.inFlight = InFlightCheck(transaction, purpose)
        entry.state = CandidatePairState.InProgress
        generation.byTransaction[txid] = entry
        driveTransaction(entry, transaction.handle(StunTransactionEvent.Start, now), now, out)
    }

    /**
     * The Binding request an outbound check carries (RFC 8445 §7.2.2): USERNAME `<theirUfrag>:<ourUfrag>`,
     * the priority we would give the resulting peer-reflexive candidate, our role and tie-breaker, keyed
     * with the *remote* password. Shared by connectivity/nomination checks and RFC 7675 consent checks,
     * which differ only in [nominate] and in what the caller does with the result — a consent check is
     * an ordinary Binding request, and building it a second way would be how the two drift apart.
     */
    private fun bindingRequest(
        entry: PairEntry,
        txid: TransactionId,
        nominate: Boolean,
    ): ReadBuffer {
        val generation = current
        val remote = generation.remoteCredentials!!
        val prflxPriority = IceCandidate.computePriority(CandidateType.PeerReflexive, entry.pair.local.component)
        val builder =
            StunMessageBuilder
                .of(StunClass.Request, StunMethod.Binding, txid, config.bufferFactory)
                .add(
                    RawAttribute.ofText(
                        StunAttributeType.Username,
                        "${remote.ufrag.value}:${generation.localCredentials.ufrag.value}",
                        config.bufferFactory,
                    ),
                ).add(IceAttributes.priority(prflxPriority, config.bufferFactory))
                .add(
                    if (generation.role == IceRole.Controlling) {
                        IceAttributes.controlling(generation.tieBreaker, config.bufferFactory)
                    } else {
                        IceAttributes.controlled(generation.tieBreaker, config.bufferFactory)
                    },
                )
        if (nominate) builder.add(IceAttributes.useCandidate(config.bufferFactory))
        return builder.addMessageIntegrity(remoteKey()).addFingerprint().encode(config.bufferFactory)
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
                    failCheck(entry, out)
                }
            }
        }
    }

    private fun clearTransaction(entry: PairEntry) {
        val inFlight = entry.inFlight ?: return
        current.byTransaction.remove(inFlight.transaction.transactionId)
        entry.inFlight = null
    }

    private fun failCheck(
        entry: PairEntry,
        out: MutableList<IceOutput>,
    ) {
        val generation = current
        entry.state = CandidatePairState.Failed
        entry.valid = false // a failed pair is no longer valid — don't let a stale latch veto AllPairsFailed
        val allDone =
            generation.checklist.none {
                it.state == CandidatePairState.Waiting ||
                    it.state == CandidatePairState.InProgress ||
                    it.state == CandidatePairState.Frozen
            }
        // `is None`: this terminal means "we could have nominated and now cannot". A revoked generation
        // already has its own typed terminal (ConsentExpired) and must not have it overwritten by
        // AllPairsFailed as its leftover checks time out — that would relabel the cause of death.
        if (generation.selection is Selection.None &&
            allDone &&
            generation.checklist.isNotEmpty() &&
            generation.checklist.none { it.valid }
        ) {
            generation.establishmentDeadline = null
            transition(IceConnectionState.Failed(IceFailureReason.AllPairsFailed(generation.checklist.size)), out)
        }
    }

    private fun selectPair(
        entry: PairEntry,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        val generation = current
        // First nomination wins, and a revoked one is not a vacancy. Testing `is None` rather than
        // `selected == null` is the whole of #75: expiry used to null the selected pair, which unlatched
        // this guard and let the next inbound check re-nominate the pair whose consent had just died —
        // and because the resurrection republished `path` as Nominated it erased its own evidence.
        if (generation.selection !is Selection.None) return
        generation.selection = Selection.Nominated(entry)
        generation.establishmentDeadline = null
        // The check that nominated this pair was answered, so consent starts fresh here (RFC 7675 §4.1).
        generation.lastConsentResponseAt = now
        generation.nextConsentAt = now + nextConsentDelay()
        // The new generation has converged, so the retained one has no job left: its sockets are the
        // driver's to retire, which it does off this very transition (Restarting → Nominated).
        retained = RetainedGeneration.None
        publishPath(out)
        transition(IceConnectionState.Connected(entry.pair), out)
        maybeComplete(out)
    }

    private fun maybeComplete(out: MutableList<IceOutput>) {
        val generation = current
        val chosen = generation.selected ?: return
        val pending =
            generation.checklist.any { it.state == CandidatePairState.Waiting || it.state == CandidatePairState.InProgress }
        if (!pending && generation.state is IceConnectionState.Connected) {
            transition(IceConnectionState.Completed(chosen.pair), out)
        }
    }

    private fun learnPeerReflexive(
        source: TransportAddress,
        priorityHint: Long?,
        component: ComponentId,
        now: Instant,
        out: MutableList<IceOutput>,
    ): IceCandidate {
        val prflx =
            IceCandidate.PeerReflexive(
                address = source,
                base = source, // a learned remote candidate: the peer's base is unknown, so the source stands in
                component = component,
                transport = IceTransport.Udp,
                foundation = Foundation.of(CandidateType.PeerReflexive, source.ip(), serverIp = null, transport = IceTransport.Udp),
                priority = priorityHint ?: IceCandidate.computePriority(CandidateType.PeerReflexive, component),
                relatedAddress = source,
            )
        current.remoteCandidates += prflx
        formPairs(now, out)
        return prflx
    }

    // ---- role, restart, state -----------------------------------------------------------------------

    private fun switchRole(to: IceRole) {
        if (current.role == to) return
        current.role = to
        sortChecklist()
    }

    /**
     * RFC 8445 §9. Installs a fresh generation and retains the outgoing one; nothing is cleared. The new
     * generation **inherits the role** — §9 forbids redetermining it, and inheriting by construction is
     * stronger than asserting it afterwards.
     */
    private fun onRestart(out: MutableList<IceOutput>) {
        val outgoing = current
        // A restart on top of an in-flight restart keeps the ORIGINAL retained generation: that is the one
        // still carrying application data. The intermediate generation never nominated, so it owns nothing
        // to preserve, and overwriting the retention with it would drop the live pair on the floor.
        //
        // A generation whose consent was revoked is likewise not retained. Retention exists to do two
        // things §9 promises — keep data flowing on the old pair and keep answering the peer's consent
        // checks on it — and RFC 7675 §5.1 forbids both on a 5-tuple whose consent is gone. Retaining it
        // would republish `path` as Restarting over a dead pair: continuity claimed over a closed door.
        if (retained is RetainedGeneration.None && outgoing.selection is Selection.Nominated) {
            retained = RetainedGeneration.Retained(outgoing)
        }
        current = newGeneration(outgoing.role)
        transition(IceConnectionState.New, out)
        publishPath(out)
    }

    /** The ICE half of `setLocalDescription(rollback)` — see [IceEvent.RollbackRestart]. */
    private fun onRollbackRestart(
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        val previous = (retained as? RetainedGeneration.Retained)?.generation ?: return
        retained = RetainedGeneration.None
        current = previous
        // The retained generation was frozen for the restart window — it carried data but ran no consent
        // checks, so its RFC 7675 clock stopped with it. Restart that clock from `now` rather than letting
        // the frozen interval count against a pair we are about to actively probe again.
        if (previous.selected != null) {
            previous.outstandingConsent.clear() // answers to checks sent before the freeze prove nothing now
            previous.lastConsentResponseAt = now
            previous.nextConsentAt = now + nextConsentDelay()
        }
        publishState(out)
        publishPath(out)
    }

    private fun newGeneration(role: IceRole): Generation =
        Generation(
            role = role,
            localCredentials = IceCredentials.random(random),
            tieBreaker = TieBreaker.random(random),
        )

    private fun pathNow(): IcePath {
        val chosen = current.selected
        if (chosen != null) return IcePath.Nominated(chosen.pair)
        val previous = (retained as? RetainedGeneration.Retained)?.generation?.selected ?: return IcePath.Unnominated
        return IcePath.Restarting(previous.pair)
    }

    private fun publishPath(out: MutableList<IceOutput>) {
        val path = pathNow()
        if (publishedPath == path) return
        publishedPath = path
        out += IceOutput.PathChanged(path)
    }

    private fun transition(
        newState: IceConnectionState,
        out: MutableList<IceOutput>,
    ) {
        current.state = newState
        publishState(out)
    }

    private fun publishState(out: MutableList<IceOutput>) {
        val newState = current.state
        if (publishedState == newState) return
        publishedState = newState
        out += IceOutput.ConnectionStateChanged(newState)
    }

    // ---- STUN message helpers -----------------------------------------------------------------------

    private fun bindingSuccess(
        transactionId: TransactionId,
        mapped: TransportAddress,
        password: IcePassword,
    ): ReadBuffer =
        StunMessageBuilder
            .of(StunClass.SuccessResponse, StunMethod.Binding, transactionId, config.bufferFactory)
            .add(RawAttribute.ofXorMappedAddress(mapped, transactionId, config.bufferFactory))
            .addMessageIntegrity(keyOf(password))
            .addFingerprint()
            .encode(config.bufferFactory)

    private fun roleConflictResponse(transactionId: TransactionId): ReadBuffer =
        StunMessageBuilder
            .of(StunClass.ErrorResponse, StunMethod.Binding, transactionId, config.bufferFactory)
            .add(RawAttribute.ofErrorCode(StunErrorCode(ROLE_CONFLICT, "Role Conflict"), config.bufferFactory))
            .addMessageIntegrity(keyOf(current.localCredentials.password))
            .addFingerprint()
            .encode(config.bufferFactory)

    private fun transmit(
        fromBase: TransportAddress,
        to: TransportAddress,
        data: ReadBuffer,
    ): IceOutput.Transmit = IceOutput.Transmit(fromBase, to, data)

    private fun remoteKey(): ReadBuffer = keyOf(current.remoteCredentials!!.password)

    private fun keyOf(password: IcePassword): ReadBuffer {
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

    /** Why the single in-flight check on a pair is being sent (RFC 8445 §7). RFC 7675 consent is *not* a
     *  member: it is not a pair check, does not retransmit, and never changes the pair's state — keeping
     *  it out of this enum is what stops the checklist and the consent clock sharing one slot again. */
    private enum class CheckPurpose { Connectivity, Nomination }

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

    /**
     * One **ICE generation** (RFC 8445 §9): the credentials the agent advertises plus every piece of
     * state derived from them. A restart swaps the whole object, so "what a restart resets" is answered
     * by membership here rather than by a list of assignments that can silently fall out of date.
     *
     * [role] lives here so a rollback restores the role the retained generation actually settled on, but
     * a restart *inherits* it rather than redetermining it (§9 → §6.1.1).
     */
    private class Generation(
        var role: IceRole,
        val localCredentials: IceCredentials,
        val tieBreaker: TieBreaker,
    ) {
        var remoteCredentials: IceCredentials? = null
        val localCandidates: MutableList<IceCandidate> = mutableListOf()
        val remoteCandidates: MutableList<IceCandidate> = mutableListOf()
        val checklist: MutableList<PairEntry> = mutableListOf()
        val byTransaction: HashMap<TransactionId, PairEntry> = HashMap()
        var state: IceConnectionState = IceConnectionState.New
        var selection: Selection = Selection.None

        /** The pair currently carrying application data, or null when none is — never nominated, or
         *  consent revoked. Callers that may still *make* a selection must test [Selection.None]
         *  instead: a null here is also what a revoked generation looks like, and the two must not act
         *  alike (that conflation is precisely the resurrection). */
        val selected: PairEntry? get() = (selection as? Selection.Nominated)?.entry

        /** RFC 7675 §5.1 revoked this generation's consent, so it is finished: it runs no checks, takes
         *  no nomination, answers nothing, and clocks nothing. Recovery is a *new* generation. */
        val consentRevoked: Boolean get() = selection is Selection.Revoked

        // A role conflict is resolved AT MOST ONCE per ICE generation (RFC 8445 §7.3.1.1): the inbound-check
        // path and the 487-response path must not both flip the role, or a glare oscillates.
        var roleConflictResolved: Boolean = false
        var nextPacingAt: Instant? = null
        var nextConsentAt: Instant? = null
        var lastConsentResponseAt: Instant? = null
        var establishmentDeadline: Instant? = null

        // Transaction ids of consent checks sent but not yet answered (RFC 7675 §4.1). Insertion-ordered
        // and bounded by the revocation window, so the oldest can be evicted: a check unanswered for
        // longer than that window could not refresh consent even if it were answered.
        val outstandingConsent: LinkedHashSet<TransactionId> = LinkedHashSet()

        // Derived, not a stored latch: a nominating check is in flight iff some pair currently holds one.
        // Making it a projection of the checklist means it can never wedge stale (the bug a stored flag hit).
        val nominationInFlight: Boolean
            get() = checklist.any { it.inFlight?.purpose == CheckPurpose.Nomination }
    }

    /**
     * What this generation has nominated, and whether that nomination is still alive.
     *
     * Sealed rather than a `selected: PairEntry?` plus a `consentRevoked: Boolean`, because those two
     * fields can encode a state that must not exist — *nominated and revoked at once* — and the whole
     * defect this replaces was two call sites disagreeing about which half of that pair to read.
     * `selectPair`'s "first nomination wins" guard tested only the null, so the instant consent expiry
     * nulled it the guard came undone and the very next inbound check re-nominated the pair whose consent
     * had just died. As three cases the compiler asks, at each site, which of *never*, *now* and *no
     * longer* is meant — and [Revoked] is not [None], so nothing can drift back into treating it as
     * "free to nominate".
     */
    private sealed interface Selection {
        /** Nothing nominated yet in this generation; it may still nominate. */
        data object None : Selection

        /** [entry] is nominated and carrying data, with consent fresh (RFC 7675). */
        data class Nominated(
            val entry: PairEntry,
        ) : Selection

        /**
         * Consent on [entry] expired (RFC 7675 §4.1) — **terminal for the generation**. §5.1: *"After
         * consent is lost, the same ICE credentials MUST NOT be used on the affected 5-tuple again. That
         * means that a new session, or an ICE restart, is needed."* [entry] is kept rather than dropped so
         * the dead pair stays nameable in diagnostics; it is never re-selected.
         */
        data class Revoked(
            val entry: PairEntry,
        ) : Selection
    }

    /**
     * Whether an ICE restart is in flight, and if so the generation still carrying application data. A
     * sealed pair rather than a nullable field because the two cases drive different behaviour on three
     * separate paths (path publication, rollback, and answering the peer's old-credential checks) — the
     * situation where a null would be read as "nothing to do" on one of them and mean the opposite.
     */
    private sealed interface RetainedGeneration {
        /** No restart in flight — the current generation is the only one. */
        data object None : RetainedGeneration

        /** A restart is in flight; [generation] is the outgoing one, frozen but still carrying data. */
        data class Retained(
            val generation: Generation,
        ) : RetainedGeneration
    }

    private companion object {
        const val ROLE_CONFLICT = 487
        const val MAX_UTF8_PER_CHAR = 3

        // RFC 7675 §4.1: "each interval MUST be randomized from between 0.8 and 1.2 times the basic period".
        // Deliberately not `const`: a const in a private companion is still emitted as a public static
        // field on JVM, and this change alters no public API — `apiCheck` is what caught the difference.
        val MIN_CONSENT_JITTER = 0.8
        val MAX_CONSENT_JITTER = 1.2

        // A hard ceiling on outstanding consent ids, so a pathological config (a consent interval of zero,
        // or a revocation window orders of magnitude larger than it) cannot turn the set into a leak.
        val CONSENT_OUTSTANDING_CEILING = 64
    }
}

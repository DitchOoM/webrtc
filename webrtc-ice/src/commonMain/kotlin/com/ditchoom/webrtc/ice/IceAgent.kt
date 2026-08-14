@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.Utf8
import com.ditchoom.buffer.utf8Size
import com.ditchoom.buffer.writeText
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
     * Retransmission policy for each *connectivity* check (RFC 8489 §6.2.1, via [StunTransaction]).
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
     * (ARCHITECTURE §5.3 #5) that guarantees a terminal state even when the peer wedges nomination, never
     * nominates, or offers no compatible candidate.
     */
    public val establishmentTimeout: Duration = 30.seconds,
    public val bufferFactory: BufferFactory = networkBuffer(),
)

/**
 * The **sans-io ICE agent** (RFC 8445 + trickle 8838 + consent 7675) — a pure
 * `handle(event, now): List<Output>` plus [nextDeadline], with **no dispatcher, clock, RNG, or socket
 * inside** (ARCHITECTURE §5.1). It owns the checklist, the connectivity-check state machine (driven by the
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
 * **Trickle generations.** A trickled candidate may name the generation it was gathered in (RFC 8838
 * §3.1, [CandidateGeneration]), and if it does it is routed to that generation rather than to whichever
 * one happens to be current: applied, discarded as superseded, or **held** — bounded — until the
 * generation it names is signaled. That last case is the restart window, closed: a candidate for the
 * peer's new generation that overtakes the offer announcing it used to be naturalized into the outgoing
 * generation and discarded with it, leaving peer-reflexive learning (§7.3.1.3) to rediscover the path.
 * An **untagged** candidate — every peer that carries no ufrag, which is most of them — is applied to
 * the current generation exactly as it always was.
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

    // ---- the PEER's generation timeline (RFC 8838 §3.1) ---------------------------------------------
    //
    // Deliberately NOT fields on [Generation]: these track the remote agent's generations, which advance
    // when the peer signals new credentials, not when we restart. A restart swaps `current` for a
    // generation that has been signaled nothing, and a ledger living inside it would forget — at exactly
    // the moment a late candidate for the peer's outgoing generation is most likely to arrive — which
    // remote ufrag we were ever talking to.
    private var remoteGeneration: RemoteGeneration = RemoteGeneration.None
    private val retiredRemoteUfrags = LinkedHashSet<Ufrag>()
    private val heldCandidates = mutableListOf<HeldCandidate>()

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
        // Revocation is terminal, so it short-circuits before anything else is even considered — a late
        // trickled candidate must not re-arm pacing on a dead generation, and a deadline left armed on a
        // generation whose `onTimer` does nothing is a driver that spins without advancing time. Written
        // as the first arm of the exhaustive `when` below rather than a guard above it, so adding a
        // Selection case is a compile error here instead of a silently-skipped clock.
        var earliest: Instant? = null

        fun consider(instant: Instant?) {
            if (instant != null && (earliest == null || instant < earliest!!)) earliest = instant
        }
        when (val selection = current.selection) {
            is Selection.Revoked -> return null
            Selection.None ->
                // The liveness backstop keeps a deadline armed even when nothing else is (a wedged
                // nomination, a peer that never nominates, or an empty checklist), so the driver always
                // reaches a terminal.
                if (current.state !is IceConnectionState.Failed) consider(current.establishmentDeadline)
            is Selection.Nominated -> {
                // Consent has two independent deadlines and neither gates the other (RFC 7675 §4.1): the
                // next check goes out on its own cadence whether or not an earlier one is still
                // unanswered, and revocation is measured from the last *response*. Gating the cadence on
                // an in-flight check — which is what modelling consent as a retransmitting transaction
                // forced — is what let one backoff chain span the whole window and leave it undefended.
                consider(selection.consent.nextCheckAt)
                consider(selection.consent.lastResponseAt + config.consentTimeout)
            }
        }
        if (current.remote is RemotePeer.Signaled &&
            current.checklist.any { it.state == CheckState.Waiting }
        ) {
            consider(current.nextPacingAt)
        }
        for (entry in current.checklist) consider(entry.transaction?.nextDeadline())
        return earliest
    }

    public fun handle(
        event: IceEvent,
        now: Instant,
    ): List<IceOutput> {
        val out = mutableListOf<IceOutput>()
        when (event) {
            is IceEvent.AddLocalCandidate -> onAddLocalCandidate(event.candidate, now, out)
            is IceEvent.AddRemoteCandidate -> onTrickledCandidate(event, now, out)
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
        current.remote = RemotePeer.Signaled(credentials)
        val released = adoptRemoteGeneration(credentials.ufrag)
        formPairs(now, out)
        // Whatever was waiting for these credentials was waiting for exactly this (RFC 8838 §3.1), and
        // enters through the same door every other remote candidate does — including its dedup, its
        // pairing and its pacing. Released AFTER the credentials are installed, so the pairs it forms are
        // checkable immediately rather than sitting until the next intake happens to run formPairs again.
        for (candidate in released) onAddRemoteCandidate(candidate, now, out)
    }

    // ---- trickle generations (RFC 8838 §3.1) --------------------------------------------------------

    /**
     * Route a trickled candidate to the generation it names, or hold it until that generation exists.
     *
     * The four answers are four cases, not a nullable ufrag plus flags, because each carries different
     * data and a different action — and because "unknown" and "absent" are the two that a `Ufrag?` would
     * have collapsed into one, which is the whole defect: an *untagged* candidate must be applied now,
     * while one tagged for a generation we have not applied must not be.
     */
    private fun onTrickledCandidate(
        event: IceEvent.AddRemoteCandidate,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        when (val route = routeOf(event.generation)) {
            // Pre-tag behaviour, preserved exactly: no generation was named, so the current one is meant.
            CandidateRoute.Untagged -> onAddRemoteCandidate(event.candidate, now, out)
            CandidateRoute.AppliedGeneration -> onAddRemoteCandidate(event.candidate, now, out)
            is CandidateRoute.SupersededGeneration ->
                out += IceOutput.RemoteCandidateDiscarded(event.candidate, CandidateDiscardReason.SupersededGeneration(route.ufrag))
            is CandidateRoute.UnappliedGeneration -> hold(event.candidate, route.ufrag, out)
        }
    }

    private fun routeOf(generation: CandidateGeneration): CandidateRoute =
        when (generation) {
            CandidateGeneration.Untagged -> CandidateRoute.Untagged
            is CandidateGeneration.Tagged ->
                when (val known = remoteGeneration) {
                    // Nothing signaled yet, so nothing to compare against: this candidate names a
                    // generation we cannot yet place. Held, not dropped — see [adoptRemoteGeneration],
                    // where the first credentials to arrive release the lot.
                    RemoteGeneration.None -> CandidateRoute.UnappliedGeneration(generation.ufrag)
                    is RemoteGeneration.Applied ->
                        when {
                            known.ufrag == generation.ufrag -> CandidateRoute.AppliedGeneration
                            generation.ufrag in retiredRemoteUfrags -> CandidateRoute.SupersededGeneration(generation.ufrag)
                            else -> CandidateRoute.UnappliedGeneration(generation.ufrag)
                        }
                }
        }

    /**
     * Record that the peer's applied generation is now [ufrag], retiring the one it replaces, and return
     * the held candidates that belong to it.
     *
     * The **first** application is deliberately permissive: everything held is released, whatever it was
     * tagged with. Before it there is no generation for a candidate to be late for, so a tag we cannot
     * match means only that the peer's `ufrag` attribute disagrees with its own `a=ice-ufrag` — and
     * stranding a whole first negotiation over a disagreement about an optional attribute would turn an
     * interop annoyance into a dead session. Once a generation *has* been applied, routing is strict:
     * from then on an unmatched tag genuinely distinguishes past from future.
     *
     * There is deliberately no sweep here for held candidates whose generation has since been superseded,
     * because **a held candidate's generation can never be superseded**: the hold is emptied in full the
     * instant its generation is applied, and a candidate for a generation already applied *and* left is
     * discarded at the door rather than held. Eviction is therefore the only way a held candidate leaves
     * without being used, and eviction is bounded ([hold]). A sweep for a state that cannot occur would be
     * untestable code claiming to defend a buffer that is defended elsewhere.
     */
    private fun adoptRemoteGeneration(ufrag: Ufrag): List<IceCandidate> {
        when (val known = remoteGeneration) {
            RemoteGeneration.None -> {
                remoteGeneration = RemoteGeneration.Applied(ufrag)
                val all = heldCandidates.map { it.candidate }
                heldCandidates.clear()
                return all
            }
            is RemoteGeneration.Applied -> {
                if (known.ufrag == ufrag) return takeHeld(ufrag)
                retire(known.ufrag)
                remoteGeneration = RemoteGeneration.Applied(ufrag)
                return takeHeld(ufrag)
            }
        }
    }

    /** Remove and return everything held for [ufrag] (insertion order preserved). */
    private fun takeHeld(ufrag: Ufrag): List<IceCandidate> {
        val released = heldCandidates.filter { it.ufrag == ufrag }
        heldCandidates.removeAll(released)
        return released.map { it.candidate }
    }

    /** A generation the peer has left: remembered, bounded, most-recently-retired last. */
    private fun retire(ufrag: Ufrag) {
        retiredRemoteUfrags.remove(ufrag)
        retiredRemoteUfrags += ufrag
        while (retiredRemoteUfrags.size > MAX_RETIRED_REMOTE_GENERATIONS) {
            retiredRemoteUfrags.remove(retiredRemoteUfrags.first())
        }
    }

    /**
     * Hold a candidate for a generation that has not been applied yet, evicting the oldest held candidate
     * when the buffer is full.
     *
     * The bound ([MAX_HELD_CANDIDATES]) is the point: a peer that trickles candidates tagged with
     * generations it never signals — broken, or hostile — would otherwise grow this without limit, and an
     * unbounded buffer fed straight off the network is a denial of service, not a feature. Eviction is
     * oldest-first because the newest tag is the likeliest to be the one about to be signaled. Nothing
     * here is clocked: a held candidate is released by an *event* (the credentials arriving), never by a
     * timer, so this adds no deadline to [nextDeadline] and the core stays sans-io.
     */
    private fun hold(
        candidate: IceCandidate,
        ufrag: Ufrag,
        out: MutableList<IceOutput>,
    ) {
        while (heldCandidates.size >= MAX_HELD_CANDIDATES) {
            val evicted = heldCandidates.removeAt(0)
            out +=
                IceOutput.RemoteCandidateDiscarded(
                    evicted.candidate,
                    CandidateDiscardReason.UnappliedGenerationOverflow(evicted.ufrag),
                )
        }
        heldCandidates += HeldCandidate(ufrag, candidate)
    }

    // Pair every compatible (local, remote); RFC 8445 §6.1.2.2/§6.1.2.4. Runs on each intake so trickled
    // candidates extend the checklist incrementally.
    private fun formPairs(
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        val generation = current
        if (generation.remote !is RemotePeer.Signaled) return
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
            val started = entry.state != CheckState.Waiting && entry.state != CheckState.Frozen
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
        if (generation.remote is RemotePeer.Signaled && pacingAt != null && now >= pacingAt) {
            val next = generation.checklist.firstOrNull { it.state == CheckState.Waiting }
            if (next != null) startCheck(next, CheckPurpose.Connectivity, now, out)
            generation.nextPacingAt =
                if (generation.checklist.any { it.state == CheckState.Waiting }) now + config.ta else null
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
                    .filter { it.state == CheckState.Succeeded }
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
        val nominated = generation.selection as? Selection.Nominated ?: return
        val consent = nominated.consent
        // `>=`, not `>`: nextDeadline arms exactly `lastResponseAt + consentTimeout`, so at that instant
        // the check must fire — a strict `>` would leave the deadline in the past and spin the driver.
        if (now - consent.lastResponseAt >= config.consentTimeout) {
            // Swapping the case *is* discarding the clock — the outstanding ids go with it, because
            // Selection.Revoked has nowhere to hold them. What still needs saying out loud is the
            // checklist: consent is revoked for these credentials, so no outstanding transaction can lead
            // anywhere, and one left armed would leave a deadline on a generation nothing will service.
            for (entry in generation.checklist) clearTransaction(entry, becomes = CheckState.Failed)
            generation.selection = Selection.Revoked(nominated.entry)
            transition(IceConnectionState.Failed(IceFailureReason.ConsentExpired), out)
            publishPath(out) // the pair is dead: app data has nowhere to go, and must not keep flowing there
            return
        }
        if (now >= consent.nextCheckAt) {
            sendConsentCheck(nominated, out)
            consent.nextCheckAt = now + nextConsentDelay()
        }
    }

    /**
     * Send one RFC 7675 §4.1 consent check: a fresh Binding request with a **new transaction id**,
     * *"transmitted once only"* — explicitly not retransmitted per RFC 8489.
     *
     * So it is deliberately not a [StunTransaction] and does not occupy the pair's one
     * [CheckState.InProgress] slot. Making consent a pair transaction conflated two unrelated things and cost three defects at
     * once: the retransmit chain outlived the revocation window it was supposed to defend (7 requests over
     * 39.5 s at the RFC defaults, versus a 30 s window) and front-loaded its probes so the last ~16 s
     * before revocation had nothing in flight at all; the "one check per pair" slot meant a check still
     * backing off blocked the next one from ever starting; and because [startCheck] marks the pair
     * `InProgress`, a pair with an unanswered consent check sat in a checking state forever, which
     * silently changed how inbound checks and completion were handled. A consent check asks one question —
     * *is the peer still there* — and now touches only the clock that answers it.
     */
    private fun sendConsentCheck(
        nominated: Selection.Nominated,
        out: MutableList<IceOutput>,
    ) {
        val entry = nominated.entry
        val remote = current.signaledCredentials ?: return
        val txid = TransactionId.random(random)
        val outstanding = nominated.consent.outstanding
        // An unanswered check older than the revocation window can never refresh consent — the pair is
        // revoked by then — so the set is bounded by how many checks fit in that window. Evicting the
        // oldest keeps it from being an unbounded ledger on a peer that never answers.
        val ceiling = maxOutstandingConsentChecks()
        while (outstanding.size >= ceiling) outstanding.remove(outstanding.first())
        outstanding += txid
        out += transmit(entry.pair.local.base, entry.pair.remote.address, bindingRequest(entry, txid, nominate = false, remote))
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
        val nominated = current.selection as? Selection.Nominated ?: return false
        val consent = nominated.consent
        if (message.transactionId !in consent.outstanding) return false
        // It is ours; from here the only question is whether it proves the peer is still there. An error
        // response does not (a 487 is a role statement, not liveness), and neither does one that fails to
        // authenticate or arrives from somewhere other than the pair's remote address (RFC 8445 §7.2.5.2.1).
        if (message.messageType.stunClass != StunClass.SuccessResponse) return true
        val remote = current.signaledCredentials ?: return true
        if (!withKey(remote.password) { message.verifyMessageIntegrity(it) }) return true
        if (source != nominated.entry.pair.remote.address) return true
        // This response proves the path, so every check it overtook is moot — including ones still
        // outstanding, whose answers would tell us nothing this one has not already.
        consent.outstanding.clear()
        consent.lastResponseAt = now
        return true
    }

    // ---- inbound datagrams --------------------------------------------------------------------------

    private fun onDatagram(
        event: IceEvent.DatagramReceived,
        now: Instant,
        out: MutableList<IceOutput>,
    ) {
        val message = (StunMessage.decode(event.data) as? StunDecodeResult.Success)?.message ?: return
        // `finally`, because every handler below is dense with early returns — an unauthenticated check,
        // an unknown ufrag, a role conflict answered — and each one is an exit that owes the decode's
        // views (see [StunMessage.release]). Releasing on the success path alone would give the chunk
        // back only for the packets that did everything right, which is the opposite of what a peer
        // sending junk should cost us.
        //
        // Safe because nothing survives the call: the agent reads attributes into value types (String,
        // Long, TransportAddress) and `StunTransaction.onResponse` returns the message without storing
        // it. The buffer `event.data` itself is NOT freed here — the drive loop still owns it and
        // releases it after `handle`, under the last-reader rule.
        try {
            if (message.messageType.method != StunMethod.Binding) return
            when (message.messageType.stunClass) {
                StunClass.Request -> onInboundCheck(message, event.localBase, event.source, now, out)
                StunClass.SuccessResponse, StunClass.ErrorResponse -> onInboundResponse(message, event.source, now, out)
                StunClass.Indication -> Unit
            }
        } finally {
            message.release()
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
        if (!withKey(generation.localCredentials.password) { request.verifyMessageIntegrity(it) }) {
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
            CheckState.Succeeded -> if (entry.nominatedByPeer) selectPair(entry, now, out)
            is CheckState.InProgress -> Unit
            CheckState.Waiting, CheckState.Frozen, CheckState.Failed ->
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
        if (!withKey(password) { request.verifyMessageIntegrity(it) }) return
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
        val purpose = entry.inFlightPurpose // capture before driveTransaction clears it on Completed
        driveTransaction(entry, txn.handle(StunTransactionEvent.ResponseReceived(message), now), now, out)
        if (entry.state is CheckState.InProgress) return // response ignored (id mismatch) — nothing completed

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
                entry.state = CheckState.Waiting
                armPacing(now) // re-arm pacing so the retry is actually scheduled (it may have gone idle)
            } else {
                failCheck(entry, out)
            }
            return
        }
        // Success. Authenticate with the remote's password and require a symmetric transport address.
        val remote = generation.signaledCredentials ?: return
        if (!withKey(remote.password) { message.verifyMessageIntegrity(it) }) {
            failCheck(entry, out)
            return
        }
        if (source != entry.pair.remote.address) {
            failCheck(entry, out)
            return
        }
        entry.state = CheckState.Succeeded

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
        val remote = generation.signaledCredentials ?: return
        val txid = TransactionId.random(random)
        val nominate = purpose == CheckPurpose.Nomination && generation.role == IceRole.Controlling
        val transaction = StunTransaction(txid, bindingRequest(entry, txid, nominate, remote), config.checkPolicy)
        entry.state = CheckState.InProgress(InFlightCheck(transaction, purpose))
        generation.byTransaction[txid] = entry
        driveTransaction(entry, transaction.handle(StunTransactionEvent.Start, now), now, out)
    }

    /**
     * The Binding request an outbound check carries (RFC 8445 §7.2.2): USERNAME `<theirUfrag>:<ourUfrag>`,
     * the priority we would give the resulting peer-reflexive candidate, our role and tie-breaker, keyed
     * with the *remote* password. Shared by connectivity/nomination checks and RFC 7675 consent checks,
     * which differ only in [nominate] and in what the caller does with the result — a consent check is
     * an ordinary Binding request, and building it a second way would be how the two drift apart.
     *
     * [remote] is passed in rather than read off the generation, so the "have we been signaled yet?"
     * question is answered once by the caller that can actually act on the answer — instead of being
     * asserted away with a `!!` on a reachability argument, which is what #84 removed.
     */
    private fun bindingRequest(
        entry: PairEntry,
        txid: TransactionId,
        nominate: Boolean,
        remote: IceCredentials,
    ): ReadBuffer {
        val generation = current
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
        return withKey(remote.password) { builder.addMessageIntegrity(it).addFingerprint().encode(config.bufferFactory) }
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
                // The transaction is over, but the *outcome* is [onInboundResponse]'s to set — it still has
                // to authenticate the response and check the address is symmetric. Waiting is the honest
                // interim, and deliberately the state the machine makes progress from: an edit that ever
                // forgot to set the outcome would leave a pair that gets re-checked, not one parked
                // forever, which is exactly how the old InProgress-with-no-transaction bug behaved.
                is StunTransactionOutput.Completed -> clearTransaction(entry, becomes = CheckState.Waiting)
                is StunTransactionOutput.Failed -> {
                    clearTransaction(entry, becomes = CheckState.Failed)
                    failCheck(entry, out)
                }
            }
        }
    }

    /**
     * Retire the in-flight check on [entry] and move the pair to [becomes].
     *
     * The successor state is a required argument, and that is the whole point: the previous shape let a
     * caller drop the transaction and say nothing about the pair, which left it `InProgress` forever (see
     * [CheckState]). Now every caller has to answer the question that was silently getting answered wrong.
     */
    private fun clearTransaction(
        entry: PairEntry,
        becomes: CheckState,
    ) {
        // Returns without touching [becomes] when nothing is in flight, so a caller sweeping the whole
        // checklist cannot clobber the state of a pair that was never checking. Defensive rather than
        // load-bearing: today's only sweep runs on an already-terminal generation, and removing this
        // early return fails no test. It is kept because it preserves the pre-fusion `?: return`
        // semantics exactly, and a future caller that sweeps a *live* checklist would otherwise silently
        // rewrite states it never checked.
        val inFlight = (entry.state as? CheckState.InProgress)?.check ?: return
        current.byTransaction.remove(inFlight.transaction.transactionId)
        // Dropping a transaction is not the same as finishing one: nothing will deliver it a response or
        // a timeout now, so `goTerminal` — the only place its request buffer is released — would never
        // run. Consent revocation sweeps the whole checklist through here, which made a revoked session
        // leak one request per pair still in flight.
        inFlight.transaction.abandon()
        entry.state = becomes
    }

    private fun failCheck(
        entry: PairEntry,
        out: MutableList<IceOutput>,
    ) {
        val generation = current
        entry.state = CheckState.Failed
        val allDone =
            generation.checklist.none {
                it.state == CheckState.Waiting ||
                    it.state is CheckState.InProgress ||
                    it.state == CheckState.Frozen
            }
        // `is None`: this terminal means "we could have nominated and now cannot". A revoked generation
        // already has its own typed terminal (ConsentExpired) and must not have it overwritten by
        // AllPairsFailed as its leftover checks time out — that would relabel the cause of death.
        if (generation.selection is Selection.None &&
            allDone &&
            generation.checklist.isNotEmpty() &&
            generation.checklist.none { it.state == CheckState.Succeeded }
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
        // The check that nominated this pair was answered, so the consent clock starts here with a real
        // round trip behind it (RFC 7675 §4.1) — which is why [Consent.lastResponseAt] need not be nullable.
        generation.selection =
            Selection.Nominated(entry, Consent(lastResponseAt = now, nextCheckAt = now + nextConsentDelay()))
        generation.establishmentDeadline = null
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
            generation.checklist.any { it.state == CheckState.Waiting || it.state is CheckState.InProgress }
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
        // Whatever happens to `outgoing` below — retained, or dropped — its in-flight checks are over:
        // the new generation has its own credentials, so no answer to them can ever be matched. Their
        // request buffers are released here because nothing else will deliver those transactions an end.
        outgoing.abandonInFlight()
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
        // The generation being rolled back OUT of is discarded here and will never be answered.
        current.abandonInFlight()
        retained = RetainedGeneration.None
        current = previous
        // The retained generation was frozen for the restart window — it carried data but ran no consent
        // checks, so its RFC 7675 clock stopped with it. Give it a *fresh* clock rather than resetting the
        // old one field by field: the frozen interval must not count against a pair we are about to probe
        // again, and answers to checks sent before the freeze prove nothing now. Building a new [Consent]
        // states both at once — and cannot forget a field the way a list of assignments can.
        val nominated = previous.selection as? Selection.Nominated
        if (nominated != null) {
            previous.selection =
                Selection.Nominated(nominated.entry, Consent(lastResponseAt = now, nextCheckAt = now + nextConsentDelay()))
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
        withKey(password) { key ->
            StunMessageBuilder
                .of(StunClass.SuccessResponse, StunMethod.Binding, transactionId, config.bufferFactory)
                .add(RawAttribute.ofXorMappedAddress(mapped, transactionId, config.bufferFactory))
                .addMessageIntegrity(key)
                .addFingerprint()
                .encode(config.bufferFactory)
        }

    private fun roleConflictResponse(transactionId: TransactionId): ReadBuffer =
        withKey(current.localCredentials.password) { key ->
            StunMessageBuilder
                .of(StunClass.ErrorResponse, StunMethod.Binding, transactionId, config.bufferFactory)
                .add(RawAttribute.ofErrorCode(StunErrorCode(ROLE_CONFLICT, "Role Conflict"), config.bufferFactory))
                .addMessageIntegrity(key)
                .addFingerprint()
                .encode(config.bufferFactory)
        }

    private fun transmit(
        fromBase: TransportAddress,
        to: TransportAddress,
        data: ReadBuffer,
    ): IceOutput.Transmit = IceOutput.Transmit(fromBase, to, data)

    /**
     * Derive the short-term MESSAGE-INTEGRITY key for [password], run [block] over it, and release it.
     *
     * Every keyed operation here — verifying an inbound check, signing an outbound one — only *reads* the
     * key, so its lifetime is exactly this call. It used to be allocated per packet and dropped, which on
     * a native factory is not a GC's problem to solve: an established session verifies a check every
     * consent interval, forever.
     *
     * Deriving it once per credentials set would be better still, but a cached key is a buffer held for
     * the life of the generation, and that is indistinguishable from a leak to the pool accounting
     * `BufferLifecycleTest` asserts on. Scoping it keeps the invariant exact and still costs only a pool
     * hit; the cache wants a generation-scoped release path first.
     */
    private inline fun <T> withKey(
        password: IcePassword,
        block: (ReadBuffer) -> T,
    ): T {
        val text = password.value
        // Sized exactly rather than by the 3-bytes-per-char upper bound: an ICE password is
        // `ice-char` (RFC 8445 §5.3, ASCII) in every implementation, so the bound only ever
        // over-allocated, and this buffer comes from the injected factory — on a pooled one, a
        // three-times-oversized request can take a larger chunk class for the whole call.
        val buffer = config.bufferFactory.allocate(maxOf(1, text.utf8Size()), ByteOrder.BIG_ENDIAN)
        buffer.writeText(text, Utf8.Lenient)
        buffer.resetForRead()
        try {
            return block(buffer)
        } finally {
            buffer.freeNativeMemory()
        }
    }

    private fun sameFamily(
        a: TransportAddress,
        b: TransportAddress,
    ): Boolean = (a.ip is IpAddress.V4) == (b.ip is IpAddress.V4)

    /**
     * Whether the peer's ICE credentials have been signaled (RFC 8445 §7.3). No check can be built or
     * authenticated without them, so this gates pairing, pacing and every outbound request.
     *
     * Sealed rather than a nullable `IceCredentials?`, because the nullable was read with `!!` at two
     * sites whose safety rested on a *reachability argument* — "you cannot be building a check without
     * credentials". Reachability arguments are exactly what the `selectPair` guard was resting on until
     * consent expiry quietly invalidated it. The session layer already models the same fact this way
     * (`PeerConnection.RemoteIceCredentials`); this brings `webrtc-ice` in line with it.
     */
    private sealed interface RemotePeer {
        /** No offer/answer has carried the peer's ufrag/pwd yet — nothing can be checked. */
        data object Unsignaled : RemotePeer

        /** The peer's [credentials] arrived from signaling; pairing and checks can proceed. */
        class Signaled(
            val credentials: IceCredentials,
        ) : RemotePeer
    }

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
     * Where a pair stands on the checklist (RFC 8445 §6.1.2.6).
     *
     * The in-flight check lives **inside** [InProgress] rather than in a field beside the state, because
     * as two independent fields they desynchronised and that desync shipped a bug: `clearTransaction`
     * dropped the transaction without touching the state, so a consent check that timed out left its pair
     * `InProgress` *with nothing in flight*, permanently. That parked pair then counted as pending in
     * [maybeComplete] (so the agent could never reach `Completed`) and made [onInboundCheck] take its
     * `InProgress` arm forever — which is what hid the consent-resurrection bug (#75) for as long as it
     * existed. Here, retiring a check cannot be written without also saying what the pair becomes.
     */
    private sealed interface CheckState {
        /** Waiting on its foundation — a same-foundation pair is checked first (the frozen algorithm). */
        data object Frozen : CheckState

        /** Unfrozen and eligible to be checked when the pacing timer (Ta) next fires. */
        data object Waiting : CheckState

        /** [check] is on the wire, awaiting a response or a retransmission. */
        class InProgress(
            val check: InFlightCheck,
        ) : CheckState

        /** The last completed check succeeded — the pair is valid and may be nominated. */
        data object Succeeded : CheckState

        /** The last completed check failed (timed out, or an unrecoverable error response). */
        data object Failed : CheckState
    }

    /**
     * Mutable checklist state for a pair. Kept separate from the immutable [CandidatePair] identity so the
     * identity stays a clean map key and a diffable fixture value.
     *
     * [nominatedByPeer] is the one genuine boolean here — the peer sent USE-CANDIDATE, a fact orthogonal
     * to where the pair sits on the checklist. A second `valid` flag used to sit alongside it and has been
     * deleted: it was written only in lockstep with [state] and read only from [failCheck] under
     * `allDone`, where every pair is by definition [CheckState.Succeeded] or [CheckState.Failed] — so it
     * could never disagree with the state at the one place it was consulted, while still having to be
     * kept in sync by hand.
     */
    private class PairEntry(
        val pair: CandidatePair,
    ) {
        var state: CheckState = CheckState.Waiting
        var nominatedByPeer: Boolean = false

        val transaction: StunTransaction? get() = (state as? CheckState.InProgress)?.check?.transaction
        val inFlightPurpose: CheckPurpose? get() = (state as? CheckState.InProgress)?.check?.purpose
    }

    /**
     * Release everything this agent still holds — every in-flight check's request buffer, in the current
     * generation and in a retained one.
     *
     * The agent is sans-io and owns no sockets, so this is not a lifecycle in the usual sense; it exists
     * because `StunTransaction` releases its request only when it *finishes*, and a session that closes
     * mid-check finishes nothing. `IceAgentDriver.close` calls it, which is the one place that knows the
     * session is over. Idempotent: `abandon()` is.
     */
    public fun close() {
        current.abandonInFlight()
        (retained as? RetainedGeneration.Retained)?.generation?.abandonInFlight()
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
        var remote: RemotePeer = RemotePeer.Unsignaled

        /**
         * The signaled credentials, or null when the peer has not been signaled yet. A *narrowing
         * accessor*, not stored state: [remote] is the field, and this is the idiomatic way to consume a
         * sealed type at the sites whose answer is "then do X, otherwise bail". The point of #84 was to
         * delete the two `!!` reads that rested on a reachability argument, not to ban `as?`.
         */
        val signaledCredentials: IceCredentials? get() = (remote as? RemotePeer.Signaled)?.credentials
        val localCandidates: MutableList<IceCandidate> = mutableListOf()
        val remoteCandidates: MutableList<IceCandidate> = mutableListOf()
        val checklist: MutableList<PairEntry> = mutableListOf()
        val byTransaction: HashMap<TransactionId, PairEntry> = HashMap()

        /**
         * Abandon every check still in flight, releasing the request buffer each one holds.
         *
         * A transaction releases its request in `goTerminal`, which a response or a timeout reaches. A
         * generation that is simply **discarded** — by a restart, a rollback, or the session closing —
         * delivers neither, so without this its in-flight requests are never freed.
         */
        fun abandonInFlight() {
            for (entry in checklist) (entry.state as? CheckState.InProgress)?.check?.transaction?.abandon()
            byTransaction.clear()
        }

        var state: IceConnectionState = IceConnectionState.New

        /** What this generation has nominated, and — for [Selection.Nominated] — its consent clock. */
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
        var establishmentDeadline: Instant? = null

        // Derived, not a stored latch: a nominating check is in flight iff some pair currently holds one.
        // Making it a projection of the checklist means it can never wedge stale (the bug a stored flag hit).
        val nominationInFlight: Boolean
            get() = checklist.any { it.inFlightPurpose == CheckPurpose.Nomination }
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

        /** [entry] is nominated and carrying data, and [consent] is the RFC 7675 clock keeping it. */
        class Nominated(
            val entry: PairEntry,
            val consent: Consent,
        ) : Selection

        /**
         * Consent on [entry] expired (RFC 7675 §4.1) — **terminal for the generation**. §5.1: *"After
         * consent is lost, the same ICE credentials MUST NOT be used on the affected 5-tuple again. That
         * means that a new session, or an ICE restart, is needed."* [entry] is kept rather than dropped so
         * the dead pair stays nameable in diagnostics; it is never re-selected.
         *
         * It carries **no [Consent]**, and that is the point: revocation does not *clear* the clock, it
         * leaves it unrepresentable. An outstanding check on a revoked pair cannot be forgotten about,
         * because there is nowhere to put one.
         */
        class Revoked(
            val entry: PairEntry,
        ) : Selection
    }

    /**
     * The RFC 7675 consent clock for a nominated pair — and it lives **inside** [Selection.Nominated]
     * rather than beside it on [Generation], because every field here is meaningless without a pair to
     * refresh consent *on*. Held as three loose fields it re-created in miniature exactly the soup
     * [Selection] exists to remove: a `nextCheckAt` armed with nothing selected, an outstanding-id ledger
     * surviving revocation, and a `lastResponseAt` that had to be nullable — forcing a null check on a
     * state that cannot occur, since nomination *is* a proven round trip.
     *
     * Now [lastResponseAt] is non-null by construction, revocation drops the clock with the case that
     * owned it, and a rollback builds a fresh one instead of resetting three fields and hoping the list
     * is complete.
     */
    private class Consent(
        /** When the peer last proved it is still there. Never null: [selectPair] starts it at nomination. */
        var lastResponseAt: Instant,
        /** When the next check goes out — paced independently of any still-outstanding one (§4.1). */
        var nextCheckAt: Instant,
        /** Transaction ids sent but not yet answered; insertion-ordered, bounded by the revocation window. */
        val outstanding: LinkedHashSet<TransactionId> = LinkedHashSet(),
    )

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

    /**
     * Which of the peer's generations a trickled candidate names (RFC 8838 §3.1) — the routing decision,
     * as four cases the compiler makes every call site answer.
     *
     * Written as a sealed set rather than "a nullable ufrag plus a couple of booleans" for the reason
     * [Selection] is: the flag encoding admits combinations that must not exist (untagged *and*
     * superseded; unapplied *and* current), and each real answer carries different data — [Untagged]
     * carries none, [SupersededGeneration] carries the ufrag to report, [UnappliedGeneration] carries the
     * ufrag to file it under. An `else` branch here would silently swallow a case added later, which is
     * exactly how "we'll handle that generation properly next time" becomes a lost candidate.
     */
    private sealed interface CandidateRoute {
        /** No generation named — apply to the current one (pre-RFC-8838-§3.1 behaviour, unchanged). */
        data object Untagged : CandidateRoute

        /** Names the generation whose credentials are applied right now — apply it. */
        data object AppliedGeneration : CandidateRoute

        /** Names a generation the peer has already left — discard it, and say so. */
        data class SupersededGeneration(
            val ufrag: Ufrag,
        ) : CandidateRoute

        /** Names a generation not applied (yet) — hold it, bounded, until it is. */
        data class UnappliedGeneration(
            val ufrag: Ufrag,
        ) : CandidateRoute
    }

    /** The peer's currently applied ICE generation, as signaled. Sealed for the same reason
     *  [RemotePeer] is: "never signaled" and "signaled X" drive different routing, and a null would be
     *  read as the wrong one of them at exactly one call site. */
    private sealed interface RemoteGeneration {
        /** The peer has never signaled credentials — no generation to be late for, or early for. */
        data object None : RemoteGeneration

        /** [ufrag] names the peer's generation whose candidates are checkable now. */
        data class Applied(
            val ufrag: Ufrag,
        ) : RemoteGeneration
    }

    /** A candidate parked until the generation it names is applied — the ufrag is its filing key. */
    private class HeldCandidate(
        val ufrag: Ufrag,
        val candidate: IceCandidate,
    )

    private companion object {
        const val ROLE_CONFLICT = 487

        // RFC 7675 §4.1: "each interval MUST be randomized from between 0.8 and 1.2 times the basic period".
        // Deliberately not `const`: a const in a private companion is still emitted as a public static
        // field on JVM, and this change alters no public API — `apiCheck` is what caught the difference.
        val MIN_CONSENT_JITTER = 0.8
        val MAX_CONSENT_JITTER = 1.2

        // A hard ceiling on outstanding consent ids, so a pathological config (a consent interval of zero,
        // or a revocation window orders of magnitude larger than it) cannot turn the set into a leak.
        val CONSENT_OUTSTANDING_CEILING = 64

        /**
         * The hold bound (RFC 8838 §3.1): how many candidates for not-yet-applied generations are parked
         * before the oldest is evicted. Sized for one full gather of a real endpoint — a browser trickles
         * on the order of ten candidates per generation over a couple of interfaces, so 32 holds a whole
         * generation's worth twice over with room to spare, while a peer that never signals the generation
         * it keeps tagging costs a fixed, small amount of memory instead of an unbounded one.
         */
        val MAX_HELD_CANDIDATES = 32

        /**
         * How many superseded remote ufrags stay nameable, so a late candidate for one is discarded
         * *deliberately* rather than mistaken for a future generation and held. Bounded for the same
         * reason: a peer that restarts in a loop must not turn this into a ledger. A ufrag that falls off
         * the end degrades to the safe answer — held, then evicted — never to "applied".
         */
        val MAX_RETIRED_REMOTE_GENERATIONS = 8
    }
}

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.association.StreamCount

/**
 * Which side of RFC 8832 §6's stream-id split an id belongs to. A named pair rather than
 * `isPeerParity: Boolean`, because the predicate had two live call sites reading it with **opposite**
 * polarity — one negated, one not — which is the precondition for exactly the confusion the sealed
 * `DeliveryOrder` next door was introduced to remove.
 */
internal enum class StreamParity {
    /** This endpoint opens channels on ids of this parity. */
    Ours,

    /** The peer opens channels on ids of this parity; claiming one collides with its next open. */
    Peers,
}

/**
 * How a data channel on a given stream id came to exist. Three states, not two independent Booleans.
 *
 * Registration used to be `registerChannel(incoming: Boolean)` beside a separate
 * `unconfirmedOutbound += id`, which is two Booleans admitting four combinations where the protocol has
 * three — and the third legal case, an out-of-band channel that is neither published to `accept` nor
 * force-ordered, is **not expressible** by any assignment of the two.
 */
internal sealed interface ChannelProvenance {
    /** We opened it with a DCEP OPEN (RFC 8832 §5.1): not published to `accept`, ordered until confirmed. */
    data object LocalInBand : ChannelProvenance

    /** The peer opened it with a DCEP OPEN: published to `accept`, and already confirmed by that OPEN. */
    data object PeerInBand : ChannelProvenance

    /**
     * The application named the id out of band (RFC 8832 §5's negotiated channels): no DCEP OPEN is sent
     * or expected, so it is neither published — the opener already holds it — nor force-ordered, because
     * §6's "send ordered until the channel is confirmed" rule exists to keep a DCEP OPEN first on the wire
     * and there is no OPEN here to keep first.
     */
    data object OutOfBand : ChannelProvenance
}

/**
 * What the ledger knows about one stream id. This is the type that replaces four containers — a reuse
 * queue, a half-close map, a parity predicate and a bare `Int` cursor — and the reason to merge them is
 * that every one of them was keyed on a stream id and none of them could see the others: an id could be
 * queued for reuse while still mid-close, or handed out by the cursor while reserved out of band, and
 * nothing in the shape of the code said otherwise.
 */
internal sealed interface StreamIdState {
    /** Backing a live channel, or reserved for one the application has asked for. */
    data class Claimed(
        val origin: ChannelProvenance,
    ) : StreamIdState

    /** One direction of the RFC 8831 §6.7 two-sided close has been reset; the other has not. */
    data class Closing(
        val origin: ChannelProvenance,
        val half: ResetHalf,
    ) : StreamIdState

    /**
     * Both directions are reset. The peer holds no Stream Sequence Number state for it, so it may back a
     * new channel — but only if it was ours to begin with, which is what [ChannelProvenance] decides.
     */
    data class Released(
        val origin: ChannelProvenance,
    ) : StreamIdState

    /**
     * Spent for the life of the association: the peer refused the reset, or cannot reset streams at all,
     * so its SSN state can never be cleared and a new channel here would start mid-sequence.
     */
    data object Burned : StreamIdState
}

/**
 * The next never-yet-handed-out id of this endpoint's parity, or the end of the space.
 *
 * A sealed pair rather than an `Int` that walks past the end, which is what it replaces and what made
 * running out of stream ids a crash: the cursor stepped to 65536, `StreamId` refused it with an
 * `IllegalArgumentException`, and that throw happened on the serialized drive loop.
 */
private sealed interface StreamCursor {
    data class At(
        val id: StreamId,
    ) : StreamCursor

    data object PastEnd : StreamCursor
}

/** The answer to "give this channel an id". */
internal sealed interface StreamIdGrant {
    /** Use [id]. It is claimed by the time this is returned. */
    data class Granted(
        val id: StreamId,
    ) : StreamIdGrant

    /**
     * [wanted] is the next id this endpoint would use, and it is at or above the negotiated [capacity].
     * [shortfall] is how many streams the association would have to gain for it to fit — the number an
     * RFC 6525 §4.5 Add Outgoing Streams request has to ask for, at minimum.
     */
    data class NeedsMoreStreams(
        val wanted: StreamId,
        val capacity: StreamCount,
        val shortfall: StreamCount,
    ) : StreamIdGrant

    /** Every id of this endpoint's parity is spent. Growing the association cannot help. */
    data object SpaceExhausted : StreamIdGrant
}

/**
 * The one place a data-channel stream id is chosen, retired and reused (RFC 8832 §6, RFC 8831 §6.7).
 *
 * It owns three things that used to be separate and had to agree by hand:
 *
 * - **the ledger** — what every id this association has touched is currently doing;
 * - **the parity** — which half of the space is ours to hand out;
 * - **the cursor** — the next id never handed out, which walks by two and **stops** at the end of the
 *   space instead of stepping off it.
 *
 * `allocate` returns a [StreamIdGrant] rather than a `StreamId`, so "there is no id for you" is a value
 * the caller must handle instead of an exception thrown from the drive loop.
 */
internal class StreamIdAllocator(
    private val role: SctpRole,
) {
    private val states = HashMap<StreamId, StreamIdState>()

    // Ids released in both directions and free to back a new channel, oldest first. Derived from `states`
    // — the invariant is asserted by [checkInvariants] — but kept alongside it because a reuse order is
    // the one thing a map cannot express, and reusing the least recently retired id is what keeps a
    // long-lived session away from the cursor.
    private val reusable = ArrayDeque<StreamId>()

    private var cursor: StreamCursor = StreamCursor.At(StreamId(if (role == SctpRole.Client) 0 else 1))

    /** Ids whose channel closed in both directions and that a future open will reuse — test-visible. */
    val recycled: List<StreamId> get() = reusable.toList()

    /** Ids with a live or half-closed channel: the concrete meaning of "reset all streams" on this side. */
    val liveIds: Set<StreamId>
        get() =
            states
                .filterValues { it is StreamIdState.Claimed || it is StreamIdState.Closing }
                .keys

    /**
     * Which side of RFC 8832 §6's split [id] falls on: a [SctpRole.Client] uses even ids, a
     * [SctpRole.Server] odd ones, and the peer holds the other half.
     */
    fun parityOf(id: StreamId): StreamParity {
        val even = id.value % 2 == 0
        val ours = if (role == SctpRole.Client) even else !even
        return if (ours) StreamParity.Ours else StreamParity.Peers
    }

    /** What [id] is currently doing, or null when this association has never touched it. */
    fun stateOf(id: StreamId): StreamIdState? = states[id]

    /**
     * Pick an id for a channel this endpoint is opening, inside a negotiated [capacity] of streams
     * (RFC 4960 §5.1.1). Prefers an id whose channel closed cleanly in both directions over burning a
     * fresh one, because RFC 8832 §6 gives this side only half of the space and the cursor never comes
     * back down.
     */
    fun allocate(capacity: StreamCount): StreamIdGrant {
        val recycledId = reusable.firstOrNull()
        if (recycledId != null && capacity.admits(recycledId)) {
            reusable.removeFirst()
            states[recycledId] = StreamIdState.Claimed(ChannelProvenance.LocalInBand)
            return StreamIdGrant.Granted(recycledId)
        }
        skipClaimed()
        return when (val at = cursor) {
            StreamCursor.PastEnd -> StreamIdGrant.SpaceExhausted
            is StreamCursor.At ->
                if (capacity.admits(at.id)) {
                    cursor = step(at.id)
                    states[at.id] = StreamIdState.Claimed(ChannelProvenance.LocalInBand)
                    StreamIdGrant.Granted(at.id)
                } else {
                    // `wanted` needs ids 0..wanted to exist, i.e. wanted + 1 streams. The subtraction is on
                    // Int and cannot underflow: this arm is reached only when capacity <= wanted.
                    StreamIdGrant.NeedsMoreStreams(
                        wanted = at.id,
                        capacity = capacity,
                        shortfall = StreamCount((at.id.value + 1 - capacity.value.toInt()).toUShort()),
                    )
                }
        }
    }

    /**
     * Claim [id] for a channel of [origin] that did not come from [allocate] — a peer's DCEP OPEN, or an
     * application naming the id out of band. Returns null when the claim succeeded, or the refusal that
     * forbids it.
     *
     * Collision refusals only. Whether the id is inside the negotiated capacity is deliberately **not**
     * asked here: an application may name an id before the handshake has settled any capacity at all, so
     * the range check belongs at dispatch, where a capacity exists.
     */
    fun claim(
        id: StreamId,
        origin: ChannelProvenance,
    ): DataChannelOpenRefusal? {
        when (val state = states[id]) {
            null -> Unit
            is StreamIdState.Claimed -> return DataChannelOpenRefusal.StreamIdInUse(id)
            is StreamIdState.Closing -> return DataChannelOpenRefusal.StreamIdClosing(id)
            StreamIdState.Burned -> return DataChannelOpenRefusal.StreamIdBurned(id)
            // Released in both directions: the peer holds no sequencing state for it, so it may be
            // re-claimed. Taking it out of the reuse queue is what stops `allocate` handing it out twice.
            is StreamIdState.Released -> reusable.remove(id)
        }
        states[id] = StreamIdState.Claimed(origin)
        skipClaimed()
        return null
    }

    /**
     * Record a channel the peer opened on [id] with a DCEP OPEN. Unlike [claim] this always succeeds, and
     * that asymmetry is deliberate: the peer's own cursor is the authority for the peer's half of the id
     * space (RFC 8832 §6), so a half-landed close or a burn *of ours* cannot outrank an OPEN it has
     * already sent. Whether the OPEN is admitted at all is decided one layer up, where the routing map and
     * the reservations are both visible.
     */
    fun adoptPeerOpen(id: StreamId) {
        states[id] = StreamIdState.Claimed(ChannelProvenance.PeerInBand)
        reusable.remove(id)
        skipClaimed()
    }

    /** Give [id] back without retiring it — the open that claimed it was refused after the claim landed. */
    fun relinquish(id: StreamId) {
        states.remove(id)
    }

    /**
     * Record that one direction of [id]'s close has been reset (RFC 8831 §6.7). When the second direction
     * lands the id is [StreamIdState.Released], and becomes reusable if it was ours to hand out in the
     * first place.
     *
     * An id the ledger has never seen is ignored. Only an id that was actually handed out can come back,
     * and pushing a stray one into the reuse queue would have the cursor hand out the same id twice.
     */
    fun noteResetHalf(
        id: StreamId,
        half: ResetHalf,
    ) {
        when (val state = states[id]) {
            null, is StreamIdState.Released, StreamIdState.Burned -> Unit
            is StreamIdState.Claimed -> states[id] = StreamIdState.Closing(state.origin, half)
            is StreamIdState.Closing ->
                if (state.half != half) {
                    states[id] = StreamIdState.Released(state.origin)
                    // Only ids of OUR parity that WE opened in band are ours to hand out again: a
                    // peer-opened stream is the peer's to reuse, and an out-of-band id belongs to the
                    // application that named it — recycling either collides with its next open.
                    if (state.origin == ChannelProvenance.LocalInBand && parityOf(id) == StreamParity.Ours) {
                        reusable.addLast(id)
                    }
                }
        }
    }

    /**
     * Spend [id] for the life of the association: the peer refused the reset, or never advertised RFC 6525
     * at all, so it still holds Stream Sequence Number state that we can never clear.
     */
    fun burn(id: StreamId) {
        if (states[id] == null) return
        states[id] = StreamIdState.Burned
        reusable.remove(id)
    }

    /** Drop every id — the association is gone and so is everything the peer knew about its streams. */
    fun clear() {
        states.clear()
        reusable.clear()
        cursor = StreamCursor.At(StreamId(if (role == SctpRole.Client) 0 else 1))
    }

    /**
     * The ledger invariants the type system cannot state, asserted from fixtures rather than in production
     * (plan residue R5). Two containers describe one fact — every queued-for-reuse id is exactly a
     * locally-opened id released in both directions — and a reuse queue that drifts from the ledger hands
     * the same id to two channels, which presents as a peer's messages arriving on the wrong one.
     */
    fun checkInvariants() {
        val released =
            states
                .filterValues { it is StreamIdState.Released && it.origin == ChannelProvenance.LocalInBand }
                .keys
        check(reusable.toSet() == released) { "reuse queue $reusable disagrees with the released-in-band ids $released" }
        check(reusable.size == reusable.toSet().size) { "an id is queued for reuse more than once: $reusable" }
        for (id in reusable) {
            check(parityOf(id) == StreamParity.Ours) { "stream id ${id.value} is the peer's to reuse, not ours" }
        }
        when (val at = cursor) {
            StreamCursor.PastEnd -> Unit
            is StreamCursor.At -> check(at.id !in states) { "the cursor points at stream id ${at.id.value}, which is already claimed" }
        }
    }

    // The cursor names the next id NEVER handed out, so it has to step over anything the ledger already
    // knows — an id reserved out of band before the cursor reached it, above all. Without this the cursor
    // would hand out an id the application is holding for a negotiated channel.
    private fun skipClaimed() {
        while (true) {
            val at = cursor as? StreamCursor.At ?: return
            if (at.id !in states) return
            cursor = step(at.id)
        }
    }

    // RFC 8832 §6: ids of one parity step by two. Past the last id any negotiated capacity can admit the
    // cursor STOPS, because the next value is not a stream id at all — constructing one is what used to
    // throw from the drive loop.
    private fun step(id: StreamId): StreamCursor {
        val next = id.value + 2
        return if (next > StreamCount.MaxUsableId.value) StreamCursor.PastEnd else StreamCursor.At(StreamId(next))
    }
}

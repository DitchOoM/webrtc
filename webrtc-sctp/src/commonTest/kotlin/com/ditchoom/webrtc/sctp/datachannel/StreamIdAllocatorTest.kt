package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.association.StreamCount
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The stream-id ledger's rules, asserted directly rather than through a live association.
 *
 * Each rule used to live in a different container — a reuse queue, a half-close map, a parity predicate,
 * a bare cursor — and none of them could see the others, so the invariants *between* them were held by
 * the order of a few lines in `SctpDataChannelStack` and by nothing else. `checkInvariants` is the
 * executable form of the one that matters (plan residue R5): the reuse queue is exactly the set of
 * locally-opened ids released in both directions. It is asserted after every mutation below, because a
 * queue that drifts from the ledger hands one id to two channels, and that presents as a peer's messages
 * arriving on the wrong one — nowhere near the code that caused it.
 */
class StreamIdAllocatorTest {
    private fun client() = StreamIdAllocator(SctpRole.Client)

    private fun StreamIdAllocator.allocateId(capacity: StreamCount = StreamCount.Max): StreamId =
        assertIs<StreamIdGrant.Granted>(allocate(capacity)).id

    private fun StreamIdAllocator.closeBothHalves(id: StreamId) {
        noteResetHalf(id, ResetHalf.Ours)
        noteResetHalf(id, ResetHalf.Peers)
    }

    @Test
    fun a_locally_opened_id_comes_back_only_after_both_halves_are_reset() {
        val allocator = client()
        val id = allocator.allocateId()

        allocator.noteResetHalf(id, ResetHalf.Ours)
        assertEquals(emptyList(), allocator.recycled, "one half is not a close (RFC 8831 §6.7)")
        assertIs<StreamIdState.Closing>(allocator.stateOf(id))
        allocator.checkInvariants()

        allocator.noteResetHalf(id, ResetHalf.Peers)
        assertEquals(listOf(id), allocator.recycled, "both halves reset, so the peer holds no SSN state for it")
        allocator.checkInvariants()
    }

    /**
     * Either order. The two resets are independent RFC 6525 exchanges and nothing sequences them, so a
     * ledger that only recognised one order would leak an id on every close that raced the other way.
     */
    @Test
    fun the_two_reset_halves_land_in_either_order() {
        for (first in listOf(ResetHalf.Ours, ResetHalf.Peers)) {
            val allocator = client()
            val id = allocator.allocateId()
            allocator.noteResetHalf(id, first)
            allocator.noteResetHalf(id, if (first == ResetHalf.Ours) ResetHalf.Peers else ResetHalf.Ours)
            assertEquals(listOf(id), allocator.recycled, "$first first")
            allocator.checkInvariants()
        }
    }

    /** The same half twice is the peer retransmitting, not the other direction arriving. */
    @Test
    fun the_same_half_twice_does_not_close_the_channel() {
        val allocator = client()
        val id = allocator.allocateId()
        allocator.noteResetHalf(id, ResetHalf.Peers)
        allocator.noteResetHalf(id, ResetHalf.Peers)
        assertEquals(emptyList(), allocator.recycled)
        allocator.checkInvariants()
    }

    @Test
    fun a_recycled_id_is_handed_out_before_a_fresh_one_and_only_once() {
        val allocator = client()
        val first = allocator.allocateId()
        val second = allocator.allocateId()
        assertEquals(listOf(StreamId(0), StreamId(2)), listOf(first, second))

        allocator.closeBothHalves(second)
        allocator.closeBothHalves(first)
        assertEquals(listOf(second, first), allocator.recycled, "retired in that order, so offered in that order")

        assertEquals(second, allocator.allocateId(), "the oldest retirement is reused first")
        assertEquals(first, allocator.allocateId())
        assertEquals(StreamId(4), allocator.allocateId(), "…and only then does the cursor burn a fresh id")
        allocator.checkInvariants()
    }

    /**
     * A peer-opened id is the peer's to reuse. Claiming one would collide with its very next open, and
     * nothing on the wire would say so — the peer's DCEP OPEN and ours would simply both be on stream 1.
     */
    @Test
    fun a_peer_opened_id_is_never_recycled_into_our_cursor() {
        val allocator = client()
        val peerId = StreamId(1)
        assertEquals(StreamParity.Peers, allocator.parityOf(peerId))
        assertNull(allocator.claim(peerId, ChannelProvenance.PeerInBand))

        allocator.closeBothHalves(peerId)
        assertEquals(emptyList(), allocator.recycled, "the peer will reuse its own id when it chooses")
        assertIs<StreamIdState.Released>(allocator.stateOf(peerId))
        allocator.checkInvariants()
    }

    /**
     * Nor is an id the application named out of band. It belongs to whoever chose it, on both peers, and
     * handing it back to the cursor would open an in-band channel on an id the application still owns.
     */
    @Test
    fun an_out_of_band_id_is_never_recycled_into_our_cursor() {
        val allocator = client()
        assertNull(allocator.claim(StreamId(0), ChannelProvenance.OutOfBand))
        allocator.closeBothHalves(StreamId(0))
        assertEquals(emptyList(), allocator.recycled)
        assertEquals(StreamId(2), allocator.allocateId(), "and the cursor stepped over it rather than through it")
        allocator.checkInvariants()
    }

    /**
     * A refused reset spends the id for the life of the association (RFC 6525 §5.1): the peer still holds
     * Stream Sequence Number state for it, so a new channel there would start mid-sequence and every
     * ordered message on it would be held forever waiting for SSNs that already went by.
     */
    @Test
    fun a_burned_id_is_never_reused_and_refuses_every_later_claim() {
        val allocator = client()
        val id = allocator.allocateId()
        allocator.closeBothHalves(id)
        assertEquals(listOf(id), allocator.recycled, "the fixture needs it recycled first, so burning has something to undo")

        allocator.burn(id)
        assertEquals(emptyList(), allocator.recycled, "burning takes it back out of circulation")
        assertEquals(DataChannelOpenRefusal.StreamIdBurned(id), allocator.claim(id, ChannelProvenance.OutOfBand))
        assertEquals(StreamId(2), allocator.allocateId(), "the cursor moves on rather than reoffering it")
        allocator.checkInvariants()
    }

    @Test
    fun a_claim_on_an_id_another_channel_holds_is_refused_by_what_it_is_doing() {
        val allocator = client()
        val live = allocator.allocateId()
        assertEquals(
            DataChannelOpenRefusal.StreamIdInUse(live),
            allocator.claim(live, ChannelProvenance.OutOfBand),
            "an id backing a live channel",
        )

        val closing = allocator.allocateId()
        allocator.noteResetHalf(closing, ResetHalf.Ours)
        assertEquals(
            DataChannelOpenRefusal.StreamIdClosing(closing),
            allocator.claim(closing, ChannelProvenance.OutOfBand),
            "an id whose close is half-landed still has SSN state on one side",
        )
        allocator.checkInvariants()
    }

    /** A released id may be re-claimed by name, and doing so takes it out of the reuse queue. */
    @Test
    fun claiming_a_released_id_by_name_removes_it_from_the_reuse_queue() {
        val allocator = client()
        val id = allocator.allocateId()
        allocator.closeBothHalves(id)
        assertNull(allocator.claim(id, ChannelProvenance.OutOfBand))
        assertEquals(emptyList(), allocator.recycled, "or `allocate` would hand out an id already claimed")
        allocator.checkInvariants()
    }

    /** A teardown drops every id: the peer that agreed to them is gone, so none of it means anything. */
    @Test
    fun clearing_returns_the_allocator_to_its_first_id() {
        val allocator = client()
        allocator.allocateId()
        allocator.allocateId()
        allocator.clear()
        assertEquals(StreamId(0), allocator.allocateId())
        assertTrue(allocator.recycled.isEmpty())
        allocator.checkInvariants()
    }

    /** A negotiated capacity bounds the cursor, and says how far short it fell (the RFC 6525 §4.5 ask). */
    @Test
    fun a_capacity_the_cursor_has_outrun_reports_the_shortfall() {
        val allocator = client()
        allocator.allocateId(StreamCount(3u))
        allocator.allocateId(StreamCount(3u))
        val grant = assertIs<StreamIdGrant.NeedsMoreStreams>(allocator.allocate(StreamCount(3u)))
        assertEquals(StreamId(4), grant.wanted, "ids 0 and 2 fit in 3 streams; 4 does not")
        assertEquals(StreamCount(3u), grant.capacity)
        assertEquals(StreamCount(2u), grant.shortfall, "id 4 needs 5 streams to exist, so 2 more than 3")
        allocator.checkInvariants()
    }
}

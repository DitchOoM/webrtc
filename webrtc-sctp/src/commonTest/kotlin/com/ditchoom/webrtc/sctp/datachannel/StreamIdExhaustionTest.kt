@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.association.SctpAssociationState
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.association.StreamCount
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

private val EPOCH = Instant.fromEpochSeconds(0)

// Ids of one parity below the 65535-stream ceiling any capacity can express. File-private rather than a
// companion constant, per the standing rule about `const val` in a private companion.
private const val HALF_THE_SPACE = 32768

/**
 * Running out of stream ids, at both ends of the space, and the fact that made it worth a fixture: it
 * used to be a **crash**.
 *
 * `dispatchOpen` picked its id with `StreamId(nextStreamId).also { nextStreamId += 2 }` and no bound. The
 * cursor starts at 0 or 1, steps by 2, and only ever comes back down through the reuse queue — so a
 * session that opened enough channels reached 65536, where `StreamId`'s own `require` throws. That throw
 * happened inside the serialized drive loop, which on Kotlin/Native takes the whole PROCESS down rather
 * than raising something a consumer can catch, and on every other target left the `open()` deferred
 * uncompleted and its caller suspended for good.
 *
 * So the assertion is not "the id is in range". It is that the allocator is **driven to the end of the
 * space** and answers with a value, and that the value reaches the caller of `open()` as a typed refusal.
 */
class StreamIdExhaustionTest {
    private fun TestScope.clock(): () -> Instant = { EPOCH + testScheduler.currentTime.milliseconds }

    /**
     * The id space itself, walked to the end. 32768 even ids exist below the 65535-stream ceiling
     * (`0..65534`) and 32767 odd ones (`1..65533`), and the allocation after the last is
     * [StreamIdGrant.SpaceExhausted] rather than an exception.
     *
     * The loop is the point: an `IllegalArgumentException` from `StreamId` anywhere inside it fails this
     * test, which is precisely what the old cursor did on its final step. Both parities run, because the
     * two ends of the space are different — the even cursor stops because the next value is not a stream
     * id, the odd one because the next value is an id no capacity can ever admit.
     */
    @Test
    fun the_cursor_stops_at_the_end_of_the_id_space_instead_of_stepping_off_it() {
        for (role in listOf(SctpRole.Client, SctpRole.Server)) {
            val allocator = StreamIdAllocator(role)
            val granted = ArrayList<StreamId>()
            var exhausted: StreamIdGrant? = null
            // One more attempt than the space can hold, so the last one is the refusal under test.
            repeat(HALF_THE_SPACE + 1) {
                when (val grant = allocator.allocate(StreamCount.Max)) {
                    is StreamIdGrant.Granted -> granted += grant.id
                    else -> if (exhausted == null) exhausted = grant
                }
            }

            val expected = if (role == SctpRole.Client) HALF_THE_SPACE else HALF_THE_SPACE - 1
            assertEquals(expected, granted.size, "$role owns $expected of the 65535 ids a capacity can admit")
            assertEquals(
                if (role == SctpRole.Client) StreamId(0) else StreamId(1),
                granted.first(),
                "$role starts on its own parity (RFC 8832 §6)",
            )
            assertEquals(
                if (role == SctpRole.Client) StreamId(0xFFFE) else StreamId(0xFFFD),
                granted.last(),
                "…and the last id it can use is the highest of that parity inside the space",
            )
            assertEquals(granted.size, granted.toSet().size, "no id was handed out twice")
            assertIs<StreamIdGrant.SpaceExhausted>(exhausted, "$role: the step past the end is an answer, not a throw")
            allocator.checkInvariants()
        }
    }

    /** Belt and braces on the premise: the value the old cursor would have constructed does not exist. */
    @Test
    fun the_id_the_old_cursor_stepped_to_is_not_a_stream_id_at_all() {
        assertFailsWith<IllegalArgumentException>("a u16 stream id cannot hold 65536") {
            StreamId(StreamCount.MaxUsableId.value + 2)
        }
    }

    /**
     * …and the refusal reaches the caller. Exhausting the whole 16-bit space through a live association
     * would mean 32768 DCEP exchanges, so this drives the *negotiated* ceiling instead — which is the
     * boundary a real session actually hits, and the same refusal path.
     *
     * The discriminating half is the second and third opens: a stack that refused every open would pass a
     * test that only asserted the failure.
     */
    @Test
    fun an_open_with_no_stream_id_left_fails_its_caller_with_a_typed_refusal() =
        runTest {
            val config = SctpConfig(outboundStreams = 4u, inboundStreams = 4u)
            val pair = MemoryTransportPair(backgroundScope)
            val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, config, Random(1))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, config, Random(2))
            client.start()
            server.start()

            // A negotiated count of 4 admits ids 0..3, of which the client owns 0 and 2.
            val first = client.open(DataChannelConfig(label = "one")) as DataChannelConnection
            val second = client.open(DataChannelConfig(label = "two")) as DataChannelConnection
            assertEquals(listOf(0L, 2L), listOf(first.id, second.id), "the client's parity inside a count of 4")

            val refused =
                assertFailsWith<DataChannelOpenRefusedException>("a third open has no id and must say so") {
                    client.open(DataChannelConfig(label = "three"))
                }
            val refusal = assertIs<DataChannelOpenRefusal.StreamIdOutsideNegotiatedRange>(refused.refusal)
            assertEquals(StreamId(4), refusal.id, "the id it would have used")
            assertEquals(StreamCount(4u), refusal.capacity, "…and the ceiling it sits above")

            // The association survived the refusal: it is not a teardown, and the channels already open on
            // it still work. Without this the test passes on a stack that simply died.
            assertEquals(SctpAssociationState.Established, client.state.value, "a refusal is not a teardown")
            client.streamIdLedger.checkInvariants()
        }
}

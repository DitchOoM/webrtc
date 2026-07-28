package com.ditchoom.webrtc.harness

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The ordering contract behind issue #95 — the deterministic sibling of the `foreign-restart-*` lanes.
 *
 * A trickled candidate carries no `ufrag` (RFC 8838 §3.1), so a peer attributes one to whatever generation
 * its current remote description names. Across a renegotiation there is a window in which a candidate has
 * arrived and the description that names its generation has not, and no publish ordering closes it — the
 * reader can always poll the description slot a moment before the write lands and the candidate slot a
 * moment after. That window cost `foreign-restart-firefox` an intermittent red: three candidates read one
 * poll iteration early went to the generation the restart had just superseded, the peer's new checklist was
 * empty, and it never sent a connectivity check.
 *
 * [TrickleBuffer] is the repair — what was read under the old description is handed back when the new one
 * arrives — and these pin the three properties the repair actually needs.
 */
class TrickleBufferTest {
    @Test
    fun what_was_read_under_the_previous_description_is_handed_back_in_order() {
        val buffer = TrickleBuffer()
        buffer.read(CandidateLine(HOST))
        buffer.read(CandidateLine(SRFLX))

        // Order is not cosmetic: ICE processes candidates in arrival order, and re-applying a re-gathered
        // generation's candidates out of order would pair them in a different priority sequence than the
        // peer signalled them in.
        assertEquals(listOf(HOST, SRFLX), buffer.drain().map { it.text })
    }

    @Test
    fun a_second_drain_owes_nothing() {
        val buffer = TrickleBuffer()
        buffer.read(CandidateLine(HOST))
        buffer.drain()

        // Every remote description drains, and most of them arrive with nothing pending. A buffer that kept
        // handing the same lines back would re-add a candidate on every later round — harmless (every stack
        // dedupes) but it would make the "re-applying N" diagnostic lie about when the window was hit.
        assertTrue(buffer.drain().isEmpty())
    }

    @Test
    fun a_description_with_nothing_read_under_it_owes_nothing() {
        assertTrue(TrickleBuffer().drain().isEmpty())
    }

    @Test
    fun candidates_read_after_a_drain_belong_to_the_generation_that_drain_named() {
        val buffer = TrickleBuffer()
        buffer.read(CandidateLine(HOST))
        buffer.drain()
        buffer.read(CandidateLine(SRFLX))

        // The whole point of clearing on drain: once the description has been applied, arriving candidates
        // ARE attributable, and only the ones read after it are owed to the round after that.
        assertEquals(listOf(SRFLX), buffer.drain().map { it.text })
    }

    private companion object {
        const val HOST = "candidate:host:10.0.0.1:-:udp 1 udp 2116288511 10.0.0.1 40000 typ host"
        const val SRFLX =
            "candidate:srflx:10.0.0.1:10.0.0.9:udp 1 udp 1680080895 172.30.0.31 40000 typ srflx raddr 10.0.0.1 rport 40000"
    }
}

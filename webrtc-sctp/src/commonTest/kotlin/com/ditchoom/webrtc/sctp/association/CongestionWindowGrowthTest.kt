@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime

/**
 * Slow start has to start — on **every** fragmentation point, not only on the ones that divide the
 * congestion window (directive #5 fixture).
 *
 * RFC 4960 §7.2.1 permits cwnd to grow only for a sender that is using it, and states the condition as
 * `outstanding >= cwnd`. That is a *proxy*, exact only while every chunk is the same size and that size
 * divides cwnd — because the send loop stops at the last whole chunk that fits and leaves `cwnd mod
 * fragmentSize` bytes of the window unused. This stack met both conditions by accident for its whole life:
 * every cwnd the controller can hold is a multiple of `SctpConfig.maxPayloadBytes` (the initial
 * `initialCwndMtus × mtu`, the `+mtu` slow-start step, the collapse to `mtu`), and the fragmentation point
 * *was* `maxPayloadBytes`. So the flight landed exactly on cwnd and the proxy held.
 *
 * A path profile ends that coincidence, and the arithmetic is in [the_ipv4_ceiling_divides_the_window_which_is_why_this_was_invisible]:
 * a relayed IPv6 path fragments at 1116 bytes, four of those are 4464, and the initial window is 4800.
 * `4464 >= 4800` is false, so a sender blocked on cwnd reports itself un-limited, cwnd never grows, and
 * **slow start never starts**. It cannot recover on its own either: the window is frozen at a value the
 * flight can never reach, so no acknowledgement can unfreeze it.
 *
 * ## Why an "it still arrives" assertion cannot see this
 *
 * Every packet is well-formed, every chunk is acknowledged, and the message *does* arrive — one round trip
 * per `cwnd / fragment` bytes, forever. Under a virtual clock a liveness fixture then passes at any speed,
 * which is exactly what happened: three large-message fixtures were added for this failure and all three
 * were green while the defect was live. So the assertion here is on the **window itself**, and the
 * end-to-end shape is pinned separately by a bounded instant ([a_long_transfer_is_paced_by_a_window_that_opens]),
 * which is the only form of "fast enough" this repo permits (directive #4).
 */
class CongestionWindowGrowthTest {
    private val stream = StreamId(0)

    private val config = SctpConfig()
    private val initialCwnd = config.initialCwndMtus * config.maxPayloadBytes

    // The answerer's pair on the failing L2 lane: local candidate Relayed, remote IPv6 — 40 (IPv6) + 8
    // (UDP) + 37 (DTLS 1.2 AES-GCM) + 48 (a TURN Send indication with an IPv6 XOR-PEER-ADDRESS).
    private val relayedIpv6 =
        SctpPathProfile.Assessed(PathIdentity(1u), PathAddressFamily.Ipv6, PathOverheadBytes(133))

    private fun established(impairment: Impairment = Impairment.PERFECT): SctpSim {
        val sim = SctpSim(config = config, configB = config)
        sim.associateA()
        sim.run()
        sim.impairment = impairment
        return sim
    }

    private fun SctpSim.send(bytes: Int) =
        post(toA = true, SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(bytes)))

    /**
     * The defect, stated as the arithmetic that produced it. Not a restatement of the fix: it is the reason
     * the four IPv6/dual L2 lanes failed while every IPv4 lane passed, and without it the fixtures below
     * look like they are about IPv6 rather than about divisibility.
     */
    @Test
    fun the_ipv4_ceiling_divides_the_window_which_is_why_this_was_invisible() {
        assertEquals(4800, initialCwnd, "four MTUs of the configured 1200-byte payload")
        assertEquals(0, initialCwnd % config.maxPayloadBytes, "an unassessed path fragments at exactly one MTU")

        val ipv6Ceiling = relayedIpv6.unprobedFragmentCeiling.value
        assertEquals(1116, ipv6Ceiling, "1280 (RFC 8200 §5) less 133 below SCTP less 28 of SCTP, 4-byte aligned")
        assertTrue(initialCwnd % ipv6Ceiling != 0, "and it does not divide the window — which is the whole defect")
        assertEquals(4464, (initialCwnd / ipv6Ceiling) * ipv6Ceiling, "so the flight tops out 336 bytes short of cwnd")
    }

    /**
     * The window opens on a fragmentation point that does not divide it.
     *
     * Pre-fix this is `4800` — the initial value, unchanged after a quarter-megabyte transfer, because the
     * flight never reached it.
     */
    @Test
    fun a_ceiling_that_does_not_divide_the_initial_window_still_opens_it() {
        val sim = established()
        sim.post(toA = true, SctpEvent.PathChanged(relayedIpv6))
        sim.send(256 * 1024)
        sim.run()

        assertEquals(1, sim.inboxB.size, "the message arrives either way — that is what makes this invisible")
        assertTrue(
            sim.a.congestionWindowBytes > initialCwnd,
            "cwnd is still ${sim.a.congestionWindowBytes} after 256 KiB: slow start never started, because the " +
                "flight tops out at 4464 of a 4800-byte window and `outstanding >= cwnd` reads that as idle",
        )
    }

    /** The control: the same transfer on the ceiling that *does* divide the window. Green before and after. */
    @Test
    fun the_dividing_ceiling_opens_it_too() {
        val sim = established()
        sim.send(256 * 1024)
        sim.run()
        assertTrue(sim.a.congestionWindowBytes > initialCwnd, "the IPv4 lane's ceiling was never affected")
    }

    /**
     * The half that turns a slow association into a stalled one: RFC 4960 §7.2.3 collapses cwnd to **one
     * MTU** on a T3 expiry, and one MTU is 1200 while the fragment is 1116 — so the flight is a single
     * chunk, 84 bytes short of the window, and the collapse is permanent. The receiver then has one packet
     * to acknowledge, which is below the every-second-packet rule, so each round costs a whole delayed-SACK
     * interval. That is the shape the L2 lane reported: 192 KiB echoed, and the 256 KiB probe behind it
     * never came back inside 25 s.
     */
    @Test
    fun a_window_collapsed_by_a_timeout_reopens_on_a_ceiling_that_does_not_divide_it() {
        val sim = established()
        sim.post(toA = true, SctpEvent.PathChanged(relayedIpv6))

        // Lose the whole first flight, so A's T3 expires with nothing acknowledged.
        var dropping = true
        sim.dropFilter = { toA -> !toA && dropping }
        sim.send(256 * 1024)
        sim.runUntil(sim.now + 100.milliseconds)
        assertTrue(sim.inboxB.isEmpty(), "the first flight really was lost")

        dropping = false
        sim.run()

        assertEquals(1, sim.inboxB.size, "the message is recovered")
        assertTrue(
            sim.a.congestionWindowBytes > config.maxPayloadBytes,
            "cwnd is still ${sim.a.congestionWindowBytes} — one MTU — so the association is pinned to one " +
                "1116-byte chunk per delayed-SACK interval for the rest of its life",
        )
    }

    /**
     * The end-to-end symptom, as **observable state at a bounded instant** — [SctpSim.runUntil]'s own idiom,
     * not a wall-clock budget: the clock is virtual and the path is modelled, so the number of round trips a
     * transfer takes is a deterministic property of the window, and 20 ms is one of them.
     *
     * A window that opens carries 256 KiB in a handful of round trips. A frozen one carries 4464 bytes per
     * round trip and needs 59, which is what puts a 256 KiB echo outside a 25-second interop window on a
     * path whose one-way delay is measured in milliseconds.
     */
    @Test
    fun a_long_transfer_is_paced_by_a_window_that_opens() {
        val sim = established(Impairment(delay = 10.milliseconds))
        sim.post(toA = true, SctpEvent.PathChanged(relayedIpv6))
        sim.send(256 * 1024)

        // Fifteen round trips. Exponential growth needs about seven; a frozen window needs fifty-nine.
        sim.runUntil(sim.now + (15 * 20).milliseconds)

        assertEquals(
            1,
            sim.inboxB.size,
            "256 KiB did not arrive within 15 round trips — the sender is pacing at one congestion window " +
                "per round trip and the window is not opening",
        )
    }
}

@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.ErrorDetectionMethodId
import com.ditchoom.webrtc.sctp.OutboundChecksum
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.SctpDecodeResult
import com.ditchoom.webrtc.sctp.SctpPacket
import com.ditchoom.webrtc.sctp.SctpParameter
import com.ditchoom.webrtc.sctp.TransportErrorDetection
import com.ditchoom.webrtc.sctp.ZeroChecksumAcceptance
import com.ditchoom.webrtc.sctp.ZeroChecksumParameterDecode
import com.ditchoom.webrtc.sctp.ZeroChecksumPolicy
import com.ditchoom.webrtc.sctp.acceptanceOver
import com.ditchoom.webrtc.sctp.asZeroChecksumAcceptable
import com.ditchoom.webrtc.sctp.emissionTo
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.time.ExperimentalTime

/**
 * RFC 9653 negotiation, and the one thing about it that is easy to get wrong: **it is per direction**.
 *
 * Sending the Zero Checksum Acceptable parameter says "I will accept a zero checksum *from you*" (§5.3).
 * It grants nothing in the other direction — permission to *send* one comes from the peer's own
 * advertisement (§5.2 restriction 1). A single "zero checksum negotiated" flag reads correctly in both
 * sentences and is wrong in one of them, and the failure it produces is the quietest in this module:
 * every packet we emit is discarded by a peer that never agreed, nothing is malformed anywhere, and the
 * association dies looking exactly like a path that went away.
 *
 * So the discriminating fixture here is [only_the_direction_the_peer_permitted_may_carry_a_zero_checksum]
 * — two peers that both advertise, of which only one may emit. A symmetric fixture passes just as green
 * on an implementation that conflates the two.
 */
class ZeroChecksumNegotiationTest {
    private val dtls = TransportErrorDetection.Provided(ErrorDetectionMethodId.ZeroChecksum)

    private fun policy(policy: ZeroChecksumPolicy) = SctpConfig(zeroChecksum = policy)

    /**
     * The error detection method a transmitted packet's INIT/INIT-ACK advertises, or null if none does —
     * read off the encoded bytes rather than off either association's state, so it answers "what went on
     * the wire" instead of "what we believe we decided".
     */
    private fun advertisedIn(outputs: List<SctpOutput>): ErrorDetectionMethodId? {
        for (transmit in outputs.filterIsInstance<SctpOutput.Transmit>()) {
            transmit.packet.position(0)
            val packet = assertIs<SctpDecodeResult.Success>(SctpPacket.decode(transmit.packet.slice())).packet
            try {
                val parameters =
                    packet.chunks.flatMap { chunk ->
                        when (chunk) {
                            is SctpChunk.Init -> chunk.parameters
                            is SctpChunk.InitAck -> chunk.parameters
                            else -> emptyList<SctpParameter>()
                        }
                    }
                for (parameter in parameters) {
                    when (val decoded = parameter.asZeroChecksumAcceptable()) {
                        ZeroChecksumParameterDecode.NotZeroChecksum -> Unit
                        is ZeroChecksumParameterDecode.Malformed -> Unit
                        is ZeroChecksumParameterDecode.Advertised -> return decoded.method
                    }
                }
            } finally {
                packet.release()
            }
        }
        return null
    }

    private fun established(sim: SctpSim): SctpSim {
        sim.associateA()
        sim.run()
        assertEquals(SctpAssociationState.Established, sim.a.state, "the fixture needs an established association")
        assertEquals(SctpAssociationState.Established, sim.b.state, "the fixture needs an established association")
        return sim
    }

    /**
     * The happy path, and the only one where a packet may carry a zero in either direction: both peers ask
     * for it, and both ride a transport that actually detects errors.
     */
    @Test
    fun two_willing_peers_over_a_guaranteeing_transport_settle_both_directions() {
        val sim =
            established(
                SctpSim(
                    config = policy(ZeroChecksumPolicy.AcceptAndEmit),
                    errorDetection = dtls,
                ),
            )

        assertEquals(ZeroChecksumAcceptance.Advertised(ErrorDetectionMethodId.ZeroChecksum), sim.a.zeroChecksumAcceptance)
        assertEquals(ZeroChecksumAcceptance.Advertised(ErrorDetectionMethodId.ZeroChecksum), sim.b.zeroChecksumAcceptance)
        assertEquals(OutboundChecksum.ZeroWherePermitted(ErrorDetectionMethodId.ZeroChecksum), sim.a.outboundChecksum)
        assertEquals(OutboundChecksum.ZeroWherePermitted(ErrorDetectionMethodId.ZeroChecksum), sim.b.outboundChecksum)
    }

    /**
     * The asymmetry, driven through one real handshake. Both peers advertise, so both are obliged to
     * accept a zero checksum; only A is willing to emit one. B's restraint is a policy decision it makes
     * about itself, and A's permission is a fact about B — two different questions with two different
     * answers on one association.
     *
     * A conflated implementation cannot produce this state at all: whichever direction it read, both
     * endpoints would agree.
     */
    @Test
    fun only_the_direction_the_peer_permitted_may_carry_a_zero_checksum() {
        val sim =
            established(
                SctpSim(
                    config = policy(ZeroChecksumPolicy.AcceptAndEmit),
                    configB = policy(ZeroChecksumPolicy.AcceptOnly),
                    errorDetection = dtls,
                ),
            )

        assertEquals(
            OutboundChecksum.ZeroWherePermitted(ErrorDetectionMethodId.ZeroChecksum),
            sim.a.outboundChecksum,
            "B advertised, so A may emit",
        )
        assertEquals(
            OutboundChecksum.Crc32c,
            sim.b.outboundChecksum,
            "B asked to accept only; its own emission is unaffected by what A advertised",
        )
        assertEquals(
            ZeroChecksumAcceptance.Advertised(ErrorDetectionMethodId.ZeroChecksum),
            sim.b.zeroChecksumAcceptance,
            "AcceptOnly still advertises — that is the whole of what it does",
        )
    }

    /**
     * One peer advertises and the other does not, which is the case a Boolean gets backwards. A wants zero
     * checksums and says so; B never answers, so A **must not** emit one (§5.2 restriction 1) even though
     * A is perfectly willing and its own transport would justify it.
     */
    @Test
    fun a_peer_that_never_advertised_still_receives_a_real_crc32c() {
        val sim =
            established(
                SctpSim(
                    config = policy(ZeroChecksumPolicy.AcceptAndEmit),
                    configB = policy(ZeroChecksumPolicy.Disabled),
                    errorDetection = dtls,
                ),
            )

        assertEquals(OutboundChecksum.Crc32c, sim.a.outboundChecksum, "B granted nothing, so A may emit nothing")
        assertEquals(OutboundChecksum.Crc32c, sim.b.outboundChecksum)
        assertEquals(
            ZeroChecksumAcceptance.RequireCrc32c,
            sim.b.zeroChecksumAcceptance,
            "a peer that advertised nothing must keep dropping packets whose checksum disagrees",
        )
        assertEquals(
            ZeroChecksumAcceptance.Advertised(ErrorDetectionMethodId.ZeroChecksum),
            sim.a.zeroChecksumAcceptance,
            "A's own acceptance is unaffected by B's silence — it advertised, so §5.3 binds it",
        )
    }

    /** The default: nothing advertised, nothing emitted, and no parameter on the wire at all. */
    @Test
    fun the_default_configuration_changes_nothing() {
        val sim = SctpSim()
        val initOutputs = sim.associateA()
        sim.run()

        assertNull(advertisedIn(initOutputs), "the INIT must carry no RFC 9653 parameter by default")
        assertEquals(ZeroChecksumAcceptance.RequireCrc32c, sim.a.zeroChecksumAcceptance)
        assertEquals(ZeroChecksumAcceptance.RequireCrc32c, sim.b.zeroChecksumAcceptance)
        assertEquals(OutboundChecksum.Crc32c, sim.a.outboundChecksum)
        assertEquals(OutboundChecksum.Crc32c, sim.b.outboundChecksum)
    }

    /**
     * The safety property, at the altitude where it would actually be violated. Both peers ask for zero
     * checksums over a transport that guarantees nothing — there is no alternate method to name, so
     * nothing is advertised and nothing is emitted. It is a shape rather than a check: `acceptanceOver`
     * has no arm that can produce an advertisement from a `CrcOnly` transport.
     */
    @Test
    fun a_willing_policy_over_a_transport_that_guarantees_nothing_advertises_nothing() {
        val sim = SctpSim(config = policy(ZeroChecksumPolicy.AcceptAndEmit))
        val initOutputs = sim.associateA()
        sim.run()

        assertNull(advertisedIn(initOutputs), "there is no method to name, so no parameter may go out")
        assertEquals(ZeroChecksumAcceptance.RequireCrc32c, sim.a.zeroChecksumAcceptance)
        assertEquals(OutboundChecksum.Crc32c, sim.a.outboundChecksum)
        assertEquals(OutboundChecksum.Crc32c, sim.b.outboundChecksum)
    }

    /**
     * A peer advertising a method from some future registry entry. It is declined by comparison — neither
     * endpoint can vouch for a method it does not implement — and that is the *only* consequence: no parse
     * failure, no refused parameter, and an association that establishes exactly as it always did.
     *
     * Asserting the INIT actually carried 0x0000BEEF is what stops this from passing for the wrong reason.
     * A reader that folded every unrecognized identifier into "nothing advertised" would produce the same
     * two `Crc32c` verdicts below while having thrown the peer's advertisement away — and would then fail
     * the day IANA assigns entry 2.
     */
    @Test
    fun an_unknown_method_identifier_is_declined_without_a_parse_failure() {
        val future = ErrorDetectionMethodId(0x0000BEEFu)
        val sim =
            SctpSim(
                config = policy(ZeroChecksumPolicy.AcceptAndEmit),
                errorDetection = TransportErrorDetection.Provided(future),
                errorDetectionB = dtls,
            )
        val initOutputs = sim.associateA()
        sim.run()

        assertEquals(SctpAssociationState.Established, sim.a.state, "an unknown method must not cost the association")
        assertEquals(SctpAssociationState.Established, sim.b.state)
        assertEquals(future, advertisedIn(initOutputs), "A's INIT must name the identifier it was given")
        assertEquals(
            OutboundChecksum.Crc32c,
            sim.b.outboundChecksum,
            "B was offered a method it does not implement and must decline it",
        )
        assertEquals(OutboundChecksum.Crc32c, sim.a.outboundChecksum)
    }

    /**
     * Permission belongs to the peer that granted it. A teardown that let it survive would hand the next
     * association a licence its peer never issued — and RFC 9653 offers no signal that would ever surface
     * it, because a zero checksum from an unpermitted sender is simply a packet the receiver discards.
     */
    @Test
    fun tearing_the_association_down_gives_back_the_permission_to_emit() {
        val sim =
            established(
                SctpSim(
                    config = policy(ZeroChecksumPolicy.AcceptAndEmit),
                    errorDetection = dtls,
                ),
            )
        assertEquals(OutboundChecksum.ZeroWherePermitted(ErrorDetectionMethodId.ZeroChecksum), sim.a.outboundChecksum)

        sim.a.close()

        assertEquals(OutboundChecksum.Crc32c, sim.a.outboundChecksum, "the permission died with the association")
        assertEquals(
            ZeroChecksumAcceptance.Advertised(ErrorDetectionMethodId.ZeroChecksum),
            sim.a.zeroChecksumAcceptance,
            "our own acceptance is a property of our configuration, not of the association that closed",
        )
    }

    /**
     * The resolution table itself, asserted directly rather than only through a handshake. Nine of these
     * twelve rows are refusals, and each one is a place where a mistake would be invisible on a link that
     * happens to be reliable — which is every link a fixture runs over.
     */
    @Test
    fun the_resolution_table_refuses_everything_that_is_not_fully_negotiated() {
        val crcOnly = TransportErrorDetection.CrcOnly
        for (policy in listOf(ZeroChecksumPolicy.Disabled, ZeroChecksumPolicy.AcceptOnly, ZeroChecksumPolicy.AcceptAndEmit)) {
            assertEquals(
                ZeroChecksumAcceptance.RequireCrc32c,
                policy.acceptanceOver(crcOnly),
                "$policy over a transport guaranteeing nothing has no method to advertise",
            )
            assertEquals(
                OutboundChecksum.Crc32c,
                policy.emissionTo(ErrorDetectionMethodId.ZeroChecksum, crcOnly),
                "$policy over a transport guaranteeing nothing may never emit a zero",
            )
            assertEquals(
                OutboundChecksum.Crc32c,
                policy.emissionTo(ErrorDetectionMethodId.Reserved, dtls),
                "$policy must decline a peer that advertised nothing (RFC 9653 §8 reserves 0)",
            )
            assertEquals(
                OutboundChecksum.Crc32c,
                policy.emissionTo(ErrorDetectionMethodId(2u), dtls),
                "$policy must decline a method this endpoint does not provide",
            )
        }
        assertEquals(ZeroChecksumAcceptance.RequireCrc32c, ZeroChecksumPolicy.Disabled.acceptanceOver(dtls))
        assertEquals(OutboundChecksum.Crc32c, ZeroChecksumPolicy.Disabled.emissionTo(ErrorDetectionMethodId.ZeroChecksum, dtls))
        assertEquals(OutboundChecksum.Crc32c, ZeroChecksumPolicy.AcceptOnly.emissionTo(ErrorDetectionMethodId.ZeroChecksum, dtls))
    }
}

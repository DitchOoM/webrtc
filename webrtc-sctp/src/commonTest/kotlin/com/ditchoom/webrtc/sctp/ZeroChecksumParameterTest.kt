package com.ditchoom.webrtc.sctp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The RFC 9653 §4 Zero Checksum Acceptable chunk parameter, both directions of its codec.
 *
 * The wire shape is pinned by hand rather than by round-tripping our own writer through our own reader:
 * two halves of one mistake agree perfectly, and this parameter's whole value is that a *foreign* stack
 * reads it. Type 0x8001, Length 8, then the 32-bit EDMID, big-endian — that is the entire specification,
 * and the byte assertion is the only thing that holds us to it.
 *
 * The malformed and unknown-identifier cases are the ones with teeth. Both describe a conforming or
 * near-conforming peer, and the response to each is to keep processing: the parameter's two high bits are
 * `10`, which RFC 9260 §3.2.1 defines as skip-this-and-continue, so neither may cost the peer its
 * association.
 */
class ZeroChecksumParameterTest {
    private fun initCarrying(vararg parameters: SctpParameter): SctpChunk.Init =
        SctpChunk.Init(
            initiateTag = VerificationTag(0xABCDEF01u),
            advertisedReceiverWindow = 65536u,
            outboundStreams = 16u,
            inboundStreams = 16u,
            initialTsn = Tsn(1u),
            parameters = parameters.toList(),
        )

    /** Encode a chunk into a real packet and decode it back, so the parameter is read off actual wire bytes. */
    private fun throughTheWire(chunk: SctpChunk.Init): SctpChunk.Init {
        val encoded = SctpPacketBuilder(5000u, 5000u, VerificationTag(0u)).add(chunk).encode()
        val decoded = assertIs<SctpDecodeResult.Success>(SctpPacket.decode(encoded)).packet
        return assertIs<SctpChunk.Init>(decoded.chunks.single())
    }

    /**
     * The wire layout, byte for byte. `00 01` is the EDMID for SCTP over DTLS — RFC 9653 §8's registry
     * calls entry 1 "SCTP over DTLS", which is the same value this library names
     * [ErrorDetectionMethodId.ZeroChecksum].
     */
    @Test
    fun the_parameter_is_type_0x8001_length_8_and_a_big_endian_edmid() {
        val parameter = SctpParameter.zeroChecksumAcceptable(ErrorDetectionMethodId.ZeroChecksum)
        val encoded = SctpPacketBuilder(5000u, 5000u, VerificationTag(0u)).add(initCarrying(parameter)).encode()

        // Common header (12) + chunk header (4) + INIT fixed fields (16) = 32 bytes before the parameter.
        assertEquals(
            listOf(0x80, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01),
            encoded.toIntList().drop(32),
            "RFC 9653 §4: type 0x8001, Length 8, then the 32-bit EDMID in network byte order",
        )
    }

    @Test
    fun a_well_formed_parameter_round_trips_through_a_real_init() {
        val decoded = throughTheWire(initCarrying(SctpParameter.zeroChecksumAcceptable(ErrorDetectionMethodId.ZeroChecksum)))

        val advertised = assertIs<ZeroChecksumParameterDecode.Advertised>(decoded.parameters.single().asZeroChecksumAcceptable())
        assertEquals(ErrorDetectionMethodId.ZeroChecksum, advertised.method)
    }

    /**
     * The registry is IANA's and this library is not the last word on it. A peer naming a method minted
     * after this code was written must decode cleanly — declining it is a comparison made later, on data,
     * not a refusal to read. Modelling the identifier as an enum is exactly what would turn this
     * conforming advertisement into a decode error.
     */
    @Test
    fun an_unknown_error_detection_method_decodes_rather_than_failing() {
        val future = ErrorDetectionMethodId(0x0000BEEFu)
        val decoded = throughTheWire(initCarrying(SctpParameter.zeroChecksumAcceptable(future)))

        val advertised = assertIs<ZeroChecksumParameterDecode.Advertised>(decoded.parameters.single().asZeroChecksumAcceptable())
        assertEquals(future, advertised.method, "an identifier we do not implement is still an identifier")
    }

    /**
     * A parameter of the right type and the wrong length. RFC 9653 §4 says the Length field "MUST be 8",
     * and this reports the length that was actually there — which is the only diagnostic available for a
     * peer whose encoder is wrong, since nothing else about this exchange will ever look unusual.
     */
    @Test
    fun a_wrong_length_parameter_is_malformed_rather_than_a_throw() {
        val truncated = SctpParameter.ofValue(ParameterType.ZeroChecksumAcceptable, bufferOf(0x00, 0x01))
        val decoded = throughTheWire(initCarrying(truncated))

        val malformed = assertIs<ZeroChecksumParameterDecode.Malformed>(decoded.parameters.single().asZeroChecksumAcceptable())
        assertEquals(6, malformed.declaredLength, "the wire Length field, which RFC 9653 §4 requires be 8")
    }

    /**
     * The skip-and-continue obligation, asserted where it actually matters: a malformed 0x8001 riding
     * beside the parameters this stack depends on must not take them down with it. A decoder that
     * rejected the chunk would turn a peer's encoding bug into a handshake that never completes — and the
     * two high bits exist precisely so that cannot happen.
     */
    @Test
    fun a_malformed_parameter_does_not_disturb_the_parameters_beside_it() {
        val decoded =
            throughTheWire(
                initCarrying(
                    SctpParameter.forwardTsnSupported(),
                    SctpParameter.ofValue(ParameterType.ZeroChecksumAcceptable, bufferOf(0x00)),
                    SctpParameter.supportedExtensions(listOf(SctpChunkType.ForwardTsn, SctpChunkType.ReConfig)),
                ),
            )

        assertEquals(3, decoded.parameters.size, "every parameter must survive the walk")
        assertTrue(decoded.supportsForwardTsn(), "RFC 3758 was advertised before the malformed parameter")
        assertTrue(
            decoded.parameters.any { it.asSupportedExtensions()?.contains(SctpChunkType.ReConfig) == true },
            "RFC 6525 was advertised after the malformed parameter",
        )
        assertIs<ZeroChecksumParameterDecode.Malformed>(decoded.parameters[1].asZeroChecksumAcceptable())
    }

    /** Every other parameter type reads as "not this one" — a distinct answer from "this one, broken". */
    @Test
    fun another_parameter_type_is_not_a_malformed_zero_checksum_parameter() {
        assertEquals(
            ZeroChecksumParameterDecode.NotZeroChecksum,
            SctpParameter.forwardTsnSupported().asZeroChecksumAcceptable(),
        )
        assertEquals(
            ZeroChecksumParameterDecode.NotZeroChecksum,
            SctpParameter.supportedExtensions(listOf(SctpChunkType.ReConfig)).asZeroChecksumAcceptable(),
        )
    }
}

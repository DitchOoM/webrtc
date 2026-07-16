package com.ditchoom.webrtc

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.ice.IceDataTransport
import com.ditchoom.webrtc.sctp.datachannel.SctpDatagramTransport

/**
 * Which side of the DTLS handshake this endpoint plays (RFC 8842 / the SDP `a=setup` attribute): the
 * **client** sends the DTLS ClientHello (`a=setup:active`) and becomes the SCTP client (even DCEP stream
 * ids); the **server** is passive (`a=setup:passive`) and the SCTP server. A two-value enum, not a
 * boolean, so call sites read themselves (DESIGN §3).
 */
public enum class DtlsRole {
    Client,
    Server,
}

/**
 * Wraps the raw ICE app-data seam ([IceDataTransport], the demuxed non-STUN half of the selected pair)
 * into the secured [SctpDatagramTransport] the data-channel stack rides — **the one boundary where DTLS
 * lives** (RFC §6 step 4). This is the injected seam so that:
 *
 *  - **now (W4 parked):** [PlaintextDtls] passes bytes through unchanged, exactly the plaintext stand-in
 *    W5 proved the SCTP stack over — the full ICE+**DTLS**+SCTP end-to-end fixture is the exit gate once
 *    the real backend lands (HANDOFF: "build against the plaintext DTLS-shaped seam now");
 *  - **W4:** a BoringSSL-backed factory replaces [PlaintextDtls] here with no change above or below it —
 *    the SCTP association and the ICE agent both keep their exact interfaces (the swap, not a rewrite).
 */
public fun interface DtlsTransportFactory {
    /**
     * Perform the DTLS handshake as [role] over [iceData] and return the secured record layer as an
     * [SctpDatagramTransport]. Throws [WebRtcException] with a [PeerConnectionFailureReason.Dtls] cause if
     * the handshake fails.
     */
    public suspend fun secure(
        iceData: IceDataTransport,
        role: DtlsRole,
    ): SctpDatagramTransport
}

/**
 * The **plaintext** DTLS stand-in used while W4 is parked: it adapts [IceDataTransport] straight onto
 * [SctpDatagramTransport] with no handshake and no encryption — the identical seam W5 tested the SCTP
 * association over. It exists so the whole session composes and the round-trip fixture runs today; it is
 * **not** wire-secure and must be swapped for the BoringSSL factory before any real-network use (W4/W7).
 */
public object PlaintextDtls : DtlsTransportFactory {
    override suspend fun secure(
        iceData: IceDataTransport,
        role: DtlsRole,
    ): SctpDatagramTransport =
        object : SctpDatagramTransport {
            override suspend fun send(packet: ReadBuffer) = iceData.send(packet)

            override suspend fun receive(): ReadBuffer? = iceData.receive()

            override fun close() = iceData.close()
        }
}

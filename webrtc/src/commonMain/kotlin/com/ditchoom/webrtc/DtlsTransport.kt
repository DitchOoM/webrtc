package com.ditchoom.webrtc

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.ice.IceDataTransport
import com.ditchoom.webrtc.sctp.datachannel.SctpDatagramTransport
import com.ditchoom.webrtc.sdp.Fingerprint

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
 * lives** (RFC §6 step 4). [PureKotlinDtls] is the real implementation (W4/W4b — pure-Kotlin engine on
 * every non-browser target); [PlaintextDtls] is the insecure stand-in kept for fixtures and for the
 * W5 SCTP tests that exercise the association without a handshake.
 *
 * The factory owns the **local certificate identity**, not just the handshake: [localFingerprint] is the
 * `a=fingerprint` [NativePeerConnection] advertises in its offer/answer. That is deliberate — it makes
 * "advertise one fingerprint, present another" unrepresentable (DESIGN §4), which matters because the
 * advertised digest is the *only* thing binding the signaling channel to the media/data path (RFC 8827).
 * It also fixes an ordering constraint: the fingerprint must exist at `createOffer` time, long before
 * `a=setup` resolves the role at [secure].
 */
public interface DtlsTransportFactory {
    /**
     * The `a=fingerprint` (RFC 8122) of the certificate this factory presents. Stable for the lifetime
     * of the factory — one factory is one endpoint identity, so one [NativePeerConnection].
     */
    public val localFingerprint: Fingerprint

    /**
     * Perform the DTLS handshake as [role] over [iceData] and return the secured record layer as an
     * [SctpDatagramTransport], verifying the peer's certificate against [peerFingerprint] — the digest
     * the peer advertised in its SDP. Throws [WebRtcException] with a [PeerConnectionFailureReason.Dtls]
     * cause if the handshake fails or the peer presents a certificate that does not match.
     */
    public suspend fun secure(
        iceData: IceDataTransport,
        role: DtlsRole,
        peerFingerprint: Fingerprint,
    ): SctpDatagramTransport
}

/**
 * The **plaintext** DTLS stand-in: it adapts [IceDataTransport] straight onto [SctpDatagramTransport]
 * with no handshake and no encryption — the seam W5 tested the SCTP association over, and a deliberate
 * stand-in for tests and fixtures that want the data path without a handshake (real DTLS is now
 * [PureKotlinDtls] on every non-browser target). It presents no certificate, so [localFingerprint] is
 * the all-zero placeholder and
 * [peerFingerprint] is **not verified** — nothing is authenticated because nothing is encrypted.
 *
 * It is **not** wire-secure and must never be used against a real peer: prefer [PureKotlinDtls]. There is
 * deliberately no default factory, so every insecure call site is greppable.
 */
public object PlaintextDtls : DtlsTransportFactory {
    /** A syntactically valid SHA-256 placeholder — this stand-in has no certificate to digest. */
    override val localFingerprint: Fingerprint = Fingerprint("sha-256", List(32) { "00" }.joinToString(":"))

    override suspend fun secure(
        iceData: IceDataTransport,
        role: DtlsRole,
        peerFingerprint: Fingerprint,
    ): SctpDatagramTransport =
        object : SctpDatagramTransport {
            override suspend fun send(packet: ReadBuffer) = iceData.send(packet)

            override suspend fun receive(): ReadBuffer? = iceData.receive()

            override fun close() = iceData.close()
        }
}

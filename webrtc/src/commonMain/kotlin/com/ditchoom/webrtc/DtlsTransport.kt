package com.ditchoom.webrtc

import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.ice.IceDataReadResult
import com.ditchoom.webrtc.ice.IceDataTransport
import com.ditchoom.webrtc.sctp.datachannel.SctpDatagramTransport
import com.ditchoom.webrtc.sdp.Fingerprint

/**
 * Release a received buffer whose last reader has finished with it — this module's copy of the rule
 * `webrtc-ice`'s `IceProtocol.releaseReceived` states and `webrtc-sctp` restates at its own seam.
 *
 * There are three of these, one per module, and the duplication is deliberate: each is `internal` to a
 * leaf that depends only downward (ARCHITECTURE §3), so sharing one would mean an upward dependency or a
 * new published artifact for a two-line function. They are expected to change together.
 *
 * The rule: a received payload has exactly one owner at a time. The loop that received it either
 * **consumes** it (reads what it needs, releases before the next iteration) or **transfers** it (across a
 * channel or deferred, after which the receiver owes the release). A decoded view is neither — a borrow is
 * never released, it merely must not outlive the owner.
 *
 * [PureKotlinDtls] owns two chains of this: records arriving from the ICE seam, and the decrypted
 * application data it hands to SCTP.
 */
internal fun ReadBuffer.releaseReceived() {
    if (this is PlatformBuffer) freeNativeMemory()
}

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
 * lives** (ARCHITECTURE §6 step 4). [PureKotlinDtls] is the real implementation (a pure-Kotlin engine on
 * every non-browser target); [PlaintextDtls] is the insecure stand-in kept for fixtures and for the
 * SCTP tests that exercise the association without a handshake.
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
 * with no handshake and no encryption — the seam the SCTP association was first tested over, and a deliberate
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

            // SctpDatagramTransport (webrtc-sctp) still models "closed" as a null; this is the adapter
            // boundary where the ICE seam's sealed result meets it.
            override suspend fun receive(): ReadBuffer? =
                when (val read = iceData.receive()) {
                    is IceDataReadResult.Received -> read.packet
                    IceDataReadResult.Closed -> null
                }

            override fun close() = iceData.close()
        }
}

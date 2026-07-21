package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.crypto.KeyAgreementBlockingOps
import com.ditchoom.buffer.crypto.KeyAgreementPrivateKey
import com.ditchoom.buffer.crypto.KeyAgreementPublicKey
import com.ditchoom.webrtc.dtls.DtlsException
import com.ditchoom.webrtc.dtls.DtlsFailureReason

// JS: browsers delegate to RTCPeerConnection, so the pure-Kotlin engine is never driven here, and
// WebCrypto key agreement is suspend-only (no blocking bridge). Fail fast with a typed reason if the
// engine is somehow driven on this target.
internal actual fun rawEcdhPremaster(
    ops: KeyAgreementBlockingOps,
    privateKey: KeyAgreementPrivateKey,
    peerPublicKey: KeyAgreementPublicKey,
): PlatformBuffer =
    throw DtlsException(
        DtlsFailureReason.BackendUnavailable,
        "pure-Kotlin DTLS engine is not driven on JS — browsers delegate to RTCPeerConnection",
    )

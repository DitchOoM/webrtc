package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.crypto.KeyAgreementBlockingOps
import com.ditchoom.buffer.crypto.KeyAgreementPrivateKey
import com.ditchoom.buffer.crypto.KeyAgreementPublicKey
import com.ditchoom.webrtc.dtls.DtlsException
import com.ditchoom.webrtc.dtls.DtlsFailureReason

// WASM: same as JS — browsers delegate; WebCrypto is suspend-only. Typed fail-fast if ever driven.
internal actual fun rawEcdhPremaster(
    ops: KeyAgreementBlockingOps,
    privateKey: KeyAgreementPrivateKey,
    peerPublicKey: KeyAgreementPublicKey,
): PlatformBuffer =
    throw DtlsException(
        DtlsFailureReason.BackendUnavailable,
        "pure-Kotlin DTLS engine is not driven on WASM — browsers delegate to RTCPeerConnection",
    )

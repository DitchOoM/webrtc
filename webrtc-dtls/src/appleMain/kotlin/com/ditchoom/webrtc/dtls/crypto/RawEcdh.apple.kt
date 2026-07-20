package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.crypto.KeyAgreementBlockingOps
import com.ditchoom.buffer.crypto.KeyAgreementPrivateKey
import com.ditchoom.buffer.crypto.KeyAgreementPublicKey
import kotlinx.coroutines.runBlocking

// Apple: buffer-crypto's key agreement is CryptoKit/CommonCrypto, synchronous underneath — same
// runBlocking bridge. This lights up DTLS on Apple in pure Kotlin (no BoringSSL, no boringssl-kmp).
internal actual fun rawEcdhPremaster(
    ops: KeyAgreementBlockingOps,
    privateKey: KeyAgreementPrivateKey,
    peerPublicKey: KeyAgreementPublicKey,
): PlatformBuffer = runBlocking { ops.deriveTlsPremasterSecret(privateKey, peerPublicKey) }

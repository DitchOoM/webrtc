package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.crypto.KeyAgreementBlockingOps
import com.ditchoom.buffer.crypto.KeyAgreementPrivateKey
import com.ditchoom.buffer.crypto.KeyAgreementPublicKey
import kotlinx.coroutines.runBlocking

// Kotlin/Native Linux: buffer-crypto's key agreement is BoringSSL libcrypto and fulfils
// deriveTlsPremasterSecret synchronously; runBlocking drives the coroutine to completion on the
// current thread with no external dispatch (no deadlock under runTest virtual time).
internal actual fun rawEcdhPremaster(
    ops: KeyAgreementBlockingOps,
    privateKey: KeyAgreementPrivateKey,
    peerPublicKey: KeyAgreementPublicKey,
): PlatformBuffer = runBlocking { ops.deriveTlsPremasterSecret(privateKey, peerPublicKey) }

package com.ditchoom.webrtc.dtls

import com.ditchoom.webrtc.dtls.cinterop.boringssl.bd_smoke
import kotlinx.cinterop.ExperimentalForeignApi

@OptIn(ExperimentalForeignApi::class)
internal actual fun dtlsBackendProbe(): Long = bd_smoke()

package com.ditchoom.webrtc.ice

import kotlin.time.Duration

/**
 * Moot on wasmJs, for the same two reasons as js: [systemInterfaceEnumerator] reports
 * [InterfaceEnumerationFailure.NoPlatformApi], so no monitor is ever built for this to drive, and there
 * is no raw-UDP `AddressedDatagramChannel` actual here for an ICE agent of ours to ride. Reported as
 * [InterfaceChangeTrigger.Polled] rather than a fake signal.
 */
internal actual fun platformInterfaceChangeTrigger(pollInterval: Duration): InterfaceChangeTrigger =
    InterfaceChangeTrigger.Polled(pollInterval, ReactivityDegradation.NoPlatformSignal)

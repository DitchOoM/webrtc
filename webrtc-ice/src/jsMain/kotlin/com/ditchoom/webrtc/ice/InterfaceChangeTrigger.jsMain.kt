package com.ditchoom.webrtc.ice

import kotlin.time.Duration

/**
 * Moot on js, and deliberately so: [systemInterfaceEnumerator] reports
 * [InterfaceEnumerationFailure.NoPlatformApi] here, so `systemNetworkMonitor()` never returns a monitor
 * for this trigger to drive. Reported as [InterfaceChangeTrigger.Polled] rather than a fake signal,
 * because the one property this type must never violate is claiming push where there is none.
 *
 * (network-monitor *does* publish a js artifact, but its `JsNetworkMonitor` polls
 * `os.networkInterfaces()` / reads `navigator.connection` — and it would have nothing to drive anyway:
 * there is no raw-UDP `AddressedDatagramChannel` actual on js, so there is no ICE agent of ours to restart.)
 */
internal actual fun platformInterfaceChangeTrigger(pollInterval: Duration): InterfaceChangeTrigger =
    InterfaceChangeTrigger.Polled(pollInterval, ReactivityDegradation.NoPlatformSignal)

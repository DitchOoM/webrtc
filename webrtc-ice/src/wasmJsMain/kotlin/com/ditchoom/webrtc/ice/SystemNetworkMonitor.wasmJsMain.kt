package com.ditchoom.webrtc.ice

/**
 * wasmJs has no interface table to read, for the same two reasons as the js actual — a browser page
 * cannot enumerate NICs and delegates ICE to its own `RTCPeerConnection`, and there is no raw-UDP
 * `DatagramChannel` actual on this target for an ICE agent of ours to ride. Reported as the typed
 * [InterfaceEnumerationFailure.NoPlatformApi] so [systemNetworkMonitor] hands back
 * [NetworkMonitorSupport.Unavailable] rather than a monitor that silently never fires.
 */
public actual fun systemInterfaceEnumerator(): InterfaceEnumerator =
    InterfaceEnumerator { InterfaceSnapshot.Unavailable(InterfaceEnumerationFailure.NoPlatformApi) }

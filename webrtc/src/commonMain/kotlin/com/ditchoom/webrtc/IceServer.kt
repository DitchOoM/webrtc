package com.ditchoom.webrtc

/**
 * `IceServer` and `IceServerCredentials` moved down to `webrtc-ice` (issue #136).
 *
 * They are ICE concepts, and the thing that had to consume them — the production
 * [IceGatheringPolicy][com.ditchoom.webrtc.ice.IceGatheringPolicy], built over `socket-udp` in
 * `webrtc-ice`'s `socketMain` — sits *below* this module. Before the move, `IceServer` was reachable
 * only from the browser bridges here, which is precisely why it never reached the native path at all.
 *
 * These aliases keep every existing `com.ditchoom.webrtc.IceServer` call site compiling, constructors
 * included — `IceServer(url, username, credential)` is unaffected.
 *
 * **One case they cannot cover:** Kotlin does not resolve a *nested* classifier through a type alias, so
 * `IceServerCredentials.LongTerm(…)` and `IceServerCredentials.None` must be imported from
 * `com.ditchoom.webrtc.ice` directly. That is a source break for anyone naming those two, which is why
 * it is stated here rather than discovered at the call site; the browser bridges in this module import
 * the real declaration for exactly this reason.
 */
public typealias IceServer = com.ditchoom.webrtc.ice.IceServer

/** @see IceServer */
public typealias IceServerCredentials = com.ditchoom.webrtc.ice.IceServerCredentials

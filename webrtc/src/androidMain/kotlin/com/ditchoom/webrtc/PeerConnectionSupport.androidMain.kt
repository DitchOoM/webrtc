package com.ditchoom.webrtc

/** android: the native stack owns the protocol — no RTCPeerConnection to delegate to (RFC §1.1). */
public actual fun peerConnectionSupport(): PeerConnectionSupport = PeerConnectionSupport.Native

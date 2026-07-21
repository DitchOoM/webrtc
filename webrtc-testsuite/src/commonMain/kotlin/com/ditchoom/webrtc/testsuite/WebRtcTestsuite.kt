package com.ditchoom.webrtc.testsuite

/**
 * Module marker for the published consumer harness (RFC §7 "Consumer" tier). The real surface is the
 * [com.ditchoom.webrtc.testsuite.harness.withWebRtcHarness] `{ natType(); relayOnly(); impaired() }`
 * DSL, which drives a full two-peer establishment over the deterministic in-memory vnet under `runTest`
 * virtual time; the JVM [com.ditchoom.webrtc.testsuite.controller.HarnessController] bridges those
 * scenarios to the L2 container harness (`test-harness/`).
 */
public object WebRtcTestsuite {
    public const val MODULE: String = "webrtc-testsuite"
}

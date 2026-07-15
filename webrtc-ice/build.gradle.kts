plugins {
    id("webrtc.multiplatform-library")
}

// Only this module's dependencies live here — targets, publishing, versioning, lint, and ABI
// validation all come from the webrtc.multiplatform-library convention (build-logic/).
kotlin {
    sourceSets {
        commonMain.dependencies {
            // Sans-io agent core (RFC §5.1): handle(event, now) + nextDeadline. Gathering drivers ride
            // the DatagramChannel/NetworkMonitor seams; UDP/mDNS actuals arrive in W3.
            // buffer-flow carries the @ExperimentalDatagramApi DatagramChannel seam (buffer 6.11.0); the
            // core targets it, NOT socket-udp — socket-udp is real-socket only (no wasm/browser, RFC §1.1)
            // and is consumed at the platform-edge gathering driver, keeping the core all-platform.
            api(project(":webrtc-stun"))
            api(libs.buffer.flow)
            api(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            // runTest virtual time — the whole seam gate (VnetDatagramSeamTest) runs on it. kotlin("test")
            // comes from the convention; coroutines-test is per-module.
            implementation(libs.kotlinx.coroutines.test)
        }
        // The real-socket resolution smoke test (RealUdpSocketSeamTest) binds two `socket-udp` UdpSockets
        // on loopback and echoes over the SAME buffer-flow DatagramChannel the vnet implements — proving
        // socket-udp resolves (from Central) and its actual honors the seam. JVM-only: socket-udp has no
        // wasm/browser target, and real UDP is not virtual-time (real dispatcher).
        jvmTest.dependencies {
            implementation(libs.socket.udp)
        }
    }
}

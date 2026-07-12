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
            api(project(":webrtc-stun"))
            api(libs.buffer.flow)
            api(libs.kotlinx.coroutines.core)
        }
    }
}

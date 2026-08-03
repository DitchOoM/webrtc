import org.jetbrains.kotlin.konan.target.HostManager

// Consumer-smoke: a REAL downstream consumer of the PUBLISHED com.ditchoom:webrtc artifacts. Unlike a
// dependency-resolution check (which only RESOLVES the graph and checks module-metadata shape), this
// project COMPILES consumer code against the published API on every declared target, LINKS Kotlin/Native
// binaries, and RUNS a behavioural `withWebRtcHarness { }` establishment on the JVM — catching an API that
// resolves but won't compile, a klib left out of the publish (the socket #188 class of bug), or a runtime
// break that resolution never exercises. It is the artifact-shape safety net the source-built lanes can't see.
//
// Parameterised into three modes, so the same consumer proves the artifacts at both ends of the release:
//   -PmavenRepoPath=<dir>  PRE-release  — the merged maven-local repo the CI build just produced.
//   -PcentralOnly=true     POST-release — Maven Central and NOTHING else, so the coordinates under test
//                          can only resolve if they are genuinely PUBLISHED — resolving from Central
//                          as a real consumer does, with no mavenLocal fallback to silently satisfy a
//                          module that never made it out.
//   (neither)              a developer's own `publishToMavenLocal` run.
// -PwebrtcVersion selects the version in every mode.
plugins {
    alias(libs.plugins.kotlin.multiplatform)
}

val webrtcVersion = (findProperty("webrtcVersion") as String?) ?: "0.0.2-SNAPSHOT"
val mavenRepoPath = findProperty("mavenRepoPath") as String?
val centralOnly = (findProperty("centralOnly") as String?)?.toBoolean() ?: false

require(!(centralOnly && mavenRepoPath != null)) {
    "-PcentralOnly and -PmavenRepoPath are mutually exclusive: centralOnly means Central is the ONLY source"
}

val isLinux = HostManager.hostIsLinux
val isMacOS = HostManager.hostIsMac

repositories {
    // The artifacts under test. In centralOnly mode this list is deliberately just mavenCentral(): a
    // missing or malformed published module has nowhere to fall back to and fails the build.
    if (!centralOnly) {
        if (mavenRepoPath != null) {
            maven(url = uri(file(mavenRepoPath)))
        } else {
            mavenLocal()
        }
        google()
    }
    mavenCentral()
}

kotlin {
    jvmToolchain(21)
    jvm {
        testRuns.all {
            executionTask.configure { testLogging { showStandardStreams = true } }
        }
    }

    // Match the host gating the library itself publishes: the Linux-native target only on Linux, Apple only
    // on macOS — so the consumer's target set matches what each host actually published.
    if (isLinux) {
        linuxX64()
    }
    if (isMacOS) {
        macosArm64()
    }

    sourceSets {
        commonMain.dependencies {
            // BOTH published coordinates a downstream project actually writes down, declared DIRECTLY —
            // not left to a transitive edge. `webrtc` is the consumer API (PeerConnection, DataChannel,
            // IceServer); `webrtc-testsuite` is the harness they test against. Depending on the testsuite
            // alone would still compile (it re-exposes :webrtc via `api`), but it would never prove that
            // `com.ditchoom:webrtc` itself resolves as a standalone coordinate — which is exactly the
            // artifact-shape bug this project exists to catch.
            implementation("com.ditchoom:webrtc:$webrtcVersion")
            implementation("com.ditchoom:webrtc-testsuite:$webrtcVersion")
        }

        // kotlin.test + coroutines-test in commonTest so EVERY test source set inherits them — notably the
        // K/N test source set, whose ApiLinkTest is the Kotlin/Native LINK gate against the published klibs.
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}

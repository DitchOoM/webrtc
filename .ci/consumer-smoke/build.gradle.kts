import org.jetbrains.kotlin.konan.target.HostManager

// Consumer-smoke: a REAL downstream consumer of the PUBLISHED com.ditchoom:webrtc artifacts. Unlike a
// dependency-resolution check (which only RESOLVES the graph and checks module-metadata shape), this
// project COMPILES consumer code against the published API on every declared target, LINKS Kotlin/Native
// binaries, and RUNS a behavioural `withWebRtcHarness { }` establishment on the JVM — catching an API that
// resolves but won't compile, a klib left out of the publish (the socket #188 class of bug), or a runtime
// break that resolution never exercises. It is the artifact-shape safety net the source-built lanes can't see.
//
// Parameterised: -PwebrtcVersion + -PmavenRepoPath point it at the just-built merged maven-local repo in
// CI; both default to a local `publishToMavenLocal` run.
plugins {
    alias(libs.plugins.kotlin.multiplatform)
}

val webrtcVersion = (findProperty("webrtcVersion") as String?) ?: "0.0.2-SNAPSHOT"
val mavenRepoPath = findProperty("mavenRepoPath") as String?

val isLinux = HostManager.hostIsLinux
val isMacOS = HostManager.hostIsMac

repositories {
    // The artifacts under test: an explicit merged maven-local repo in CI, else the developer's local
    // publishToMavenLocal cache.
    if (mavenRepoPath != null) {
        maven(url = uri(file(mavenRepoPath)))
    } else {
        mavenLocal()
    }
    google()
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
            // The published testsuite surface a real consumer touches (transitively pulls :webrtc, buffer,
            // coroutines). Compiling commonMain against it on every declared target is already stronger than
            // resolution: it catches an API shape that resolves but won't compile.
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

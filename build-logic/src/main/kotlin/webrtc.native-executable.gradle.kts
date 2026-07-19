// ── Convention for a NON-published Kotlin/Native executable module ───────────────────────────────
//
// The W7 interop harness endpoint (:webrtc-harness-endpoint) is a native binary, not a library. It must
// NOT apply the `webrtc.multiplatform-library` convention (that adds jvm/js/wasm/android/apple targets +
// publishing + apiCheck, all wrong for an executable). But it DOES need KGP + KSP applied from
// build-logic's classpath — the SAME classloader the library convention uses — or KGP is "loaded
// multiple times in different subprojects" (the trap documented in build-logic/build.gradle.kts, hit if
// a module applies `alias(libs.plugins.kotlin.multiplatform)` in its own `plugins {}` block).
//
// This convention therefore applies exactly those two plugins and the shared JDK toolchain, and nothing
// else. The module's own build file declares its linux targets, executable binaries + linkerOpts, its
// dependencies, and (if it generates buffer-codec schemas) the `kspCommonMainMetadata` wiring.

plugins {
    id("org.jetbrains.kotlin.multiplatform")
    id("com.google.devtools.ksp")
}

// The library convention defines these per-module; a native-executable module needs them too to
// resolve buffer / socket-udp / coroutines (matches the convention: Central + Google, no mavenLocal).
repositories {
    google()
    mavenCentral()
}

kotlin {
    jvmToolchain(21)
}

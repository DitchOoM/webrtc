@file:OptIn(ExperimentalWasmDsl::class, kotlinx.validation.ExperimentalBCVApi::class)

import com.ditchoom.webrtc.gradle.computeNextVersion
import org.gradle.api.publish.PublishingExtension
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.konan.target.HostManager

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The single convention every com.ditchoom:webrtc module applies:  plugins { id("webrtc.multiplatform-library") }
//
// It owns everything structural — the KMP target matrix, the JDK-21 toolchain, Android, ktlint, dokka,
// kover, binary-compatibility validation, Maven Central publishing, signing, and version derivation —
// so a module's own build.gradle.kts carries ONLY its dependencies. Structural facts are derived from
// the module name (artifactId, JS module name, Android namespace); prose (POM_NAME / POM_DESCRIPTION)
// comes from the module's gradle.properties. No copy-pasted publishing blocks.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

plugins {
    id("org.jetbrains.kotlin.multiplatform")
    // AGP 9's Kotlin-Multiplatform-native Android plugin: Android is a normal KMP target configured as
    // `kotlin { android { } }`, and it composes cleanly with the KMP plugin (no `android.newDsl`
    // opt-out, and no accessor-generation conflict inside this convention plugin).
    id("com.android.kotlin.multiplatform.library")
    id("org.jlleitschuh.gradle.ktlint")
    id("com.vanniktech.maven.publish")
    id("org.jetbrains.dokka")
    id("org.jetbrains.kotlinx.kover")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
    id("dev.detekt")
    // kotlinx-benchmark + allopen (JMH @State classes must be open). Benchmarks live in a shared
    // src/commonBenchmark/kotlin source set and run on demand; results tracked in PERFORMANCE.md.
    id("org.jetbrains.kotlin.plugin.allopen")
    id("org.jetbrains.kotlinx.benchmark")
    id("signing")
}

// detekt — the only static analyzer that sees the Native/JS/WASM actuals (CodeQL only traces JVM
// bytecode). Non-blocking, committed per-module baselines so only NEW findings surface. KMP sources
// live under src/<sourceSet>/kotlin, not detekt's default JVM layout, so point it at each src/*/kotlin.
detekt {
    buildUponDefaultConfig.set(true)
    baseline.set(layout.projectDirectory.file("config/detekt/baseline.xml"))
    parallel.set(true)
    ignoreFailures.set(true)
    val ktSourceRoots =
        layout.projectDirectory.dir("src").asFile
            .listFiles { f -> f.isDirectory }
            ?.map { layout.projectDirectory.dir("src/${it.name}/kotlin") }
            ?: emptyList()
    if (ktSourceRoots.isNotEmpty()) {
        source.setFrom(ktSourceRoots)
    }
}

group = "com.ditchoom"

val onGithub = System.getenv("GITHUB_REPOSITORY")?.isNotBlank() == true
if (version.toString() == "unspecified") {
    // Local builds get -SNAPSHOT; CI publishes release versions. -Pversion=x still wins (Gradle sets
    // `version` from it, so this guard is skipped).
    version = computeNextVersion(snapshot = !onGithub)
}

// Structural identity, derived — never restated per module.
val moduleArtifactId = name
val jsModuleName = "$name-kt"
val androidNamespace = "com.ditchoom." + name.replace('-', '.')

// Lock the published public ABI so additive minors are proven non-breaking by `apiCheck`. Validate
// the JVM dump only: it is host-independent and the common public surface is wholly contained in it,
// whereas klib validation diverges between partial-target dev hosts and CI runners.
apiValidation {
    klib {
        enabled = false
    }
}

// JMH @State classes must be open for subclassing by the generated benchmark harness.
allOpen {
    annotation("org.openjdk.jmh.annotations.State")
}

// The convention has no `libs` accessor (it is not part of the main build), so reach the shared
// catalog explicitly for the one dependency the benchmark source sets need.
val benchmarkRuntime =
    extensions
        .getByType(org.gradle.api.artifacts.VersionCatalogsExtension::class.java)
        .named("libs")
        .findLibrary("kotlinx-benchmark-runtime")
        .get()

repositories {
    google()
    mavenCentral()
}

kotlin {
    jvmToolchain(21)

    // Android as a first-class KMP target (new AGP KMP-library DSL). namespace / compileSdk / minSdk
    // are the only Android facts a library needs; the plugin publishes the release variant itself, so
    // there is no separate `android {}` block. commonTest also runs on the Android host JVM.
    android {
        namespace = androidNamespace
        compileSdk = 36
        minSdk = 21
        withHostTest { }
    }
    jvm {
        compilerOptions.jvmTarget.set(JvmTarget.JVM_1_8)
        // Benchmark compilation associated with main so benchmarks see the module's classes.
        compilations.create("benchmark") {
            associateWith(this@jvm.compilations.getByName("main"))
        }
    }
    js {
        outputModuleName.set(jsModuleName)
        browser()
        nodejs()
    }
    wasmJs {
        browser()
        nodejs()
    }
    // Apple targets register on macOS hosts only (compile-faithful locally, runtime-validated on the
    // macOS runner). Linux K/N always registers — the server-side lane and a downstream consumer.
    // The deprecated x64 Apple tiers (macosX64/watchosX64/tvosX64) are intentionally omitted —
    // runners and modern devices are arm64.
    if (HostManager.hostIsMac) {
        macosArm64()
        iosArm64()
        iosSimulatorArm64()
        iosX64()
        watchosArm64()
        watchosSimulatorArm64()
        tvosArm64()
        tvosSimulatorArm64()
    }
    linuxX64 {
        compilations.create("benchmark") {
            associateWith(this@linuxX64.compilations.getByName("main"))
        }
    }
    linuxArm64()

    applyDefaultHierarchyTemplate()

    sourceSets {
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
        // Shared benchmark sources compiled into both the JVM and Linux-K/N benchmark compilations.
        val jvmBenchmark by getting {
            kotlin.srcDir("src/commonBenchmark/kotlin")
            dependencies {
                implementation(benchmarkRuntime)
            }
        }
        val linuxX64Benchmark by getting {
            kotlin.srcDir("src/commonBenchmark/kotlin")
            dependencies {
                implementation(benchmarkRuntime)
            }
        }
    }
}

// Benchmark targets + run profiles (the buffer pattern): `main` for real numbers, `quick` for a fast
// validation pass. Invoke on demand, e.g. `./gradlew :webrtc-stun:jvmBenchmarkBenchmark`.
benchmark {
    targets {
        register("jvmBenchmark")
        register("linuxX64Benchmark")
    }
    configurations {
        named("main") {
            warmups = 3
            iterations = 5
            iterationTime = 1000
            iterationTimeUnit = "ms"
        }
        register("quick") {
            warmups = 1
            iterations = 2
            iterationTime = 500
            iterationTimeUnit = "ms"
        }
    }
}

ktlint {
    verbose.set(true)
    outputToConsole.set(true)
    android.set(true)
    filter {
        exclude("**/generated/**")
    }
}

// ── Publishing / signing (POM prose from module gradle.properties; shared fields from root) ──
val pomName = providers.gradleProperty("POM_NAME").orElse(moduleArtifactId)
val pomDescription = providers.gradleProperty("POM_DESCRIPTION").orElse("")
val publishedGroupId = providers.gradleProperty("publishedGroupId").get()
val siteUrl = providers.gradleProperty("siteUrl").get()
val gitUrl = providers.gradleProperty("gitUrl").get()
val licenseName = providers.gradleProperty("licenseName").get()
val licenseUrl = providers.gradleProperty("licenseUrl").get()
val developerOrg = providers.gradleProperty("developerOrg").get()
val developerName = providers.gradleProperty("developerName").get()
val developerEmail = providers.gradleProperty("developerEmail").get()
val developerId = providers.gradleProperty("developerId").get()

// Sign + publish to Central only on the main branch of CI with the key present; local and PR builds
// publish unsigned to mavenLocal.
val signingKey = findProperty("signingInMemoryKey")
val signingPassword = findProperty("signingInMemoryKeyPassword")
val isMainBranchGithub = System.getenv("GITHUB_REF") == "refs/heads/main"
val shouldSignAndPublish = isMainBranchGithub && signingKey is String && signingPassword is String

if (shouldSignAndPublish) {
    signing {
        useInMemoryPgpKeys(signingKey as String, signingPassword as String)
        sign(extensions.getByType(PublishingExtension::class.java).publications)
    }
}

mavenPublishing {
    if (shouldSignAndPublish) {
        publishToMavenCentral()
        signAllPublications()
    }
    coordinates(publishedGroupId, moduleArtifactId, version.toString())
    pom {
        name.set(pomName)
        description.set(pomDescription)
        url.set(siteUrl)
        licenses {
            license {
                name.set(licenseName)
                url.set(licenseUrl)
            }
        }
        developers {
            developer {
                id.set(developerId)
                name.set(developerName)
                email.set(developerEmail)
            }
        }
        organization {
            name.set(developerOrg)
        }
        scm {
            connection.set(gitUrl)
            developerConnection.set(gitUrl)
            url.set(siteUrl)
        }
    }
}

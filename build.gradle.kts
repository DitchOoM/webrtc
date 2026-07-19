// Root build file for the multi-module com.ditchoom:webrtc project.
// Per-module build logic (KMP targets, publishing, versioning, ktlint, dokka, kover, detekt,
// binary-compat validation) lives entirely in the build-logic `webrtc.multiplatform-library`
// convention plugin. This file carries only the aggregate lifecycle tasks CI invokes.

// The published library modules — every subproject EXCEPT the non-published native-executable harness
// endpoint (:webrtc-harness-endpoint), which applies `webrtc.native-executable`, not the library
// convention, so it has no detekt / apiCheck / android-host / js-browser / allTests tasks to aggregate.
// It is built via the top-level `build`/`assemble` lifecycle and linked explicitly by the L2 harness CI
// job; it never participates in the library aggregates below.
val libraryModules = subprojects.filter { it.name != "webrtc-harness-endpoint" }

// Aggregate detekt across every library module (each applies detekt via the convention plugin).
tasks.register("detektAll") {
    description = "Run detekt static analysis across all modules and Kotlin source sets (non-blocking)."
    group = "verification"
    dependsOn(libraryModules.map { "${it.path}:detekt" })
}

tasks.register("allTests") {
    description = "Run tests for all modules and platforms"
    group = "verification"
    dependsOn(libraryModules.map { "${it.path}:allTests" })
}

// Pre-publish gate: allTests + the Android-host and JS-browser suites that `allTests` skips and that
// have historically masked platform-only bugs. Every publishToMavenLocal depends on it.
tasks.register("prePublishCheck") {
    description = "allTests + Android-host unit tests + JS browser tests. Run before publishToMavenLocal."
    group = "verification"
    dependsOn("allTests")
    // Android host unit tests (new AGP KMP DSL task name) + JS browser tests — the two suites that
    // `allTests` skips and that have historically masked platform-only bugs. Library modules only.
    dependsOn(libraryModules.map { "${it.path}:testAndroidHostTest" })
    dependsOn(libraryModules.map { "${it.path}:jsBrowserTest" })
}

// Gate the local-publish safety net so CI can skip it: the build lanes already run the full test
// suite before publishing (and a single lane can't run cross-platform tests it has no toolchain for —
// e.g. the macOS lane has no Chrome for jsBrowserTest). Pass -PskipPrePublishCheck=true on CI.
val skipPrePublishCheck = providers.gradleProperty("skipPrePublishCheck").map { it.toBoolean() }.getOrElse(false)
subprojects {
    tasks.matching { it.name == "publishToMavenLocal" }.configureEach {
        if (!skipPrePublishCheck) {
            dependsOn(rootProject.tasks.named("prePublishCheck"))
        }
    }
}

tasks.register("buildAll") {
    description = "Build all modules"
    group = "build"
    dependsOn(subprojects.map { "${it.path}:build" })
}

// Copy Dokka output into the Docusaurus static dir (docs site build).
tasks.register<Copy>("copyDokkaToDocusaurus") {
    description = "Generate and copy API documentation to Docusaurus"
    group = "documentation"
    dependsOn(subprojects.map { "${it.path}:dokkaGenerateHtml" })
    subprojects.forEach { module ->
        from(module.layout.buildDirectory.dir("dokka/html")) {
            into(module.name)
        }
    }
    into(layout.projectDirectory.dir("docs/static/api"))
}

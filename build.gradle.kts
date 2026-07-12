// Root build file for the multi-module com.ditchoom:webrtc project.
// Per-module build logic (KMP targets, publishing, versioning, ktlint, dokka, kover, detekt,
// binary-compat validation) lives entirely in the build-logic `webrtc.multiplatform-library`
// convention plugin. This file carries only the aggregate lifecycle tasks CI invokes.

// Aggregate detekt across every module (each module applies detekt via the convention plugin).
tasks.register("detektAll") {
    description = "Run detekt static analysis across all modules and Kotlin source sets (non-blocking)."
    group = "verification"
    dependsOn(subprojects.map { "${it.path}:detekt" })
}

tasks.register("allTests") {
    description = "Run tests for all modules and platforms"
    group = "verification"
    dependsOn(subprojects.map { "${it.path}:allTests" })
}

// Pre-publish gate: allTests + the Android-host and JS-browser suites that `allTests` skips and that
// have historically masked platform-only bugs. Every publishToMavenLocal depends on it.
tasks.register("prePublishCheck") {
    description = "allTests + Android-host unit tests + JS browser tests. Run before publishToMavenLocal."
    group = "verification"
    dependsOn("allTests")
    // Android host unit tests (new AGP KMP DSL task name) + JS browser tests — the two suites that
    // `allTests` skips and that have historically masked platform-only bugs.
    dependsOn(subprojects.map { "${it.path}:testAndroidHostTest" })
    dependsOn(subprojects.map { "${it.path}:jsBrowserTest" })
}

subprojects {
    tasks.matching { it.name == "publishToMavenLocal" }.configureEach {
        dependsOn(rootProject.tasks.named("prePublishCheck"))
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

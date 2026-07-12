plugins {
    `kotlin-dsl`
}

// The precompiled `webrtc.multiplatform-library` convention script applies the ecosystem plugins by
// id. For that to resolve, each plugin's marker artifact must be on this build's compile classpath.
// `toDep()` turns a version-catalog plugin (id + version) into its Gradle plugin-marker coordinates,
// so versions still live only in gradle/libs.versions.toml — no hardcoded plugin versions here.
fun Provider<PluginDependency>.toDep(): Provider<String> =
    map { "${it.pluginId}:${it.pluginId}.gradle.plugin:${it.version}" }

dependencies {
    implementation(libs.plugins.kotlin.multiplatform.toDep())
    implementation(libs.plugins.android.kmp.library.toDep())
    implementation(libs.plugins.kotlin.allopen.toDep())
    implementation(libs.plugins.kotlinx.benchmark.toDep())
    implementation(libs.plugins.ktlint.toDep())
    implementation(libs.plugins.maven.publish.toDep())
    implementation(libs.plugins.dokka.toDep())
    implementation(libs.plugins.kover.toDep())
    implementation(libs.plugins.binary.compatibility.validator.toDep())
    // detekt is applied per module (inside the convention) rather than at root: detekt 2.x touches
    // Kotlin's KotlinBasePlugin at apply time, so it must run where KGP is on the classpath.
    implementation(libs.plugins.detekt.toDep())
    // KSP is applied per module (inside the convention) rather than via a module-level `alias(...)`:
    // applying it in the main build alongside the included-build convention loads the Kotlin Gradle
    // plugin twice ("loaded multiple times in different subprojects"). Putting it on this classpath
    // and applying it in the convention keeps KGP + KSP on one classloader. Modules that generate
    // buffer-codec schemas add the `kspCommonMainMetadata` wiring in their own build file; KSP is
    // inert in modules that don't.
    implementation(libs.plugins.ksp.toDep())
}

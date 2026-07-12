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
}

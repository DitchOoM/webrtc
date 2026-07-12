// Standalone build that provides the `webrtc.*` convention plugins to the main build via
// `includeBuild("build-logic")` in the root settings. Sharing the root version catalog here means
// plugin versions are declared once, in gradle/libs.versions.toml.
dependencyResolutionManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
    versionCatalogs {
        create("libs") {
            from(files("../gradle/libs.versions.toml"))
        }
    }
}

rootProject.name = "build-logic"

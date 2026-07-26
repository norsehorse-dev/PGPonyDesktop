// PGPony Desktop — a SEPARATE Gradle build from the Android app (which is AGP-only). Standing on
// its own lets us use a plain kotlin("jvm") toolchain and reuse the exact portable crypto source
// via vendored source sets (see build.gradle.kts), with none of AGP's variant machinery.
// Same pattern, same proven plugin set as RelayPonyDesktop.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "pgpony-desktop"

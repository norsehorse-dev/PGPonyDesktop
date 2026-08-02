// VersionDriftTest.kt
// 1.1.0 — the version lives in two files that must move together and nothing enforced it:
// AppVersion.VERSION (what the app reports, what UpdateCheck compares) and build.gradle.kts's
// packageVersion (what jpackage stamps on the installers). Flagged in the release-mechanics
// section of PLANNING_DESKTOP_1_1_0.md. Reads the build script off disk the same way
// I18nTest's source grep does — the test runs with the repo root as its working directory.

package com.pgpony.desktop

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class VersionDriftTest {

    @Test
    fun packageVersionMatchesAppVersion() {
        val gradle = File("build.gradle.kts")
        assertTrue(gradle.isFile, "expected to run from the repo root; no ${gradle.absolutePath}")
        val match = Regex("""packageVersion\s*=\s*"([^"]+)"""").find(gradle.readText())
        assertNotNull(match, "no packageVersion assignment found in build.gradle.kts")
        assertEquals(
            AppVersion.VERSION, match.groupValues[1],
            "AppVersion.VERSION and build.gradle.kts packageVersion must move together"
        )
    }

    @Test
    fun versionIsPlainSemver() {
        // UpdateCheck and the downstream winget/AUR templates all assume x.y.z with no suffix.
        assertTrue(Regex("""\d+\.\d+\.\d+""").matches(AppVersion.VERSION), AppVersion.VERSION)
    }
}

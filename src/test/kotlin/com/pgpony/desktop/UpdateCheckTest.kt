// UpdateCheckTest.kt
// D13 validation — the version comparator behind the automatic update check.
//
// Every case below is one a plausible implementation gets wrong. Comparing versions looks like
// string comparison until "1.0.10" sorts before "1.0.9" and the app tells someone to downgrade;
// it looks like a float parse until there are three segments. The comparator is pure and the
// manifest it reads comes off the network, so malformed input is a normal case, not an edge one.

package com.pgpony.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UpdateCheckTest {

    private fun older(a: String, b: String) =
        assertTrue(UpdateCheck.compareVersions(a, b) < 0, "expected $a to sort older than $b")

    private fun newer(a: String, b: String) =
        assertTrue(UpdateCheck.compareVersions(a, b) > 0, "expected $a to sort newer than $b")

    private fun same(a: String, b: String) =
        assertEquals(0, UpdateCheck.compareVersions(a, b), "expected $a to equal $b")

    @Test
    fun identicalVersionsAreEqual() {
        same("1.0.0", "1.0.0")
        same("2.13.4", "2.13.4")
    }

    /** The lexicographic trap: as strings, "1.0.10" < "1.0.9". */
    @Test
    fun segmentsCompareNumericallyNotAsStrings() {
        older("1.0.9", "1.0.10")
        newer("1.0.10", "1.0.9")
        older("1.9.0", "1.10.0")
    }

    @Test
    fun missingSegmentsCountAsZero() {
        same("1.1", "1.1.0")
        same("1", "1.0.0")
        older("1.1", "1.1.1")
    }

    @Test
    fun earlierSegmentsDominate() {
        older("1.9.9", "2.0.0")
        newer("2.0.0", "1.99.99")
    }

    /**
     * A pre-release sorts BELOW its own release. Without this, someone running the final 1.1.0
     * would be offered 1.1.0-rc.1 as an upgrade.
     */
    @Test
    fun prereleaseSortsBelowTheSameRelease() {
        older("1.1.0-rc.1", "1.1.0")
        newer("1.1.0", "1.1.0-rc.1")
    }

    @Test
    fun prereleasesCompareAmongThemselves() {
        older("1.1.0-rc.1", "1.1.0-rc.2")
        same("1.1.0-rc.1", "1.1.0-rc.1")
    }

    /** The exact string this project shipped through D12 — it must not beat the 1.0.0 release. */
    @Test
    fun theOldDevVersionIsOlderThanTheRelease() {
        older("1.0.0-dev.D1", "1.0.0")
    }

    /** The manifest is fetched over the network; garbage in it must mean "no update", not a crash. */
    @Test
    fun malformedSegmentsReadAsZeroRatherThanThrowing() {
        same("1.x.0", "1.0.0")
        same("", "0")
        same("not-a-version", "0-a-version")
        assertFalse(UpdateCheck.isNewer("garbage", "1.0.0"))
    }

    @Test
    fun surroundingWhitespaceIsIgnored() {
        same(" 1.0.0 ", "1.0.0")
    }

    @Test
    fun isNewerIsStrictlyGreater() {
        assertFalse(UpdateCheck.isNewer("1.0.0", "1.0.0"))
        assertFalse(UpdateCheck.isNewer("0.9.0", "1.0.0"))
        assertTrue(UpdateCheck.isNewer("1.0.1", "1.0.0"))
    }

    /** A blank version field in the manifest must never present itself as an upgrade. */
    @Test
    fun blankRemoteVersionIsNeverAnUpdate() {
        assertFalse(UpdateCheck.isNewer("", "1.0.0"))
        assertFalse(UpdateCheck.isNewer("   ", "1.0.0"))
    }

    /**
     * The shipping build must not offer itself as an update. This is the case that would be most
     * embarrassing in front of a user and the cheapest to pin.
     */
    @Test
    fun theRunningVersionIsNotAnUpdateOverItself() {
        assertFalse(UpdateCheck.isNewer(AppVersion.VERSION))
    }
}

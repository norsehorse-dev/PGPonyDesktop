// DesktopPrefsSettingsTest.kt
// PGPony Desktop 3.0.0: the java.util.prefs side of the settings seam, and the four vendored
// stores running verbatim on top of it. Uses the in-memory MemoryPreferences node from
// KeyServerDirectoryTest, so nothing touches the real user preferences.

package com.pgpony.desktop

import com.pgpony.android.crypto.FallbackPrefs
import com.pgpony.android.data.KeyPublicationStore
import com.pgpony.android.data.RemovedUserIdStore
import com.pgpony.android.data.settings.SettingsStores
import com.pgpony.android.network.WkdLookup
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DesktopPrefsSettingsTest {

    private val v6fp = "A".repeat(64)

    @AfterTest
    fun uninstall() = SettingsStores.uninstall()

    @Test
    fun valuesRoundTrip() {
        val s = DesktopPrefsSettings(MemoryPreferences())
        assertNull(s.getString("a", null))
        s.putString("a", "x")
        assertEquals("x", s.getString("a", null))
        s.putString("a", null)
        assertNull(s.getString("a", null))
        s.putBoolean("b", true)
        assertTrue(s.getBoolean("b", false))
        s.putLong("c", 42L)
        assertEquals(42L, s.getLong("c", 0L))
        s.putStringSet("d", setOf("one", "two, with \"quotes\""))
        assertEquals(setOf("one", "two, with \"quotes\""), s.getStringSet("d", emptySet()))
        s.remove("d")
        assertEquals(emptySet(), s.getStringSet("d", emptySet()))
    }

    @Test
    fun v6FingerprintKeysFitAndLongerKeysStillWork() {
        val s = DesktopPrefsSettings(MemoryPreferences())
        val exact = "fallback_strict_$v6fp"
        assertEquals(80, exact.length)
        s.putBoolean(exact, true)
        assertTrue(s.getBoolean(exact, false))
        val tooLong = "x".repeat(200)
        s.putString(tooLong, "kept")
        assertEquals("kept", s.getString(tooLong, null))
    }

    @Test
    fun vendoredStoresRunOnTheSeam() {
        val node = MemoryPreferences()
        SettingsStores.install { _, _ -> DesktopPrefsSettings(node) }

        assertTrue(WkdLookup.isEnabled())
        WkdLookup.set(false)
        assertFalse(WkdLookup.isEnabled())

        FallbackPrefs.setStrict(v6fp, true)
        assertTrue(FallbackPrefs.isStrict(v6fp))

        RemovedUserIdStore.addRemoved(v6fp, "old@example.org")
        assertEquals(setOf("old@example.org"), RemovedUserIdStore.removed(v6fp))

        KeyPublicationStore.record(v6fp, "keys.openpgp.org", 1_000L)
        KeyPublicationStore.record(v6fp, "keys.pgpony.app", 2_000L)
        assertEquals(mapOf("keys.openpgp.org" to 1_000L, "keys.pgpony.app" to 2_000L), KeyPublicationStore.servers(v6fp))
        KeyPublicationStore.clear(v6fp)
        assertEquals(emptyMap(), KeyPublicationStore.servers(v6fp))
    }

    @Test
    fun storesAreInertWithNothingInstalled() {
        SettingsStores.uninstall()
        WkdLookup.set(false)
        assertTrue(WkdLookup.isEnabled())
        assertEquals(emptySet(), RemovedUserIdStore.removed(v6fp))
    }
}

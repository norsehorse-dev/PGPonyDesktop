// FlatpakTest.kt
// PGPony Desktop 3.0.0, stage 5 checkpoint 5c: Flatpak detection and the JVM defaults it sets.
// The environment and the filesystem are passed in, so nothing here depends on the machine.

package com.pgpony.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class FlatpakTest {

    private fun env(vararg pairs: Pair<String, String>): (String) -> String? = mapOf(*pairs)::get

    private fun files(vararg paths: String): (String) -> Boolean = { it in paths }

    @Test
    fun detectedByTheAppIdOrTheInfoFile() {
        assertTrue(Flatpak.detect(env("FLATPAK_ID" to "app.pgpony.PGPony"), files()))
        assertTrue(Flatpak.detect(env(), files("/.flatpak-info")))
        assertFalse(Flatpak.detect(env("FLATPAK_ID" to " "), files()))
        assertFalse(Flatpak.detect(env("XDG_CONFIG_HOME" to "/home/u/.config"), files(Flatpak.PCSC_LIBRARY)))
    }

    @Test
    fun outsideFlatpakNothingIsSet() {
        assertEquals(emptyMap(), Flatpak.defaults(env("XDG_CONFIG_HOME" to "/home/u/.config"), files(Flatpak.PCSC_LIBRARY)))
    }

    @Test
    fun insideFlatpakPreferencesAndSmartCardsMove() {
        val config = "/home/u/.var/app/app.pgpony.PGPony/config"
        assertEquals(
            mapOf(
                "java.util.prefs.userRoot" to config,
                "sun.security.smartcardio.library" to Flatpak.PCSC_LIBRARY
            ),
            Flatpak.defaults(env("FLATPAK_ID" to "app.pgpony.PGPony", "XDG_CONFIG_HOME" to config), files(Flatpak.PCSC_LIBRARY))
        )
        assertEquals(
            emptyMap(),
            Flatpak.defaults(env("FLATPAK_ID" to "app.pgpony.PGPony"), files()),
            "no config home and no bundled pcsc-lite: nothing to point at"
        )
    }
}

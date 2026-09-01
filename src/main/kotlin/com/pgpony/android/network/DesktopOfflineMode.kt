// DesktopOfflineMode.kt — DESKTOP TWIN of network/OfflineMode.kt (vendored copy excluded:
// SharedPreferences/Context). Same `object OfflineMode`, same API (isEnabled/enabled/set/
// initFromPrefs), backed by java.util.prefs and a Compose-observable mirror. File name differs
// from the excluded file (D1 Fix1 rule). isEnabled() is the authoritative gate the network choke
// point (DesktopHttpClientFactory) reads on every request; `enabled` is the reactive mirror for
// the Settings UI.

package com.pgpony.android.network

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.util.prefs.Preferences

object OfflineMode {

    const val KEY_ENABLED = "offline_mode_enabled"
    const val DEFAULT = false

    /** Test hook, mirrors DesktopProxyPrefs.prefsOverride. */
    internal var prefsOverride: Preferences? = null

    private fun prefs(): Preferences =
        prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    /** Authoritative. The network choke point gates here on every request. */
    fun isEnabled(): Boolean =
        runCatching { prefs().getBoolean(KEY_ENABLED, DEFAULT) }.getOrDefault(DEFAULT)

    /** Compose-observable mirror for the UI. Seeded by [initFromPrefs]. */
    var enabled by mutableStateOf(DEFAULT)
        private set

    fun initFromPrefs() {
        enabled = isEnabled()
    }

    fun set(value: Boolean) {
        runCatching { prefs().putBoolean(KEY_ENABLED, value) }
        enabled = value
    }
}

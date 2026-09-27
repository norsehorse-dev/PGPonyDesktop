// DesktopPrefsSettings.kt
// PGPony Desktop 3.0.0: the desktop side of the settings seam that PGPonyAndroid 4.7.0 added
// (vendored data/settings/KeyValueSettings.kt). Installed first thing in main(), for every face
// of the binary (GUI, CLI, the pgpony-gpg shim), so the vendored stores (KeyPublicationStore,
// RemovedUserIdStore, WkdLookup, FallbackPrefs) run verbatim here instead of as excluded files
// with hand-written twins.
//
// Storage is java.util.prefs, like every other desktop setting, under its own child node per
// store name ("app/pgpony/desktop/kv/pgpony_prefs") so the store keys can never collide with
// the desktop's own keys in "app/pgpony/desktop". String sets are stored as a JSON array.
//
// java.util.prefs limits a key to 80 characters and a value to 8192. A v6 fingerprint key such
// as "fallback_strict_" + 64 hex is exactly 80, so the limit holds today; a longer key is
// stored under a SHA-256 of itself instead of failing. A value over the limit is dropped, the
// same "write does nothing" the stores already tolerate when storage is unavailable.

package com.pgpony.desktop

import com.pgpony.android.data.settings.KeyValueSettings
import com.pgpony.android.data.settings.SettingsStores
import org.json.JSONArray
import java.security.MessageDigest
import java.util.prefs.Preferences

class DesktopPrefsSettings(private val node: Preferences) : KeyValueSettings {

    private fun k(key: String): String =
        if (key.length <= Preferences.MAX_KEY_LENGTH) key
        else "h:" + MessageDigest.getInstance("SHA-256").digest(key.toByteArray())
            .joinToString("") { "%02x".format(it) }

    private inline fun write(block: () -> Unit) {
        try {
            block()
            node.flush()
        } catch (_: Exception) {
            // Over-long value or a backing-store failure: the write does nothing.
        }
    }

    override fun getString(key: String, default: String?): String? = node.get(k(key), default)
    override fun getBoolean(key: String, default: Boolean): Boolean = node.getBoolean(k(key), default)
    override fun getLong(key: String, default: Long): Long = node.getLong(k(key), default)

    override fun getStringSet(key: String, default: Set<String>): Set<String> {
        val raw = node.get(k(key), null) ?: return default
        return try {
            val a = JSONArray(raw)
            (0 until a.length()).map { a.getString(it) }.toSet()
        } catch (_: Exception) {
            default
        }
    }

    override fun putString(key: String, value: String?) = write {
        if (value == null) node.remove(k(key)) else node.put(k(key), value)
    }
    override fun putBoolean(key: String, value: Boolean) = write { node.putBoolean(k(key), value) }
    override fun putLong(key: String, value: Long) = write { node.putLong(k(key), value) }
    override fun putStringSet(key: String, value: Set<String>) =
        write { node.put(k(key), JSONArray(value.sorted()).toString()) }
    override fun remove(key: String) = write { node.remove(k(key)) }

    companion object {
        /** Test hook: a scratch root instead of the real user node. */
        internal var rootOverride: Preferences? = null

        private fun root(): Preferences =
            rootOverride ?: Preferences.userRoot().node("app/pgpony/desktop/kv")

        /** One process-wide install. multiProcess has no meaning here: java.util.prefs is
         *  read through on every get, so every desktop process sees the current value. */
        fun install() {
            SettingsStores.install { name, _ -> DesktopPrefsSettings(root().node(name)) }
        }
    }
}

// DesktopProxyPrefs.kt — DESKTOP TWIN of network/ProxyPrefs.kt (vendored copy excluded:
// SharedPreferences). Same `object ProxyPrefs`, same constants, same Config, same
// effectiveBaseUrl onion-mirror rewrite — backed by java.util.prefs. Params are typed to the
// PGPonyApp shim so vendored call sites (`ProxyPrefs.x(PGPonyApp.instance)`) compile unchanged.
// MODE_ORBOT survives as the "local Tor daemon" mode (127.0.0.1:9050) — the desktop UI labels
// it "Tor"; Orbot install detection has no desktop meaning and is dropped.

package com.pgpony.android.network

import com.pgpony.android.PGPonyApp
import java.util.prefs.Preferences

object ProxyPrefs {

    const val KEY_MODE = "proxy_mode"                 // "off" | "orbot" | "custom"
    const val KEY_CUSTOM_HOST = "proxy_custom_host"
    const val KEY_CUSTOM_PORT = "proxy_custom_port"
    const val KEY_ONION_MIRROR = "proxy_onion_mirror"

    const val MODE_OFF = "off"
    const val MODE_ORBOT = "orbot"                    // desktop: local Tor daemon
    const val MODE_CUSTOM = "custom"

    const val ORBOT_HOST = "127.0.0.1"
    const val ORBOT_PORT = 9050

    /** keys.pgpony.app's onion; /pks and /vks live under it. */
    const val PGPONY_ONION_BASE =
        "http://pgponyisur7gxcrfw5ofpjr2sepqul3zgbs66rrd3ughk5qvi4a3t5id.onion"
    const val PGPONY_CLEARNET_HOST = "keys.pgpony.app"

    data class Config(
        val mode: String,
        val host: String?,
        val port: Int,
        val onionMirror: Boolean
    ) {
        val enabled: Boolean get() = mode != MODE_OFF
        /** A stable signature so HttpClientFactory rebuilds only on change. */
        val signature: String get() = "$mode|$host|$port"
    }

    /** Test hook — lets the suite point at a scratch node instead of the real one. */
    internal var prefsOverride: Preferences? = null

    private fun prefs(): Preferences =
        prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    fun config(context: PGPonyApp): Config {
        val p = prefs()
        val mode = p.get(KEY_MODE, MODE_OFF)
        return when (mode) {
            MODE_ORBOT -> Config(mode, ORBOT_HOST, ORBOT_PORT, onionMirror(context))
            MODE_CUSTOM -> Config(
                mode,
                p.get(KEY_CUSTOM_HOST, "").ifBlank { null },
                p.getInt(KEY_CUSTOM_PORT, ORBOT_PORT),
                onionMirror(context)
            )
            else -> Config(MODE_OFF, null, 0, false)
        }
    }

    fun onionMirror(context: PGPonyApp): Boolean = prefs().getBoolean(KEY_ONION_MIRROR, true)

    fun setMode(context: PGPonyApp, mode: String) = prefs().put(KEY_MODE, mode)

    fun setCustom(context: PGPonyApp, host: String, port: Int) {
        prefs().put(KEY_CUSTOM_HOST, host)
        prefs().putInt(KEY_CUSTOM_PORT, port)
    }

    fun setOnionMirror(context: PGPonyApp, enabled: Boolean) =
        prefs().putBoolean(KEY_ONION_MIRROR, enabled)

    /**
     * Rewrite a server base URL to its onion when a proxy is active and the onion mirror is
     * on — only for the first-party keys.pgpony.app. Leaves everything else untouched.
     */
    fun effectiveBaseUrl(context: PGPonyApp, baseUrl: String): String {
        val cfg = config(context)
        if (!cfg.enabled || !cfg.onionMirror) return baseUrl
        return if (baseUrl.contains(PGPONY_CLEARNET_HOST)) PGPONY_ONION_BASE else baseUrl
    }
}

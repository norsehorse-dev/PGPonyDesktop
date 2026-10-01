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
    // proxy stream isolation: optional SOCKS5 user/pass. Blank = no auth.
    // Applies to whichever proxy is active (Tor or Custom). A distinct
    // user/pass pair puts PGPony on its own Tor circuit (IsolateSOCKSAuth).
    const val KEY_PROXY_USER = "proxy_socks_user"
    const val KEY_PROXY_PASS = "proxy_socks_pass"

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
        val onionMirror: Boolean,
        val username: String? = null,
        val password: String? = null
    ) {
        val enabled: Boolean get() = mode != MODE_OFF
        /** True when SOCKS5 user/pass auth should be offered to the proxy. */
        val hasAuth: Boolean get() = !username.isNullOrEmpty() && !password.isNullOrEmpty()
        /** A stable signature so HttpClientFactory rebuilds only on change.
         *  Credentials are folded in so a user/pass change rebuilds the client
         *  (and re-scopes the SOCKS Authenticator). In-memory only, never logged. */
        val signature: String get() = "$mode|$host|$port|$username|${password?.length ?: 0}"
    }

    /** Test hook — lets the suite point at a scratch node instead of the real one. */
    internal var prefsOverride: Preferences? = null

    private fun prefs(): Preferences =
        prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    fun config(context: PGPonyApp): Config {
        val p = prefs()
        val mode = p.get(KEY_MODE, MODE_OFF)
        val user = p.get(KEY_PROXY_USER, "").ifBlank { null }
        val pass = p.get(KEY_PROXY_PASS, "").ifBlank { null }
        return when (mode) {
            MODE_ORBOT -> Config(mode, ORBOT_HOST, ORBOT_PORT, onionMirror(context), user, pass)
            MODE_CUSTOM -> Config(
                mode,
                p.get(KEY_CUSTOM_HOST, "").ifBlank { null },
                p.getInt(KEY_CUSTOM_PORT, ORBOT_PORT),
                onionMirror(context),
                user,
                pass
            )
            else -> Config(MODE_OFF, null, 0, false)
        }
    }

    // Off unless turned on, as on Android (ProxyPrefs.onionMirror explains why).
    fun onionMirror(context: PGPonyApp): Boolean = prefs().getBoolean(KEY_ONION_MIRROR, false)

    fun setMode(context: PGPonyApp, mode: String) = prefs().put(KEY_MODE, mode)

    fun setCustom(context: PGPonyApp, host: String, port: Int) {
        prefs().put(KEY_CUSTOM_HOST, host)
        prefs().putInt(KEY_CUSTOM_PORT, port)
    }

    fun setOnionMirror(context: PGPonyApp, enabled: Boolean) =
        prefs().putBoolean(KEY_ONION_MIRROR, enabled)

    /** Set the SOCKS5 user/pass (blank clears). Caller should invalidate the
     *  shared client so the change takes effect immediately. */
    fun setCredentials(context: PGPonyApp, username: String, password: String) {
        prefs().put(KEY_PROXY_USER, username)
        prefs().put(KEY_PROXY_PASS, password)
    }

    fun username(context: PGPonyApp): String = prefs().get(KEY_PROXY_USER, "")
    fun password(context: PGPonyApp): String = prefs().get(KEY_PROXY_PASS, "")

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

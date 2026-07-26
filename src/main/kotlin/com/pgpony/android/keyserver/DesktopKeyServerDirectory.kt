// DesktopKeyServerDirectory.kt — DESKTOP TWIN of keyserver/KeyServerDirectory.kt (vendored copy
// excluded: Context + DataStore). Declares the same `data class KeyServer` — VERBATIM, including
// mayNotAccept (the R5 key-type warning) and the org.json codec — and the same
// `class KeyServerDirectory` API surface over java.util.prefs. File name differs from the
// excluded file (D1 Fix1 rule); params are typed to the PGPonyApp shim so vendored call sites
// (`KeyServerDirectory.get(PGPonyApp.instance).readOnce()`, `KeyServerDirectory.ID_OPENPGP`)
// compile unchanged. Divergences from upstream, both deliberate:
//   • no serversFlow — DataStore observability has no desktop consumer; every vendored caller
//     uses readOnce(), and the Settings screen re-reads after each mutation.
//   • prefsOverride test hook (the DesktopProxyPrefs pattern) so the suite runs on an
//     in-memory Preferences node instead of the user's real prefs tree.

package com.pgpony.android.keyserver

import com.pgpony.android.PGPonyApp
import com.pgpony.android.crypto.KeyAlgorithm
import org.json.JSONArray
import org.json.JSONObject
import java.util.prefs.Preferences

/**
 * One key server in the ordered directory. Field-for-field the Android data class — the
 * persisted JSON is interchangeable, so a future settings backup/restore can carry the list
 * across platforms.
 */
data class KeyServer(
    val id: String,
    val label: String,
    val baseUrl: String,
    val isFirstParty: Boolean,
    val lookupEnabled: Boolean,
    val publishEnabled: Boolean,
    val acceptsAllKeyTypes: Boolean
) {
    /**
     * R5: is this server likely to REJECT [algorithm]? A verified-email VKS like
     * keys.openpgp.org (RFC 9580, no PQC/LibrePGP, v6 unconfirmed) is flagged for anything
     * that isn't RSA or v4 Ed25519. Servers that accept everything (first-party, custom)
     * never flag.
     */
    fun mayNotAccept(algorithm: KeyAlgorithm): Boolean {
        if (acceptsAllKeyTypes) return false
        return when (algorithm) {
            KeyAlgorithm.RSA_2048,
            KeyAlgorithm.RSA_4096,
            KeyAlgorithm.ED25519_CV25519 -> false
            else -> true // v6 variants (and future composite PQC) → flag
        }
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("label", label)
        put("baseUrl", baseUrl)
        put("isFirstParty", isFirstParty)
        put("lookupEnabled", lookupEnabled)
        put("publishEnabled", publishEnabled)
        put("acceptsAllKeyTypes", acceptsAllKeyTypes)
    }

    companion object {
        fun fromJson(o: JSONObject): KeyServer = KeyServer(
            id = o.getString("id"),
            label = o.getString("label"),
            baseUrl = o.getString("baseUrl"),
            isFirstParty = o.optBoolean("isFirstParty", false),
            lookupEnabled = o.optBoolean("lookupEnabled", true),
            publishEnabled = o.optBoolean("publishEnabled", true),
            acceptsAllKeyTypes = o.optBoolean("acceptsAllKeyTypes", true)
        )
    }
}

class KeyServerDirectory private constructor() {

    companion object {
        const val ID_OPENPGP = "keys.openpgp.org"
        const val ID_PGPONY = "keys.pgpony.app"

        // Same key name as the Android stringPreferencesKey; node name mirrors the DataStore
        // file name so the two persistence worlds stay recognizably parallel.
        private const val LIST_KEY = "servers_json"
        private const val NODE = "app/pgpony/desktop/keyserver_directory"

        /** The seed list — order matters (lookup priority). Same two entries as Android. */
        val DEFAULTS: List<KeyServer> = listOf(
            KeyServer(
                id = ID_OPENPGP,
                label = "keys.openpgp.org",
                baseUrl = "https://keys.openpgp.org",
                isFirstParty = false,
                lookupEnabled = true,
                publishEnabled = true,
                // Verified-email VKS, no PQC/LibrePGP, v6 unconfirmed → flag.
                acceptsAllKeyTypes = false
            ),
            KeyServer(
                id = ID_PGPONY,
                label = "keys.pgpony.app",
                baseUrl = "https://keys.pgpony.app",
                isFirstParty = true,
                lookupEnabled = true,
                publishEnabled = true,
                acceptsAllKeyTypes = true
            )
        )

        /** Test hook — lets the suite point at a scratch node instead of the real one. */
        internal var prefsOverride: Preferences? = null

        @Volatile
        private var instance: KeyServerDirectory? = null

        fun get(context: PGPonyApp): KeyServerDirectory =
            instance ?: synchronized(this) {
                instance ?: KeyServerDirectory().also { instance = it }
            }
    }

    private fun prefs(): Preferences =
        prefsOverride ?: Preferences.userRoot().node(NODE)

    suspend fun save(servers: List<KeyServer>) {
        val arr = JSONArray()
        servers.forEach { arr.put(it.toJson()) }
        prefs().put(LIST_KEY, arr.toString())
    }

    suspend fun setLookupEnabled(id: String, enabled: Boolean) =
        update { s -> if (s.id == id) s.copy(lookupEnabled = enabled) else s }

    suspend fun setPublishEnabled(id: String, enabled: Boolean) =
        update { s -> if (s.id == id) s.copy(publishEnabled = enabled) else s }

    /** Move [id] up (toward higher lookup priority) or down by one slot. */
    suspend fun move(id: String, up: Boolean) {
        val list = readOnce().toMutableList()
        val i = list.indexOfFirst { it.id == id }
        if (i < 0) return
        val j = if (up) i - 1 else i + 1
        if (j < 0 || j >= list.size) return
        val tmp = list[i]; list[i] = list[j]; list[j] = tmp
        save(list)
    }

    suspend fun resetToDefaults() = save(DEFAULTS)

    private suspend fun update(transform: (KeyServer) -> KeyServer) {
        save(readOnce().map(transform))
    }

    /** Read the persisted list once (or DEFAULTS). Used by the repository, the refresh
     *  pipeline, and the Settings screen. */
    suspend fun readOnce(): List<KeyServer> =
        prefs().get(LIST_KEY, null)?.let { parse(it) } ?: DEFAULTS

    private fun parse(json: String): List<KeyServer> = try {
        val arr = JSONArray(json)
        (0 until arr.length()).map { KeyServer.fromJson(arr.getJSONObject(it)) }
            .ifEmpty { DEFAULTS }
    } catch (e: Exception) {
        DEFAULTS
    }
}

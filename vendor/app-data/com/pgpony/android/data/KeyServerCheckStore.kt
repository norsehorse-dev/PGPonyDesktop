// KeyServerCheckStore.kt
// PGPony Android 4.7.0 (item 60, #90): the last key server check of each key,
// with the server it asked and what it answered.
//
// Check Key Server showed "published" or "not found" for a few seconds and
// named no server; Key Details kept only the date. The answer is kept here
// so the Details section can show it. A check that failed (no network, a
// server error) is not an answer and leaves the last one in place.

package com.pgpony.android.data

import com.pgpony.android.data.settings.SettingsStores
import org.json.JSONObject

object KeyServerCheckStore {

    data class Result(val server: String, val found: Boolean, val atMs: Long)

    private fun key(fingerprint: String) = "keyserver_check_${fingerprint.lowercase()}"

    private fun prefsOrNull() = SettingsStores.open(SettingsStores.APP_PREFS)

    fun last(fingerprint: String): Result? {
        val raw = prefsOrNull()?.getString(key(fingerprint), null) ?: return null
        return runCatching {
            val o = JSONObject(raw)
            Result(o.getString("server"), o.getBoolean("found"), o.getLong("at"))
        }.getOrNull()
    }

    fun record(fingerprint: String, server: String, found: Boolean, atMs: Long = System.currentTimeMillis()) {
        val p = prefsOrNull() ?: return
        p.putString(key(fingerprint), JSONObject().put("server", server).put("found", found).put("at", atMs).toString())
    }

    /** Forget the record for [fingerprint], e.g. when the key is purged. */
    fun clear(fingerprint: String) {
        prefsOrNull()?.remove(key(fingerprint))
    }
}

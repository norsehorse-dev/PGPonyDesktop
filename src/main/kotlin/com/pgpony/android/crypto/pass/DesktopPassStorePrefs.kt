// DesktopPassStorePrefs.kt — DESKTOP TWIN of crypto/pass/PassStorePrefs.kt (vendored copy
// excluded: android.content.SharedPreferences). Same `object PassStorePrefs`, same
// "pass_stores_json" blob shape (so a store list written by either app reads the same), same
// load / save / upsert-by-treeUri / remove semantics — backed by java.util.prefs, on the same
// node the other desktop twins use (DesktopProxyPrefs, DesktopCardPinCache).
//
// FILE NAME must differ from the excluded PassStorePrefs.kt: Kotlin source-set excludes are
// SET-WIDE and would drop this file too (D1 Fix1).
//
// One divergence forced by the backing store: Preferences caps a single value at
// Preferences.MAX_VALUE_LENGTH (8192 chars). A pass-store list is a handful of entries, but a
// deep path plus a long .gpg-id set could in principle push past it, so save() trims the OLDEST
// stores until the blob fits rather than throwing an IllegalArgumentException out of a UI
// callback. Android's SharedPreferences has no such cap, hence no such trim.

package com.pgpony.android.crypto.pass

import org.json.JSONArray
import org.json.JSONObject
import java.util.prefs.Preferences

object PassStorePrefs {

    const val KEY_STORES = "pass_stores_json"

    /** Test hook — lets the suite point at a scratch node instead of the real one. */
    internal var prefsOverride: Preferences? = null

    private fun prefs(): Preferences =
        prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    fun load(): List<PassStoreRef> {
        val json = prefs().get(KEY_STORES, null) ?: return emptyList()
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                val ids = o.optJSONArray("rootGpgIds")
                PassStoreRef(
                    id = o.getString("id"),
                    displayName = o.getString("displayName"),
                    treeUri = o.getString("treeUri"),
                    rootGpgIds = if (ids != null) (0 until ids.length()).map { ids.getString(it) } else emptyList()
                )
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun save(stores: List<PassStoreRef>) {
        // Trim from the FRONT (oldest first) until the serialized blob fits the Preferences
        // value cap. The newest store is the one the user just added, so it must survive.
        var kept = stores
        var blob = encode(kept)
        while (blob.length > Preferences.MAX_VALUE_LENGTH && kept.size > 1) {
            kept = kept.drop(1)
            blob = encode(kept)
        }
        prefs().put(KEY_STORES, blob)
    }

    private fun encode(stores: List<PassStoreRef>): String {
        val arr = JSONArray()
        for (s in stores) {
            arr.put(
                JSONObject().apply {
                    put("id", s.id)
                    put("displayName", s.displayName)
                    put("treeUri", s.treeUri)
                    put("rootGpgIds", JSONArray(s.rootGpgIds))
                }
            )
        }
        return arr.toString()
    }

    /** Add or replace a store (matched by treeUri so re-picking the same folder updates in place). */
    fun upsert(ref: PassStoreRef): List<PassStoreRef> {
        val current = load().filterNot { it.treeUri == ref.treeUri }
        val updated = current + ref
        save(updated)
        return updated
    }

    fun remove(id: String): List<PassStoreRef> {
        val updated = load().filterNot { it.id == id }
        save(updated)
        return updated
    }
}

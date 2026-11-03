// SigningSubkeyPins.kt
// PGPony Android, 4.7.0 (item 46, #82)
//
// Which signing subkey a key pair signs with when its owner has chosen one
// on Key Details (Use for signing). Item 39 signs with the newest valid
// signing subkey; a pinned subkey goes first instead while it is still a
// valid signer, and once it expires or is revoked the automatic pick takes
// over again on its own.
//
// Stored in files/signing_pins, one "PRIMARY SUBKEY" fingerprint pair per
// line, written atomically and read on every pick. Signing runs in the main
// process and in :remote_api (mail apps), and a file that every read goes to
// has no per-process copy to go stale (the SessionPolicy reasoning).
// Removed with the key when it is purged, and by Clear All Data.

package com.pgpony.android.crypto

import java.io.File

object SigningSubkeyPins {

    const val FILE = "signing_pins"

    /** Test hook: the directory the file lives in. Null means the app's filesDir. */
    @Volatile
    internal var dirOverride: File? = null

    private fun dir(): File? = dirOverride
        ?: runCatching { com.pgpony.android.PGPonyApp.instance.filesDir }.getOrNull()

    private fun norm(fp: String) = fp.filterNot { it.isWhitespace() }.uppercase()

    private fun isFingerprint(fp: String) =
        (fp.length == 40 || fp.length == 64) && fp.all { it in '0'..'9' || it in 'A'..'F' }

    /** The pins in [text]: primary fingerprint to subkey fingerprint, both normalized. */
    fun parse(text: String?): Map<String, String> {
        if (text.isNullOrBlank()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        text.lineSequence().forEach { line ->
            val parts = line.trim().split(' ').filter { it.isNotEmpty() }
            if (parts.size != 2) return@forEach
            val primary = norm(parts[0])
            val subkey = norm(parts[1])
            if (isFingerprint(primary) && isFingerprint(subkey)) out[primary] = subkey
        }
        return out
    }

    fun format(pins: Map<String, String>): String =
        pins.entries.joinToString("") { (primary, subkey) -> "$primary $subkey\n" }

    private fun read(): Map<String, String> {
        val d = dir() ?: return emptyMap()
        return runCatching { File(d, FILE).takeIf { it.isFile }?.readText() }.getOrNull().let { parse(it) }
    }

    private fun write(pins: Map<String, String>) {
        val d = dir() ?: return
        val target = File(d, FILE)
        if (pins.isEmpty()) {
            target.delete()
            return
        }
        val tmp = File(d, "$FILE.tmp")
        tmp.writeText(format(pins))
        if (!tmp.renameTo(target)) {
            target.writeText(format(pins))
            tmp.delete()
        }
    }

    /** The subkey fingerprint pinned for the key pair with [primaryFingerprint], if any. */
    fun pinnedFor(primaryFingerprint: String): String? = read()[norm(primaryFingerprint)]

    /** Pin [subkeyFingerprint] for [primaryFingerprint], or go back to automatic with null. */
    @Synchronized
    fun set(primaryFingerprint: String, subkeyFingerprint: String?) {
        val pins = read().toMutableMap()
        val primary = norm(primaryFingerprint)
        if (subkeyFingerprint == null) pins.remove(primary) else {
            val subkey = norm(subkeyFingerprint)
            if (!isFingerprint(primary) || !isFingerprint(subkey)) return
            pins[primary] = subkey
        }
        write(pins)
    }

    /** Forget the pin of a key that is being purged. */
    fun clear(primaryFingerprint: String) = set(primaryFingerprint, null)

    /** Clear All Data. */
    fun clearAll() {
        val d = dir() ?: return
        File(d, FILE).delete()
        File(d, "$FILE.tmp").delete()
    }

    /**
     * [keys] (the valid signers in automatic order) with the pinned one moved
     * to the front, when [pinnedFingerprint] is one of them; otherwise [keys]
     * unchanged. [fingerprintOf] reads a key's fingerprint.
     */
    fun <T> applyPin(keys: List<T>, pinnedFingerprint: String?, fingerprintOf: (T) -> String): List<T> {
        val pin = pinnedFingerprint?.let { norm(it) } ?: return keys
        val pinned = keys.firstOrNull { norm(fingerprintOf(it)) == pin } ?: return keys
        return listOf(pinned) + keys.filter { it !== pinned }
    }
}

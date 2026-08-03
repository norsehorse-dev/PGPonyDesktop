// WatchRule.kt
// PGPony Desktop — D18 (2.0.0 §3c): watch-folder rules, model + pure logic.
//
// A rule is: folder + glob + recipients → encrypt arrivals. ENCRYPT-ONLY by design, and that
// is the whole security argument: encryption needs only PUBLIC keys, so an unattended rule
// never holds a passphrase, never touches a PIN, and a tampered rules file can at worst
// encrypt things to keys already in the keyring. Sign and decrypt stay interactive, forever —
// there is no field on a rule that could ask for a secret. This file holds the serializable
// model, its JSON store, the master on/off preference, and the two pieces of pure logic worth
// testing on their own (the glob matcher and the quiesce tracker); WatchFolderService owns the
// WatchService thread.

package com.pgpony.desktop

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.prefs.Preferences

/**
 * One watch rule. [id] is a stable handle for the UI list and the outcomes log. [recipients]
 * are keyring fingerprints (public material is resolved at encrypt time). [outputDir] null =
 * beside the source. [deleteOriginal] defaults OFF — an unattended delete is the one
 * irreversible thing a rule could do, so it is never the default.
 */
@Serializable
data class WatchRule(
    val id: String,
    val folder: String,
    val glob: String = "*",
    val recipients: List<String> = emptyList(),
    val outputDir: String? = null,
    val deleteOriginal: Boolean = false,
    val armor: Boolean = false,
    val enabled: Boolean = true
) {
    /** True when [filename] (the name alone, no directory) matches this rule's glob. */
    fun matches(filename: String): Boolean = globMatches(glob, filename)

    val folderPath: Path get() = Paths.get(folder)
    val outputPath: Path? get() = outputDir?.let { Paths.get(it) }

    companion object {
        /**
         * Match a bare filename against a glob, via the platform PathMatcher (`glob:` syntax:
         * `*`, `?`, `[...]`, `{a,b}`). Rules glob a filename, not a path, so a pattern with a
         * `/` never matches — which is the intent, since arrivals are matched by name. A
         * malformed pattern matches nothing rather than throwing (a bad rule is inert, not fatal).
         */
        fun globMatches(glob: String, filename: String): Boolean = try {
            FileSystems.getDefault().getPathMatcher("glob:$glob").matches(Paths.get(filename))
        } catch (_: Exception) {
            false
        }
    }
}

/** The persisted rule set. A version field lets a future format migrate rather than guess. */
@Serializable
data class WatchRules(val version: Int = 1, val rules: List<WatchRule> = emptyList())

object WatchRulesStore {
    private const val KEY_ENABLED = "watch_folders_enabled"

    /** Test hooks — same pattern as the other desktop prefs objects. */
    internal var prefsOverride: Preferences? = null
    internal var fileOverride: Path? = null

    private fun prefs(): Preferences =
        prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    private fun file(): Path = fileOverride ?: Config.dataDir.resolve("watch-rules.json")

    private val JSON = Json { prettyPrint = true; prettyPrintIndent = "  "; ignoreUnknownKeys = true }

    /** Master switch — OFF by default (the unattended-feature posture: agent, sentinel, this). */
    fun enabled(): Boolean = runCatching { prefs().getBoolean(KEY_ENABLED, false) }.getOrDefault(false)

    fun setEnabled(value: Boolean) {
        runCatching { prefs().putBoolean(KEY_ENABLED, value) }
    }

    /** Load the rule set; a missing or corrupt file is an empty set, never an exception. */
    fun load(): WatchRules = try {
        val f = file()
        if (Files.exists(f)) JSON.decodeFromString(WatchRules.serializer(), Files.readString(f))
        else WatchRules()
    } catch (_: Exception) {
        WatchRules()
    }

    fun save(rules: WatchRules) {
        runCatching {
            val f = file()
            Files.createDirectories(f.parent)
            Files.writeString(f, JSON.encodeToString(WatchRules.serializer(), rules))
        }
    }

    /** Convenience mutators the Settings UI uses; each persists immediately. */
    fun add(rule: WatchRule): WatchRules =
        load().let { it.copy(rules = it.rules + rule).also(::save) }

    fun remove(id: String): WatchRules =
        load().let { it.copy(rules = it.rules.filterNot { r -> r.id == id }).also(::save) }

    fun setRuleEnabled(id: String, enabled: Boolean): WatchRules =
        load().let { cur ->
            cur.copy(rules = cur.rules.map { if (it.id == id) it.copy(enabled = enabled) else it })
                .also(::save)
        }
}

/**
 * The quiesce heuristic: a file is only encrypted once its size has held steady across two
 * consecutive observations, so a half-copied arrival isn't eaten mid-write. Pure and testable —
 * [observe] returns true exactly on the tick where a path first becomes stable, false while it
 * is still growing or already handled. Stateful across calls; [forget] drops a path once acted
 * on (or removed) so the same file can be seen fresh if it reappears.
 */
class QuiesceTracker(private val stableTicksRequired: Int = 2) {
    private data class Track(var lastSize: Long, var stableCount: Int, var fired: Boolean)

    private val seen = HashMap<Path, Track>()

    /** Record [path] at [size]; true once it has been the same size for the required ticks. */
    fun observe(path: Path, size: Long): Boolean {
        val t = seen[path]
        if (t == null) {
            seen[path] = Track(size, 1, false)
            return stableTicksRequired <= 1
        }
        if (t.fired) return false
        if (size == t.lastSize) {
            t.stableCount++
            if (t.stableCount >= stableTicksRequired) {
                t.fired = true
                return true
            }
        } else {
            t.lastSize = size
            t.stableCount = 1
        }
        return false
    }

    fun forget(path: Path) {
        seen.remove(path)
    }

    fun tracked(): Set<Path> = seen.keys.toSet()
}

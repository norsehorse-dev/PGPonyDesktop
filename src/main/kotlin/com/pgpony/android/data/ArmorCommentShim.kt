// ArmorCommentShim.kt
// PGPony Desktop vendor shim for Android's data/ArmorCommentSettings.kt (excluded: DataStore +
// Context).
//
// The vendored crypto layer (PGPCryptoService, SigningService, CardSigningService) reads the
// armor "Comment:" header from ArmorCommentHeader. This file reproduces the objects it consumes,
// with the same defaults, and (3.0.0, plan section 7) the desktop store behind them:
// ArmorCommentPrefs keeps the two toggles and the text in java.util.prefs and pushes validated
// values into the cache. Every face of the binary (GUI, CLI, git shim, watch folders) calls
// ArmorCommentPrefs.load() at startup from Main.main, so a second process can never keep the
// default the way Android's provider process did before 4.5.3 (#57). The validator is Android's
// ArmorCommentValidator rules, reproduced here because its file is excluded.

package com.pgpony.android.data

object ArmorCommentDefaults {
    /** Default Comment text — matches Android's ArmorCommentDefaults verbatim. */
    const val DEFAULT_COMMENT: String = "PGPony - PGPony.app"
}

/** Synchronous cache read by the crypto layer. Same contract as the Android original. */
object ArmorCommentHeader {
    /** Validated Comment for message-style armored output, or null for "no Comment header". */
    @Volatile
    var current: String? = ArmorCommentDefaults.DEFAULT_COMMENT

    /** Validated Comment for user-facing PUBLIC KEY exports (ForSharing path), or null. */
    @Volatile
    var pubkeyCurrent: String? = ArmorCommentDefaults.DEFAULT_COMMENT
}

/** Android ArmorCommentValidator: one printable line, no leading colon, at most 80 chars. */
object ArmorCommentValidator {
    const val MAX_LENGTH: Int = 80

    fun sanitize(raw: String): String {
        val printable = raw.filterNot { it == '\r' || it == '\n' || it.isISOControl() }
        var s = printable.trimStart()
        while (s.startsWith(":")) s = s.removePrefix(":").trimStart()
        s = s.trim()
        if (s.length > MAX_LENGTH) {
            var cut = s.substring(0, MAX_LENGTH)
            if (cut.isNotEmpty() && Character.isHighSurrogate(cut.last())) cut = cut.dropLast(1)
            s = cut.trimEnd()
        }
        return s
    }

    /** Null means no Comment header: toggle off, or nothing left after sanitizing. */
    fun validate(include: Boolean, raw: String): String? = if (!include) null else sanitize(raw).ifEmpty { null }
}

/** 3.0.0: the desktop store for the Comment header (Android ArmorCommentStore's settings). */
object ArmorCommentPrefs {
    const val KEY_INCLUDE = "armor_comment_include"
    const val KEY_PUBKEY_INCLUDE = "armor_comment_pubkey_include"
    const val KEY_TEXT = "armor_comment_text"

    internal var prefsOverride: java.util.prefs.Preferences? = null
    private fun prefs(): java.util.prefs.Preferences =
        prefsOverride ?: java.util.prefs.Preferences.userRoot().node("app/pgpony/desktop")

    fun include(): Boolean = runCatching { prefs().getBoolean(KEY_INCLUDE, true) }.getOrDefault(true)
    fun pubkeyInclude(): Boolean = runCatching { prefs().getBoolean(KEY_PUBKEY_INCLUDE, true) }.getOrDefault(true)
    fun text(): String = runCatching { prefs().get(KEY_TEXT, ArmorCommentDefaults.DEFAULT_COMMENT) }
        .getOrDefault(ArmorCommentDefaults.DEFAULT_COMMENT)

    fun setInclude(on: Boolean) = write { putBoolean(KEY_INCLUDE, on) }
    fun setPubkeyInclude(on: Boolean) = write { putBoolean(KEY_PUBKEY_INCLUDE, on) }
    fun setText(text: String) = write { put(KEY_TEXT, text) }

    private fun write(block: java.util.prefs.Preferences.() -> Unit) {
        runCatching { prefs().block(); prefs().flush() }
        load()
    }

    /** Push the stored settings into [ArmorCommentHeader]. Called at startup and after a change. */
    fun load() {
        val text = text()
        ArmorCommentHeader.current = ArmorCommentValidator.validate(include(), text)
        ArmorCommentHeader.pubkeyCurrent = ArmorCommentValidator.validate(pubkeyInclude(), text)
    }
}

// Strings.kt
// PGPony Desktop — D11: localization.
//
// WHY THIS LOOKS LIKE ANDROID
// ===========================
// The Android app carries 1,193 keys translated into de / es / fr / ja / pt-BR, with the
// terminology already settled per locale (what "keypair", "fingerprint", "subkey", "passphrase"
// are called in German, and so on) and a native-review triage running against them. Inventing a
// second vocabulary here would make the same app read differently on two platforms for no gain.
//
// So the six `strings.xml` files are VENDORED VERBATIM under vendor/app-strings/, exactly like
// the crypto source: byte-identical to Android's, never hand-edited here, refreshed with
// tools/sync-strings.sh. Desktop-only wording (PC/SC readers, file associations, window and
// menu-bar text, the pass store's desktop framing) lives in a SECOND, desktop-owned layer under
// i18n/, in the same file format. Which layer owns a key is decided by the BASE (English) file:
// if i18n/values/strings.xml declares it, the desktop layer owns it and the Android files are
// never consulted for it. That keeps overrides explicit and keeps a stray Android key from
// quietly shadowing a desktop one after a sync.
//
// Android's `strings.xml` format is a good fit for a plain-JVM app: the placeholders (`%1$s`,
// `%2$d`) are literally java.util.Formatter syntax, so parameterized strings port with zero
// rewriting, and the parity/placeholder audit script from the Android repo runs against these
// files unchanged (tools/i18n-audit.py).
//
// NOT Compose Multiplatform resources, deliberately. Two reasons: this is a plain `kotlin("jvm")`
// module (see build.gradle.kts) rather than a multiplatform one, and CMP resources resolve
// against the SYSTEM locale with no supported in-app override — but an in-app language picker is
// a D11 requirement, because a user who wants PGPony in German on an English desktop is exactly
// the person this feature is for.
//
// LIVE SWITCHING
// ==============
// [I18n.language] is Compose snapshot state, and `tr()` reads it. A snapshot read is recorded by
// whatever observer is active, so calling the plain (non-@Composable) `tr()` from inside a
// composable still subscribes that composable to language changes — the whole UI re-renders on
// the frame the picker changes. Outside composition it is just a map lookup.
//
// Nothing here throws. A missing key returns the key itself, which is loud in the UI and shows up
// in a screenshot, and a malformed format string returns the unformatted template rather than
// killing a screen over a translator's typo.

package com.pgpony.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.util.Locale
import java.util.prefs.Preferences
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element

object I18n {

    /** Settings value meaning "follow the OS". */
    const val SYSTEM = "system"

    const val KEY_LANGUAGE = "ui_language"

    /**
     * The languages that have a complete translation. English is the base and always present;
     * the other five are the locales Android ships. Order is the picker's order.
     */
    val SUPPORTED = listOf("en", "de", "es", "fr", "ja", "pt-BR")

    /** Endonyms — a language picker that names languages in a language you can't read is a joke. */
    val DISPLAY_NAMES = mapOf(
        "en" to "English",
        "de" to "Deutsch",
        "es" to "Español",
        "fr" to "Français",
        "ja" to "日本語",
        "pt-BR" to "Português (Brasil)"
    )

    /** Test hook — a scratch node instead of the real one. */
    internal var prefsOverride: Preferences? = null

    private fun prefs(): Preferences =
        prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    /**
     * The stored preference: [SYSTEM] or a tag from [SUPPORTED]. Compose snapshot state, so the
     * picker moves the whole UI on the next frame (see the header note on `tr()`).
     */
    var language: String by mutableStateOf(SYSTEM)
        private set

    /** The tag actually in use — [language] with [SYSTEM] resolved against the JVM default. */
    val effective: String
        get() = if (language == SYSTEM) systemMatch() else language

    /** Load the stored preference. Called once at startup, before the first frame. */
    fun init() {
        val stored = runCatching { prefs().get(KEY_LANGUAGE, SYSTEM) }.getOrNull() ?: SYSTEM
        language = if (stored == SYSTEM || stored in SUPPORTED) stored else SYSTEM
    }

    /**
     * Change the language and persist it. NOT named `setLanguage`: [language] is a `var`, and a
     * `private set` still emits `setLanguage(Ljava/lang/String;)V` on the JVM, so that name is
     * already taken and a hand-written twin is a platform declaration clash. (Same trap as
     * `showPassStore` in D8.)
     */
    fun selectLanguage(tag: String) {
        val next = if (tag == SYSTEM || tag in SUPPORTED) tag else SYSTEM
        runCatching { prefs().put(KEY_LANGUAGE, next) }
        language = next
    }

    /**
     * Pin THIS PROCESS to English without persisting anything — the CLI entry point (see
     * Main.kt). The repository and the shared crypto/backup helpers are localized for the GUI,
     * and CLI output is scriptable; a script that greps the import summary must not depend on
     * which language the app window happens to be set to. Deliberately not routed through
     * [selectLanguage], which writes the preference.
     */
    fun pinEnglish() {
        language = "en"
    }

    /**
     * Best supported tag for the OS locale. Region matters for exactly one entry: Brazilian
     * Portuguese is translated and European Portuguese is not, so `pt_PT` falls back to English
     * rather than being shown Brazilian wording it didn't ask for.
     */
    fun systemMatch(default: Locale = Locale.getDefault()): String {
        val lang = default.language.lowercase()
        val country = default.country.uppercase()
        return when {
            lang == "pt" && country == "BR" -> "pt-BR"
            lang == "pt" -> "en"
            lang in SUPPORTED -> lang
            else -> "en"
        }
    }

    /**
     * The JVM Locale for a tag — used for number/date formatting inside `String.format`.
     * `forLanguageTag` (not `Locale.of`, which is Java 19+; this module targets 17) parses
     * BCP 47, so "pt-BR" arrives as pt_BR without a second code path.
     */
    fun localeOf(tag: String): Locale = Locale.forLanguageTag(tag)

    /**
     * CLDR cardinal plural category for an integer [count] in the language of [tag].
     *
     * A hand-written rule table over the CLDR data — the same trade `systemMatch` makes, a
     * `when` instead of an ICU4J dependency — and integer rules only, because every count this
     * app pluralizes is a whole number of keys, files, or bytes. The rows worth reading twice:
     * French and Brazilian Portuguese put 0 with the singular (CLDR: «0 fichier», not
     * «0 fichiers»), which the old `count == 1` branch got wrong; and Russian is in the table
     * ahead of `values-ru` landing, because its `one`/`few`/`many` split over the final digit
     * (21 → `one`, 3 → `few`, 5 and 11 → `many`) is the entire reason the two-way branch had
     * to die (2.0.0 plan §4).
     *
     * Unknown languages take the English row, and a category the translation file doesn't
     * carry degrades sideways to that language's `other` in [pluralTemplate] — so a wrong row
     * here mislabels a count, but never blanks a screen and never leaks another language.
     */
    fun pluralCategory(tag: String, count: Long): String {
        // CLDR rules operate on |n|. Long.MIN_VALUE has no positive twin, so nudge it first.
        val n = kotlin.math.abs(if (count == Long.MIN_VALUE) count + 1 else count)
        val mod10 = (n % 10).toInt()
        val mod100 = (n % 100).toInt()
        return when (localeOf(tag).language) {
            "ja" -> "other"
            "fr", "pt" -> if (n < 2) "one" else "other"
            "ru" -> when {
                mod10 == 1 && mod100 != 11 -> "one"
                mod10 in 2..4 && mod100 !in 12..14 -> "few"
                else -> "many"
            }
            // en, de, es — also the rule the English base files are written against.
            else -> if (n == 1L) "one" else "other"
        }
    }

    // ── Resource layers ────────────────────────────────────────────────────

    /**
     * Where a tag's file lives in each layer. Android's resource-qualifier spelling is kept
     * as-is so the vendored files stay byte-identical to the Android repo's.
     */
    private fun dirFor(tag: String): String = when (tag) {
        "en" -> "values"
        "pt-BR" -> "values-pt-rBR"
        else -> "values-$tag"
    }

    /** The vendored Android layer (1,193 keys × 6 locales) — read-only, refreshed by sync. */
    const val ANDROID_LAYER = "/i18n/android"

    /** The desktop-owned layer: strings this app has and Android doesn't. */
    const val DESKTOP_LAYER = "/i18n/desktop"

    private val cache = HashMap<String, Map<String, String>>()

    @Synchronized
    private fun table(layer: String, tag: String): Map<String, String> =
        cache.getOrPut("$layer:$tag") { parse("$layer/${dirFor(tag)}/strings.xml") }

    /**
     * Read one `strings.xml` off the classpath. Plurals are flattened to `name/quantity` keys.
     * A missing or malformed file is an empty table, never an exception: a broken translation
     * must degrade to English, not take the app down.
     */
    private fun parse(path: String): Map<String, String> {
        val stream = I18n::class.java.getResourceAsStream(path) ?: return emptyMap()
        return try {
            val factory = DocumentBuilderFactory.newInstance()
            // Our own files, but a parser that resolves external entities is never worth having.
            runCatching {
                factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            }
            factory.isExpandEntityReferences = false
            val doc = stream.use { factory.newDocumentBuilder().parse(it) }
            val out = HashMap<String, String>()
            val strings = doc.getElementsByTagName("string")
            for (i in 0 until strings.length) {
                val el = strings.item(i) as? Element ?: continue
                val name = el.getAttribute("name")
                if (name.isNullOrEmpty()) continue
                out[name] = unescape(el.textContent ?: "")
            }
            val plurals = doc.getElementsByTagName("plurals")
            for (i in 0 until plurals.length) {
                val el = plurals.item(i) as? Element ?: continue
                val name = el.getAttribute("name")
                if (name.isNullOrEmpty()) continue
                val items = el.getElementsByTagName("item")
                for (j in 0 until items.length) {
                    val item = items.item(j) as? Element ?: continue
                    val q = item.getAttribute("quantity")
                    if (q.isNullOrEmpty()) continue
                    out["$name/$q"] = unescape(item.textContent ?: "")
                }
            }
            out
        } catch (e: Exception) {
            emptyMap()
        }
    }

    /**
     * Android's backslash escapes. The current files use none of them, but translators add
     * `\'` and `\n` by reflex and a literal backslash in the UI is a bug report.
     */
    private fun unescape(raw: String): String {
        if (!raw.contains('\\')) return raw
        val sb = StringBuilder(raw.length)
        var i = 0
        while (i < raw.length) {
            val c = raw[i]
            if (c != '\\' || i == raw.length - 1) {
                sb.append(c)
                i++
                continue
            }
            when (val next = raw[i + 1]) {
                'n' -> sb.append('\n')
                't' -> sb.append('\t')
                '\'' -> sb.append('\'')
                '"' -> sb.append('"')
                '\\' -> sb.append('\\')
                'u' -> {
                    val hex = raw.substring(i + 2, minOf(i + 6, raw.length))
                    val cp = hex.toIntOrNull(16)
                    if (hex.length == 4 && cp != null) {
                        sb.append(cp.toChar())
                        i += 4
                    } else {
                        sb.append(next)
                    }
                }
                else -> sb.append(next)
            }
            i += 2
        }
        return sb.toString()
    }

    // ── Lookup ─────────────────────────────────────────────────────────────

    /**
     * Raw template for [key] in the current language, or null if no layer declares it.
     *
     * Ownership is decided by the English file: whichever layer declares the key in `values/`
     * owns it, and only that layer's translations are consulted. Within the owning layer the
     * chain is `<tag>` then English.
     */
    fun template(key: String): String? {
        val tag = effective
        val desktopOwns = table(DESKTOP_LAYER, "en").containsKey(key)
        val layer = if (desktopOwns) DESKTOP_LAYER else ANDROID_LAYER
        return table(layer, tag)[key] ?: table(layer, "en")[key]
    }

    /**
     * A `<plurals>` lookup, resolved WITHIN a language before falling back to English.
     *
     * [template] can't do this job: its chain is `<tag>` then English per key, so asking a
     * Japanese table for `.../one` — a form Japanese does not have, and its file therefore does
     * not carry — falls straight through to the ENGLISH `one` item and renders one label in
     * English inside an otherwise Japanese window. Quantity has to degrade sideways (to `other`
     * in the same language) before it degrades to another language.
     */
    private fun plural(key: String, quantity: String): String? {
        val tag = effective
        // Every base declares `other` for a plural, so that is the name to test ownership with.
        val desktopOwns = table(DESKTOP_LAYER, "en").containsKey("$key/other")
        val layer = if (desktopOwns) DESKTOP_LAYER else ANDROID_LAYER
        val localized = table(layer, tag)
        localized["$key/$quantity"]?.let { return it }
        localized["$key/other"]?.let { return it }
        val english = table(layer, "en")
        return english["$key/$quantity"] ?: english["$key/other"]
    }

    /** True when [key] exists in either layer — used by the audit test, not by the UI. */
    fun has(key: String): Boolean = template(key) != null

    /** [plural] for the tests; the UI reaches it through [trQuantity]. */
    internal fun pluralTemplate(key: String, quantity: String): String? = plural(key, quantity)

    /**
     * One layer's whole table for one tag. Exposed for `I18nTest` (key parity, placeholder
     * arity) — the UI has no reason to read a table wholesale.
     */
    fun tableOf(layer: String, tag: String): Map<String, String> = table(layer, tag)

    /** Endonym for the picker; unknown tags fall back to the tag itself rather than blank. */
    fun displayNameOf(tag: String): String = DISPLAY_NAMES[tag] ?: tag
}

// ── The call-site API ──────────────────────────────────────────────────────

/**
 * Look up [key] in the current language. A missing key returns the key itself: loud in the UI,
 * visible in a screenshot, and caught by the parity audit long before that.
 *
 * Not `@Composable` on purpose — it reads snapshot state, which subscribes the calling
 * composition automatically, and stays usable from services and dialogs that aren't composables.
 */
fun tr(key: String): String = I18n.template(key) ?: key

/**
 * Look up [key] and format it with [args] in the current locale — so a German build groups
 * thousands as `1.234` and a Japanese build formats dates the Japanese way, which
 * `String.format` without a Locale would not do (it would use the JVM default, which the
 * in-app picker deliberately does not change).
 *
 * A format string a translator broke returns the unformatted template instead of throwing.
 */
fun tr(key: String, vararg args: Any?): String {
    val template = I18n.template(key) ?: key
    if (args.isEmpty()) return template
    return try {
        String.format(I18n.localeOf(I18n.effective), template, *args)
    } catch (e: Exception) {
        template
    }
}

/**
 * A `<plurals>` lookup, routed through the CLDR selector [I18n.pluralCategory]: English,
 * German and Spanish split on exactly 1; French and Brazilian Portuguese put 0 with the
 * singular; Japanese has one category and its file carries only `other`, so a count of 1
 * there resolves to the Japanese `other` item rather than to English (see
 * [I18n.pluralTemplate]); Russian will want `one`/`few`/`many` the day `values-ru` lands.
 * A category a file doesn't carry degrades sideways the same way Japanese does, so no file
 * ever has to declare forms its language doesn't use. A plural no layer declares renders as
 * its own key, like [tr].
 *
 * [count] is passed to the formatter as the first argument, matching Android's
 * `getQuantityString(id, count, count)` convention at PGPony's single call site.
 */
fun trQuantity(key: String, count: Int, vararg args: Any?): String =
    trQuantity(key, count.toLong(), *args)

/**
 * The [Long] overload, for counts that are genuinely 64-bit — a decrypted byte total, say.
 * Narrowing those to [Int] would wrap past 2 GB and print a negative count, so the whole
 * lookup works in [Long] and the [Int] overload widens into it. `%d` formats either.
 */
fun trQuantity(key: String, count: Long, vararg args: Any?): String {
    val quantity = I18n.pluralCategory(I18n.effective, count)
    val template = I18n.pluralTemplate(key, quantity) ?: return key
    val all = if (args.isEmpty()) arrayOf<Any?>(count) else arrayOf<Any?>(count, *args)
    return try {
        String.format(I18n.localeOf(I18n.effective), template, *all)
    } catch (e: Exception) {
        template
    }
}

// I18nTest.kt
// D11 validation for the two-layer string system (src/main/kotlin/com/pgpony/desktop/Strings.kt).
//
// tools/i18n-audit.py audits the FILES on disk. This audits what the APP actually loads: the
// tables resolved off the classpath after build.gradle.kts has mounted vendor/app-strings/ at
// /i18n/android and i18n/ at /i18n/desktop. Those are different failure surfaces — a
// processResources wiring mistake leaves every file perfectly valid and every lookup returning
// the raw key — so both exist on purpose and neither replaces the other.
//
// The interesting test here is `everyKeyReferencedInSourceResolves`: it greps the desktop UI
// source for tr("…") literals and asserts each one is declared somewhere. That is the check that
// carries the D11b screen sweep — every screen converted after this file was written gets audited
// for typo'd keys automatically, with no list to maintain. (It scans text, so a tr("example") in
// a doc comment would be treated as a real reference. Don't write one.)
//
// Nothing here touches the real Preferences node: I18n.prefsOverride is pointed at the in-memory
// node MemoryPreferences from KeyServerDirectoryTest, and the language is restored afterwards
// because I18n.language is process-global state the rest of the suite reads through tr().

package com.pgpony.desktop

import java.io.File
import java.util.Locale
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class I18nTest {

    private lateinit var prefs: MemoryPreferences

    @BeforeTest
    fun hookPrefs() {
        prefs = MemoryPreferences()
        I18n.prefsOverride = prefs
        I18n.selectLanguage("en")
    }

    @AfterTest
    fun unhookPrefs() {
        I18n.selectLanguage(I18n.SYSTEM)
        I18n.prefsOverride = null
    }

    // ── Layer wiring ───────────────────────────────────────────────────────
    //
    // If processResources stops copying either tree, every one of these tables goes empty and
    // every lookup in the app silently degrades to the raw key. That is quiet enough to ship,
    // which is why it gets a test of its own rather than being assumed by the parity checks.

    @Test
    fun bothLayersAreOnTheClasspath() {
        val android = I18n.tableOf(I18n.ANDROID_LAYER, "en")
        val desktop = I18n.tableOf(I18n.DESKTOP_LAYER, "en")

        // The vendored Android base carries ~1,193 keys. The floor is deliberately far below that
        // so upstream churn never fails this, while an empty or half-copied tree still does.
        assertTrue(
            android.size > 500,
            "vendored Android base looks unmounted: ${android.size} keys at ${I18n.ANDROID_LAYER}"
        )
        assertTrue(
            desktop.size > 20,
            "desktop base looks unmounted: ${desktop.size} keys at ${I18n.DESKTOP_LAYER}"
        )
        assertTrue(desktop.containsKey("d_nav_crypto"), "desktop base is missing a known key")
        assertTrue(android.containsKey("settings_title"), "Android base is missing a known key")
    }

    @Test
    fun everyLocaleFileLoadsInBothLayers() {
        for (layer in listOf(I18n.ANDROID_LAYER, I18n.DESKTOP_LAYER)) {
            for (tag in I18n.SUPPORTED) {
                val table = I18n.tableOf(layer, tag)
                assertTrue(
                    table.isNotEmpty(),
                    "$layer/$tag resolved to an empty table — missing file, or malformed XML " +
                        "(I18n.parse swallows the parse error by design)"
                )
            }
        }
    }

    /**
     * The two layers share one namespace, and ownership is resolved by whichever ENGLISH file
     * declares a key — so a name that appears in both bases would make the desktop layer silently
     * shadow Android's translation. The `d_` prefix is what makes that collision impossible;
     * this asserts the prefix convention actually holds rather than trusting it.
     */
    @Test
    fun desktopKeysAreNamespacedAndNeverCollideWithAndroid() {
        val desktop = I18n.tableOf(I18n.DESKTOP_LAYER, "en")
        val android = I18n.tableOf(I18n.ANDROID_LAYER, "en")

        val unprefixed = desktop.keys.filterNot { it.startsWith("d_") }.sorted()
        assertTrue(
            unprefixed.isEmpty(),
            "desktop-owned keys must start with `d_`: $unprefixed"
        )

        val collisions = desktop.keys.intersect(android.keys).sorted()
        assertTrue(collisions.isEmpty(), "declared in both English bases: $collisions")
    }

    // ── Key parity + placeholders ──────────────────────────────────────────

    /**
     * A translated key the base doesn't declare is dead weight at best and a typo'd name at
     * worst — it renders nowhere and nothing else notices.
     */
    @Test
    fun noTranslationDeclaresAKeyTheBaseDoesNot() {
        forEachTranslation { layer, tag, base, table ->
            val extra = table.keys.filterNot { it in base }.sorted()
            assertTrue(extra.isEmpty(), "$layer/$tag declares keys absent from the base: $extra")
        }
    }

    /**
     * The one that actually breaks at runtime: `String.format` throws when a `%d` is handed a
     * String. `tr()` catches it and renders the raw template, so the symptom in the wild is one
     * label showing visible `%` codes — subtle enough to ship.
     *
     * Positional args are compared by index, not order: reordering `%1$s` and `%2$d` is the whole
     * point of the positional form and German and Japanese do it constantly.
     */
    @Test
    fun placeholderArityAndTypeMatchTheBase() {
        val mismatches = mutableListOf<String>()
        forEachTranslation { layer, tag, base, table ->
            for ((key, text) in table) {
                val want = placeholders(base[key] ?: continue)
                val got = placeholders(text)
                if (want != got) mismatches += "$layer/$tag '$key': base $want, translation $got"
            }
        }
        assertTrue(mismatches.isEmpty(), "placeholder mismatches:\n" + mismatches.joinToString("\n"))
    }

    /**
     * `one` may legitimately be absent — Japanese has a single CLDR plural category and its file
     * carries only `other`. `other` is the form trQuantity() falls back to and must exist
     * wherever the plural does at all.
     */
    @Test
    fun everyTranslatedPluralHasAnOtherItem() {
        val missing = mutableListOf<String>()
        forEachTranslation { layer, tag, base, table ->
            val plurals = base.keys.filter { it.contains('/') }.map { it.substringBefore('/') }.toSet()
            for (name in plurals) {
                val present = table.keys.any { it.startsWith("$name/") }
                if (present && !table.containsKey("$name/other")) missing += "$layer/$tag '$name'"
            }
        }
        assertTrue(missing.isEmpty(), "plurals with no `other` item: $missing")
    }

    /** The desktop layer is ours to finish; an untranslated key there is a gap, not a fallback. */
    @Test
    fun theDesktopLayerIsFullyTranslated() {
        val base = I18n.tableOf(I18n.DESKTOP_LAYER, "en")
        val gaps = mutableListOf<String>()
        for (tag in I18n.SUPPORTED - "en") {
            val table = I18n.tableOf(I18n.DESKTOP_LAYER, tag)
            var absent = base.keys.filterNot { it in table }
            // Japanese has no `one` form; see everyTranslatedPluralHasAnOtherItem.
            if (tag == "ja") absent = absent.filterNot { it.endsWith("/one") }
            if (absent.isNotEmpty()) gaps += "$tag: ${absent.sorted()}"
        }
        assertTrue(gaps.isEmpty(), "untranslated desktop keys:\n" + gaps.joinToString("\n"))
    }

    // ── Call sites ─────────────────────────────────────────────────────────

    /**
     * Greps the desktop UI source for `tr("…")` / `trQuantity("…")` literals and asserts each one
     * resolves. This is the check that carries the D11b sweep: converting a screen adds its keys
     * to this test automatically.
     */
    @Test
    fun everyKeyReferencedInSourceResolves() {
        val dir = File("src/main/kotlin/com/pgpony/desktop")
        if (!dir.isDirectory) return // running from an unexpected working directory; nothing to scan
        val call = Regex("\\btr(?:Quantity)?\\(\\s*\"([A-Za-z0-9_]+)\"")

        val unresolved = sortedSetOf<String>()
        var scanned = 0
        dir.walkTopDown().filter { it.isFile && it.extension == "kt" }.forEach { file ->
            val text = file.readText()
            for (m in call.findAll(text)) {
                val key = m.groupValues[1]
                scanned++
                // trQuantity names a <plurals>, which is stored flattened as `name/quantity`.
                val ok = I18n.has(key) || I18n.has("$key/other")
                if (!ok) unresolved += "$key  (${file.name})"
            }
        }

        assertTrue(scanned > 0, "found no tr() call sites — the source scan is looking in the wrong place")
        assertTrue(unresolved.isEmpty(), "keys referenced in source but not declared:\n" +
            unresolved.joinToString("\n"))
    }

    /** The enums hold resource keys rather than literals, so nothing else type-checks them. */
    @Test
    fun enumLabelKeysResolve() {
        for (theme in AppTheme.entries) {
            assertTrue(I18n.has(theme.labelKey), "AppTheme.$theme -> '${theme.labelKey}'")
        }
        for (dest in Destination.entries) {
            assertTrue(I18n.has(dest.labelKey), "Destination.$dest -> '${dest.labelKey}'")
        }
    }

    // ── Lookup semantics ───────────────────────────────────────────────────

    @Test
    fun missingKeyRendersAsItself() {
        assertEquals("no_such_key_anywhere", tr("no_such_key_anywhere"))
        assertNull(I18n.template("no_such_key_anywhere"))
    }

    @Test
    fun argumentsAreFormattedAndOmittedArgumentsLeaveTheTemplateIntact() {
        val formatted = tr("d_status_proxy_set", "127.0.0.1:9050")
        assertTrue(formatted.contains("127.0.0.1:9050"), "got: $formatted")
        assertTrue(!formatted.contains("%"), "placeholder survived formatting: $formatted")

        // No args at all is a plain lookup, not a format pass — the template comes back raw.
        assertEquals(I18n.template("d_status_proxy_set"), tr("d_status_proxy_set"))
    }

    /**
     * A translator's broken format string must not take a screen down. The realistic version of
     * this is a `%d` in a template whose call site passes a String — exactly what
     * placeholderArityAndTypeMatchTheBase exists to prevent, and what this proves is survivable
     * when one slips through anyway.
     */
    @Test
    fun aBrokenFormatFallsBackToTheTemplate() {
        // `%1$d` handed a String: String.format throws IllegalFormatConversionException.
        val key = "d_settings_pass_status_configured/one"
        val template = assertNotNull(I18n.template(key), "$key should resolve")
        assertTrue(template.contains("%"), "picked a template with no placeholder to break")
        assertEquals(template, tr(key, "not a number"))
    }

    @Test
    fun quantityPicksOneOrOther() {
        val one = trQuantity("d_settings_pass_status_configured", 1)
        val many = trQuantity("d_settings_pass_status_configured", 3)
        assertTrue(one.contains("1"), "count not substituted: $one")
        assertTrue(many.contains("3"), "count not substituted: $many")
        assertTrue(one != many, "one and other rendered identically in English: '$one'")
    }

    /**
     * Japanese declares only `other`. A count of 1 must resolve SIDEWAYS to the Japanese `other`
     * item — not down the ordinary key chain, which would land on the ENGLISH `one` item and put
     * an English sentence in the middle of a Japanese window.
     */
    @Test
    fun japaneseResolvesACountOfOneThroughItsOtherItem() {
        val key = "d_settings_pass_status_configured"
        I18n.selectLanguage("ja")

        val jaOther = assertNotNull(
            I18n.tableOf(I18n.DESKTOP_LAYER, "ja")["$key/other"],
            "the Japanese file should declare '$key/other'"
        )
        assertNull(
            I18n.tableOf(I18n.DESKTOP_LAYER, "ja")["$key/one"],
            "the Japanese file should NOT declare a `one` item — this test would prove nothing"
        )

        assertEquals(jaOther, I18n.pluralTemplate(key, "one"))
        assertEquals(String.format(I18n.localeOf("ja"), jaOther, 1), trQuantity(key, 1))
    }

    @Test
    fun unknownPluralRendersAsItsKey() {
        assertEquals("no_such_plural", trQuantity("no_such_plural", 2))
    }

    // ── Language selection ─────────────────────────────────────────────────

    @Test
    fun switchingLanguageChangesWhatTrReturns() {
        I18n.selectLanguage("en")
        val english = tr("settings_title")
        I18n.selectLanguage("de")
        val german = tr("settings_title")
        assertEquals("de", I18n.effective)
        assertTrue(
            english != german,
            "'settings_title' reads the same in English and German ('$english') — either the " +
                "German file is unmounted or the key is untranslated upstream"
        )
    }

    @Test
    fun languagePersistsAndReloads() {
        I18n.selectLanguage("fr")
        assertEquals("fr", prefs.get(I18n.KEY_LANGUAGE, null), "the picker must write through")

        // The other direction — a restart. Only the stored value survives a launch, so writing
        // the node directly is what "next time the app starts" actually looks like; calling
        // selectLanguage() again would just overwrite the very thing init() is meant to read.
        prefs.put(I18n.KEY_LANGUAGE, "ja")
        I18n.init()
        assertEquals("ja", I18n.language, "init() must adopt the stored value")
    }

    @Test
    fun pinEnglishOverridesTheProcessWithoutTouchingThePreference() {
        // Main.kt calls this for CLI verbs, whose output is scriptable. It has to win over the
        // picked language for this process AND leave the stored value alone, so opening the GUI
        // afterwards still comes up in the language the user chose.
        I18n.selectLanguage("de")
        I18n.pinEnglish()
        assertEquals("en", I18n.effective, "the pin must win over the picked language")

        assertEquals("de", prefs.get(I18n.KEY_LANGUAGE, null), "the pin must not write through")
        I18n.init()
        assertEquals("de", I18n.language, "a restart must come back up in the picked language")
    }

    @Test
    fun unsupportedOrCorruptStoredValuesFallBackToSystem() {
        I18n.selectLanguage("kl")               // rejected at the setter
        assertEquals(I18n.SYSTEM, I18n.language)

        prefs.put(I18n.KEY_LANGUAGE, "klingon")   // written by an older or hand-edited build
        I18n.init()
        assertEquals(I18n.SYSTEM, I18n.language)
    }

    @Test
    fun systemFollowsTheJvmDefault() {
        I18n.selectLanguage(I18n.SYSTEM)
        assertEquals(I18n.systemMatch(), I18n.effective)
    }

    /**
     * Region matters for exactly one entry. Brazilian Portuguese is translated and European
     * Portuguese is not, so `pt_PT` gets English rather than Brazilian wording it didn't ask for.
     */
    @Test
    fun systemMatchResolvesLocalesToSupportedTags() {
        assertEquals("de", I18n.systemMatch(Locale.GERMANY))
        assertEquals("de", I18n.systemMatch(Locale.forLanguageTag("de-AT")))
        assertEquals("fr", I18n.systemMatch(Locale.forLanguageTag("fr-CA")))
        assertEquals("ja", I18n.systemMatch(Locale.JAPAN))
        assertEquals("es", I18n.systemMatch(Locale.forLanguageTag("es-MX")))
        assertEquals("en", I18n.systemMatch(Locale.US))
        assertEquals("pt-BR", I18n.systemMatch(Locale.forLanguageTag("pt-BR")))
        assertEquals("en", I18n.systemMatch(Locale.forLanguageTag("pt-PT")))
        assertEquals("en", I18n.systemMatch(Locale.forLanguageTag("pt")))
        assertEquals("en", I18n.systemMatch(Locale.KOREA))
        assertEquals("en", I18n.systemMatch(Locale.forLanguageTag("und")))
    }

    @Test
    fun everySupportedTagHasAnEndonymAndAParsableLocale() {
        for (tag in I18n.SUPPORTED) {
            val name = I18n.displayNameOf(tag)
            assertTrue(name != tag, "no endonym for '$tag' — DISPLAY_NAMES is out of step with SUPPORTED")
            assertTrue(I18n.localeOf(tag).language.isNotEmpty(), "'$tag' is not a parsable BCP 47 tag")
        }
        assertEquals("pt", I18n.localeOf("pt-BR").language)
        assertEquals("BR", I18n.localeOf("pt-BR").country)
        // Unknown tags name themselves rather than rendering blank in the picker.
        assertEquals("kl", I18n.displayNameOf("kl"))
    }

    // ── The app-family links ───────────────────────────────────────────────
    //
    // everyKeyReferencedInSourceResolves greps for `tr("literal")`, and these descriptions are
    // reached as `tr(app.descriptionKey)` — a property read, invisible to a regex. The list is the
    // authority instead: walk it and check each key by hand, so adding a seventh app without
    // adding its sentence to i18n/ fails here rather than shipping a row labelled
    // "d_app_whatever_desc".

    @Test
    fun everyAppRowHasATranslatedDescription() {
        assertTrue(PonyApps.ALL.isNotEmpty(), "the app list is empty")
        for (app in PonyApps.ALL) {
            assertTrue(
                I18n.has(app.descriptionKey),
                "${app.title}: '${app.descriptionKey}' is declared in no layer"
            )
            for (tag in I18n.SUPPORTED) {
                assertNotNull(
                    I18n.tableOf(I18n.DESKTOP_LAYER, tag)[app.descriptionKey],
                    "${app.title}: '${app.descriptionKey}' is missing from $tag"
                )
            }
        }
    }

    /** Every row's PNG must actually decode; a null painter silently draws an empty 40dp gap. */
    @Test
    fun everyAppRowHasAnIcon() {
        for (app in PonyApps.ALL) {
            assertNotNull(
                PonyApps::class.java.getResourceAsStream("/icons/${app.icon}.png"),
                "${app.title}: resources/icons/${app.icon}.png is not on the classpath"
            )
            assertNotNull(appIcon(app.icon), "${app.title}: icons/${app.icon}.png did not decode")
        }
    }

    /** Nothing in the app should ever hand java.awt.Desktop a non-https URL. */
    @Test
    fun everyLinkTargetIsHttps() {
        val appUrls = PonyApps.ALL.map { it.url }
        for (url in appUrls + listOf(Links.REPO, Links.ISSUES, Links.WEBSITE)) {
            assertTrue(url.startsWith("https://"), "not https: $url")
        }
        // Only the app rows have to be distinct from each other. Links.WEBSITE is deliberately the
        // same address as the PGPony row — About links to the project's site, and that site is
        // also where the mobile app lives — so the two sets are checked separately rather than
        // pooled, which is what the first draft of this test got wrong.
        assertEquals(appUrls.size, appUrls.toSet().size, "two app rows share a URL: $appUrls")
        assertEquals("${Links.REPO}/issues", Links.ISSUES, "the issue tracker must hang off the repo")
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private fun forEachTranslation(
        body: (layer: String, tag: String, base: Map<String, String>, table: Map<String, String>) -> Unit
    ) {
        for (layer in listOf(I18n.ANDROID_LAYER, I18n.DESKTOP_LAYER)) {
            val base = I18n.tableOf(layer, "en")
            for (tag in I18n.SUPPORTED - "en") {
                body(layer, tag, base, I18n.tableOf(layer, tag))
            }
        }
    }

    private companion object {
        /** java.util.Formatter syntax, which is also Android's: %1$s, %2$d, %s, %.2f. */
        val PLACEHOLDER = Regex("%(?:(\\d+)\\\$)?([-#+ 0,(]*)(\\d+)?(?:\\.(\\d+))?([a-zA-Z])")

        /**
         * index -> conversion. Positional args are keyed by their declared index so a translation
         * may reorder them; bare `%s` are keyed by occurrence.
         */
        fun placeholders(text: String): Map<Int, Char> {
            val out = sortedMapOf<Int, Char>()
            var auto = 0
            for (m in PLACEHOLDER.findAll(text)) {
                val conv = m.groupValues[5].first()
                val idx = m.groupValues[1].toIntOrNull() ?: ++auto
                out[idx] = conv.lowercaseChar()
            }
            return out
        }
    }
}

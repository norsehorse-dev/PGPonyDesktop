# PHASE_D11_NOTES.md — localization (plan D11)

## D11 (2026-07-25)

### What shipped

- **Two string layers, one lookup.** The desktop does not maintain a second translation of
  anything Android already says. Android's six `strings.xml` files are vendored VERBATIM under
  `vendor/app-strings/` (same rule as the crypto source: never hand-edited, refreshed only by
  `tools/sync-strings.sh`), and desktop-only copy lives in `i18n/`. `build.gradle.kts`
  `processResources` mounts them under distinct classpath prefixes — `/i18n/android/…` and
  `/i18n/desktop/…` — so the two `values-de/strings.xml` files never collide. Ownership of a key
  is decided by whichever layer's ENGLISH file declares it, which means a key can be *moved*
  upstream later (Android grows an equivalent, we delete ours) with no call-site change.
- **`Strings.kt`** — `object I18n` plus three top-level functions:
  - `tr(key)` / `tr(key, vararg args)` — a lookup and a `String.format`. A key no layer declares
    renders as its own name, which makes a miss loud in the UI and harmless at runtime.
  - `trQuantity(key, count, vararg args)` — `<plurals>`, with `count` passed as format argument
    1 (Android's `getQuantityString(id, count, count)` convention). `Int` and `Long` overloads.
  - None of them are `@Composable`. They read Compose snapshot state, so calling one *inside*
    composition subscribes that composable to `I18n.language` and the whole UI re-renders on the
    next frame when the language changes — while the same call still works off the UI thread and
    outside composition entirely (the CLI, the backup service, the card transport).
- **Language picker** (Settings → Appearance) — `system` plus the five locales, named by
  **endonym** (`Deutsch`, `Español`, `Français`, `日本語`, `Português (Brasil)`); a picker that
  names languages in a language you can't read is a joke. `system` resolves through
  `systemMatch()`, which maps the JVM default onto the nearest supported tag (`pt_PT` → `pt-BR`,
  `de_AT` → `de`) and falls back to English. Persisted to `java.util.prefs`; takes effect
  immediately, no restart.
- **Coverage** — 18 source files call `tr()`, referencing **552 distinct keys**: 409
  desktop-owned and **143 reused straight from the Android layer**. The desktop layer itself is
  **433 keys (408 strings + 25 plurals)**, complete in all six locales.
- **The CLI is pinned to English.** `Main.kt` calls `I18n.pinEnglish()` before any CLI verb or
  `selftest` runs. CLI output is scriptable and shares its repository, backup and crypto helpers
  with the GUI — without the pin, someone's `pgpony import | grep failed` would start missing
  lines the day they switched the app to German. `pinEnglish()` deliberately does NOT route
  through `selectLanguage()`: it sets the process language and writes nothing, so the GUI's
  stored preference survives. Tests use it for the same reason.
- **`tools/sync-strings.sh`** — delete-and-recopy of the six Android files, so a key retired
  upstream actually disappears here. Runs the audit at the end: a placeholder mismatch that
  reaches this repo is an UPSTREAM bug, and patching it here would be silently reverted by the
  next sync.
- **`tools/i18n-audit.py`** — key parity + placeholder audit over either layer. Checks `missing`
  (a warning: a half-translated file degrades to English rather than breaking), `extra`,
  `placeholders` (arity AND conversion type — the one that actually throws), and `quantities`
  (`other` must exist; `one` may be absent). `--strict` promotes `missing` to an error.
- **`I18nTest`** — 25 tests. The structural ones are the point: every locale file loads in both
  layers, desktop keys are `d_`-namespaced and never collide with Android, no translation
  declares a key its base doesn't, placeholder arity and type match the base, every translated
  plural has an `other`, the desktop layer is fully translated, **every `tr("…")` literal in
  `src/` resolves in one of the two layers**, and every enum label key resolves.

### Design rules that fell out

These are the ones that bit, and the reasons they bit are not obvious from the call site.

- **A key held in a compile-time constant must be a KEY, not a resolved string.** A top-level
  `private val` initializes once per process and would freeze the language at class-load time;
  so would an `enum` entry, and so would a Kotlin `object` singleton inside a sealed class. The
  fix is always the same shape: store the key name, resolve at the use site. In-repo:
  `Destination(val labelKey: String, …)` in `Gui.kt`, `SortMode(val labelKey: String)` in
  `KeyringScreen.kt`, and `BackupError`, whose `message` is now `get()`-computed rather than
  baked in at construction. A top-level `private fun` returning `tr(…)` is fine — it re-runs.
- **Anything built outside composition needs its strings hoisted in.** The Compose `Tray`
  `menu = { }` lambda and the AWT `FileDialog` constructors run outside composition, so a `tr()`
  in there never resubscribes. All four file-picker composables (`BackupSaveDialog`,
  `BackupOpenDialog`, `KeyFileDialog`, `QrImageDialog`) take `title: String` as a parameter and
  the caller resolves it in the composable body.
- **Menu mnemonics are localizable and shortcuts are not.** A mnemonic is read as
  `tr("d_menu_file_mnemonic").firstOrNull() ?: 'F'` — the underlined letter has to match the
  translated label. `Cmd/Ctrl+1` does not move between languages and stays hardcoded.
- **Protocol framing is not copy.** `-----BEGIN PGP PUBLIC KEY BLOCK-----`, `body.txt`,
  `.pgpony-dec`, the `.eml` `Subject:` field, algorithm display names — all stay English. They
  are wire format or proper nouns, not user-facing prose.
- **Reuse vs mint.** Reuse the Android key when the English differs only stylistically; mint a
  `d_` key when reuse would be a content regression or the desktop's format differs materially
  (a desktop dialog that names a file path where the phone named a share target, say).
- **Sentence-level, not fragment-level.** Where a label leads the sentence in English but not in
  German or Japanese, the whole sentence is one key with the label as an argument — never a
  prefix glued on in Kotlin. The publish outcomes in `KeyServerDialogs.kt` are the worked
  example.
- **Multi-clause summaries: each clause carries its OWN leading separator**, and an outer plural
  wraps the list (`DesktopKeyRepository.summary()`, then `MergeReport.summary()`). Japanese uses
  `、` where the Latin locales use `, `, which a Kotlin-side `joinToString(", ")` cannot express.

### Translation register (verified against the vendored Android files)

German informal (du/dein) · Spanish tú/tu · French **formal** (vous/votre) · Japanese ですます ·
pt-BR você. French typography keeps the space before a colon (`Étiquette :`). Quotation marks are
per-locale: de „…" · es «…» · fr « … » · ja 「…」 · en/pt-BR "…". Badge strings are UPPERCASE in
the Latin-script locales and normal case in Japanese.

Terminology was taken from the vendored files rather than invented: keyring = Schlüsselbund /
llavero / trousseau / 鍵束 / chaveiro · key pair = Schlüsselpaar / Par de claves / Paire de clés /
鍵ペア / Par de chaves · hardware key = Hardware-Schlüssel / Llave de hardware / Clé matérielle /
ハードウェアキー / Chave de hardware · passphrase = Passphrase / Contraseña / Phrase secrète /
パスフレーズ / Senha. Recovery code is リカバリーコード in Japanese (復元 alone is the restore
*action*), and Settings is **Ajustes** in pt-BR.

### Notes / limits

- **Japanese `<plurals>` carry only `other`.** `trQuantity` selects `one` for a count of 1 and
  `other` otherwise; with no `one` item present, Japanese resolves a count of 1 to its own
  `other` rather than falling through to English. Intended, tested
  (`japaneseResolvesACountOfOneThroughItsOtherItem`), and the reason the audit does not flag a
  missing `one`.
- **`AndroidAppShim`'s eight trust-level strings are deliberately NOT localized.** Nothing under
  `src/` calls `TrustLevel.localizedName()`/`localizedDescription()`; the UI resolves trust names
  through `trustName()` in `KeyDetailDialog.kt`, which maps the enum to a key at the UI boundary
  and leaves the persisted backup wire value alone. The shim exists only so the vendored
  `data/PGPKeyEntity.kt` compiles. Translating unreachable code would mint six locales' worth of
  strings no one can ever see. Still superseded by the upstream cleanup candidate in
  `PHASE_D2_NOTES.md`.
- **`DesktopPassStore.buildRef()` falls back to the literal `"Password Store"`** when a folder
  name starts with a dot. That value is persisted into `PassStoreRef.displayName`, and the
  vendored `pass_store_title` is untranslated in all six locales anyway (it is the `pass` tool's
  proper name), so localizing it would change nothing on screen. Left alone; flagged here so the
  next reader doesn't rediscover it.
- **The de/ja layout pass is visual and is Kevin's to run** (below). German runs long and can
  clip a fixed-width button; Japanese has different line-break metrics and no inter-word spaces.
- Adding a locale means updating `LOCALES` in `tools/sync-strings.sh`, `I18n.SUPPORTED` +
  `DISPLAY_NAMES` in `Strings.kt`, and `LOCALE_DIRS` in `tools/i18n-audit.py` **together** — the
  sync script errors out loudly if Android ships a locale the desktop doesn't know about.

### Validation

1. `./gradlew build` — includes `I18nTest` (25 tests).
2. `python3 tools/i18n-audit.py --layer i18n --strict` → `0 error(s), 0 untranslated key(s)`,
   458/458 per locale.
3. `python3 tools/i18n-audit.py --layer vendor` → findings here are upstream bugs, not ours.
4. Launch, Settings → Appearance, switch through all six languages. The whole window should
   re-render without a restart, including the menu bar and the tray menu.
5. **de/ja layout pass** — in German and then Japanese, walk: keyring (sort menu, badges, meta
   line), key detail, crypto (all four surfaces), cards (PIN dialog, reader picker), pass,
   settings, backup export + restore, keyserver search + publish, and the File/Edit/Help menus.
   Watch for clipped buttons, labels wrapping to three lines, a dialog that has stopped fitting,
   and mnemonics whose underlined letter is no longer in the translated word.
6. Switch to German, run `pgpony list-keys` from the shell → output is still English.

### Fix log

- **Fix1 — platform declaration clash on `setLanguage`.** `I18n.language` is
  `var language: String by mutableStateOf(SYSTEM)` with `private set`, which still emits
  `setLanguage(Ljava/lang/String;)V` on the JVM, so a hand-written `fun setLanguage(...)` beside
  it collided. Renamed to `selectLanguage()`. This is the second time the pattern has bitten
  (D8 Fix2 hit the same wall on a different property) — the rule is now: never name a helper
  `setX` next to a `var x by mutableStateOf`. `showPassStore`, `selectLanguage` and `pinEnglish`
  are all named the way they are for this reason.
- **Fix2 — the two `values-de/strings.xml` files landed on the same classpath path.** Both
  layers use Android's directory shape, so vendored and desktop resources overwrote each other
  in the jar. Fixed in `processResources` with
  `from("vendor/app-strings") { into("i18n/android") }` and `from("i18n") { into("i18n/desktop") }`;
  `Strings.kt` reads the two prefixes separately and resolves ownership from the English files.
- **Fix3 — `Locale.of(...)` does not exist on the toolchain.** It is Java 19+; the project is
  `jvmToolchain(17)`. Replaced with `Locale.forLanguageTag(tag)`, which also has the better
  behavior for `pt-BR`.
- **Fix4 — the audit's `NO_PLURAL_DISTINCTION` filter was inverted**, so it flagged a missing
  Japanese `one` as an error and stayed silent on the case it was written to catch.
- **Fix5 — `Icons.Filled.OpenInNew` is deprecated in favor of the auto-mirrored variant.** RTL
  isn't in the supported set today, but the mirrored icon is correct regardless:
  `Icons.AutoMirrored.Filled.OpenInNew`.
- **Fix6 — `everyLinkTargetIsHttps` passed against a pooled URL list** rather than the rows it
  meant to check, so it would not have caught a plain-`http` target. Rewritten to walk the
  actual app rows.
- **Fix7 — `trQuantity` had no `Long` overload** (`FileCryptoOps.kt:151`, `compileKotlin`:
  *actual type is 'Long', but 'Int' was expected*). `PGPCryptoService.DecryptResult.bytesWritten`
  is a `Long`. The tempting `.toInt()` wraps past 2 GB and would print a NEGATIVE byte count on
  a large decrypt, so instead the lookup now works in `Long` and the `Int` overload widens into
  it. Safe across the board because every `<plurals>` template in all six locales formats
  argument 1 with `%d`, which takes either width — checked before the change, not after.
- **Terminology corrections caught in review, not by a test:** Japanese recovery code was
  復元コード and should be リカバリーコード (the vendored `restore_code_label` and
  `backup_confirm_label` both use it; 復元 alone is the restore action). pt-BR Settings was
  Configurações and should be **Ajustes**, per the vendored `main_tab_settings`. Both are the
  same failure mode — translating a term the Android app had already settled instead of looking
  it up — which is why the reuse-vs-mint rule above is written down.

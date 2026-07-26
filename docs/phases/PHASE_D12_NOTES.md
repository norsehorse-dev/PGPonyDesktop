# PHASE_D12_NOTES.md — UI overhaul (plan D12)

## D12 (2026-07-25)

The brief was "make it look great, be very ambitious, incorporate the app icon into the
desktop app." Four decisions were taken before any code: **native chrome, bold interior**
(keep the OS title bar and window controls, overhaul everything inside — explicitly not an
undecorated window); the icon on **all four surfaces**; delivery in **three batches, each
green on the Mac before the next started**; and packaging deferred to **D13**, so D12 is the
overhaul and nothing else.

### What shipped

- **`Brand.kt` — a token layer, deliberately not part of `Theme.kt`.** `Theme.kt`'s two
  ColorSchemes are a verbatim port of Android's `AppTheme.kt` and are held at parity with it,
  so a desktop-only accent belongs beside that file rather than inside it. Everything in
  `Brand.kt` is additive: nothing changes what `MaterialTheme.colorScheme` resolves to, so a
  screen that had not been restyled yet kept looking exactly as it did. It holds the gradient
  (`#FF4B69F1` → `#FFB42DEB`, lifted from the Android adaptive icon's background so the mark
  in the Dock and the button under the cursor are visibly the same brand), a 4dp-grid spacing
  scale, three radii, and the widgets built on them.
- **`Layouts.kt` — `WrapRow`.** A `Row` hands out width in measure order and gives the last
  child the remainder, so four buttons that just fit in English rendered "QR anzeigen…" one
  letter per line in German. `WrapRow` measures each child at its natural width and wraps.
  Built on `Layout` rather than Foundation's `FlowRow` because that one is
  `@ExperimentalLayoutApi` and this project carries no `@OptIn` anywhere.
- **The icon on all four surfaces** — window and dock/taskbar, tray, nav rail masthead, and
  the About dialog — plus jpackage icon files for all three installers. Assets come from
  `tools/make-icons.py`, run against the iOS 1024×1024 master.
- **Screen chrome, written once.** `ScreenHeader`, `SectionHeader`, `SubHeading`,
  `SectionCard`, `EmptyState`, `StatusStrip`, `BrandBadge`, `LabeledValue`, `BrandRule`,
  `BrandCard`, `BrandButton`, `BrandMark`. The point is not saving lines; it is that a user
  moving between Keyring and Settings should not be able to tell that two different days of
  work built them.
- **All five screens restyled** onto that layer, with real empty states where the app used to
  show a bare sentence or nothing at all — an empty keyring, a search that matched nothing (a
  blank list was previously indistinguishable from having no keys), no PC/SC reader, no card
  read yet, no password store, nothing selected, no files queued.
- **Dialog chrome unified.** `BrandDialog` wraps Material3's `AlertDialog`, so the scrim,
  focus handling, escape-to-dismiss and platform window management are untouched and only the
  chrome is ours. All twelve existing dialog sites were converted; zero raw `AlertDialog`
  calls remain outside `Brand.kt`. Four are marked `destructive` (delete key, factory reset,
  on-card keygen, revoke), which swaps the title tick and colour to the scheme's error colour
  — previously those announced themselves only by colouring a word of body copy red.
- **An About dialog**, opened from a new Help menu: the mark, the version, the paste-ready
  runtime line with its copy button, the three project links and the app family. Compose
  Desktop cannot populate macOS's application menu, where an About item conventionally lives,
  so a Help menu is the one place that behaves the same on all three operating systems.
  `runtimeDescription()` went from file-private to `internal` so the dialog and the Settings
  section share one copy rather than drifting.
- **i18n: 458 → 480 desktop-owned keys**, complete in all six locales, audit clean.
  `d_keyring_empty` was retired in favour of a title/body pair the new `EmptyState` takes.

### Delivered in three batches

| batch | contents |
| --- | --- |
| 1 | `Brand.kt`, `Layouts.kt`, icon surfaces, `build.gradle.kts`, WrapRow applied to 18 sites |
| 2a | screen chrome added to `Brand.kt`; Keyring and Settings restyled |
| 2b | Crypto, Cards and Pass restyled |
| 3 | `BrandDialog` across all twelve dialogs; About dialog; Help menu; rail fixes |

### Design rules that fell out

The ones that bit, and whose reasons are not obvious from the call site.

- **A fill modifier under an unbounded constraint resolves to `minHeight`, which is zero.**
  Compose's fill node checks `constraints.hasBoundedHeight` and falls back to `minHeight`
  when the axis is unbounded. So `EmptyState` must NOT bake in `fillMaxSize`: three of the
  five screens put their empty state inside a `verticalScroll` column, where it would have
  collapsed to nothing on exactly the screens that scroll. A caller that owns a bounded
  height passes `Modifier.fillMaxSize()` itself. `fillMaxSize().verticalScroll()` in that
  order is fine and remains in three places — the size resolves against the parent's bounded
  constraint and the scroll wraps it.
- **A `Row` measures its non-weighted children first, with the whole available width.** A
  child that fills its width therefore takes everything and starves its siblings. This is
  what made the nav rail as wide as the window (Fix2) and, one level down, what let a
  rail item spill its second label line into the content pane (Fix3). Anything whose width is
  not intrinsically bounded needs pinning.
- **`weight` is a `RowScope` modifier and `WrapRow`'s content lambda is unscoped.** Where a
  screen needs both — a title, a weighted spacer, and a wrapping action group — the outer
  `Row` keeps the spacer and a nested `WrapRow` holds the buttons. When they fit, the spacer
  pushes them right; when they don't, the WrapRow claims the remaining width and the spacer
  collapses. That arrangement now lives inside `ScreenHeader` so every screen inherits it.
- **A bare `DropdownMenu` sibling breaks `WrapRow`.** Every direct child is packed as its own
  item and a popup measures to nothing, so it consumes a slot and desynchronises the gaps.
  Box it with its anchor button. Four sites needed this.
- **A `@Composable () -> Unit` lambda parameter does not inherit `ColumnScope`** from wherever
  it is invoked, so `weight`/`align` cannot be used at the top level of a `SectionCard` or
  `ScreenHeader` content block.
- **Enum labels, top-level `val` label lists and `object` singletons hold KEYS, not resolved
  strings** — the D11 rule, and it survived the overhaul unchanged.
- Only stable Compose APIs. No `@OptIn` anywhere, which is why the project has `WrapRow`
  instead of `FlowRow` and plain `DropdownMenu` instead of `ExposedDropdownMenuBox`.

### Notes / limits

- **The nav rail is pinned to 112dp and its labels are centre-aligned.** `d_nav_crypto` was
  shortened from "Encrypt · Decrypt" to one word per locale, because a rail label is a name,
  not a sentence, and the tab strip inside the screen already says Encrypt/Decrypt/Sign/
  Verify/Files. "Hardware Keys" and "Password Store" still take two centred lines, which now
  reads as deliberate rather than as overflow.
- **`d_nav_cards` in German is "Hardware-Schlüssel"** — the longest rail label in any locale
  and the one that sets the 112dp floor. Worth re-checking if the rail ever narrows.
- **The de/ja layout pass was run and found one defect: the Password Store label was English
  in every non-English locale** (Fix5 below). Nothing clipped, nothing wrapped to three lines,
  no dialog stopped fitting — including the two surfaces most at risk, the five-tab Crypto
  strip (`TabRow` divides width evenly and cannot wrap) and the keyserver rows in Settings,
  which are still a bare `Row`. Both are fine at the sizes tested but remain the first places
  to look if a longer locale is ever added.

### Validation

1. `./gradlew build` — green, including the 444-test suite.
2. `python3 tools/i18n-audit.py --layer i18n --strict` → `0 error(s), 0 untranslated key(s)`,
   480/480 per locale.
3. Launch and walk all five screens in light and dark, checking the empty states: an empty
   keyring, a search matching nothing, no reader attached, a reader with no card read, no
   password store configured, no entry selected, no files queued.
4. Help → About PGPony: the mark renders, the version is right, the three links open in a
   browser, "Copy diagnostics" produces a paste-ready line.
5. Open each of the twelve dialogs and confirm the shared chrome, and that the four
   destructive ones (delete key, factory reset, on-card keygen, revoke) show the error tick.
6. **de/ja layout pass** — in German and then Japanese, walk: the nav rail, keyring (sort
   menu, badges, meta line), key detail, crypto (all five tabs), cards (PIN dialog, reader
   picker), pass, settings (all seven cards), backup export + restore, keyserver search +
   publish, About, and the File/Keys/Message/Help menus. Watch for clipped buttons, labels
   wrapping to three lines, a dialog that has stopped fitting, and mnemonics whose underlined
   letter is no longer in the translated word.

### Fix log

- **Fix1 — `Constraints.constrainWidth`/`constrainHeight` are top-level extensions in
  `androidx.compose.ui.unit`, not members**, so they need their own imports.
  `WrapRow` uses `coerceIn`, which does exactly the same job with no import risk.
- **Fix2 — the nav rail took the entire window width and the content pane measured to zero.**
  `RailBrandHeader` opens with `fillMaxWidth`, and `NavigationRail` sizes itself to its widest
  child; a `Row` measures non-weighted children first with the whole available width, so the
  rail was offered the window and filled it. The app rendered as a giant centred menu with no
  content. Fixed by pinning the rail container to `RAIL_WIDTH` and giving the content column
  `weight(1f)` — "take everything the rail did not", said explicitly, rather than relying on
  there being width left to fill. **This compiled green and passed every static check.** It
  was a layout defect, not a type error, and no amount of reading the code was going to catch
  it; the screenshot did.
- **Fix3 — rail labels overflowed the pinned container, left-aligned.**
  `NavigationRailItem` measures to its label's natural width, so a two-word label spilled its
  second line into the content pane. Pinned each item to `RAIL_WIDTH` and centre-aligned the
  label; shortened `d_nav_crypto` to one word in all six locales.
- **Fix4 — `QrCodeTest` had been failing intermittently since D9, and it was a real defect in
  `decodeFromImage`, not flakiness.** The test generates a fresh key every run, so it only
  fired when it drew an affected certificate, which read as noise. Encoding always succeeded
  and decoding returned null. Measured over 40 freshly generated Ed25519 certificates:

  | error correction | general detector | `PURE_BARCODE` | two-pass |
  | --- | --- | --- | --- |
  | L | 2 / 40 fail | 0 / 40 | 0 / 40 |
  | M | 4 / 40 fail | 0 / 40 | 0 / 40 |
  | Q | 2 / 40 fail | 0 / 40 | 0 / 40 |

  ZXing's default detector is built for photographs — it hunts for the finder patterns in an
  image that may be blurred, rotated, skewed or unevenly lit. On a pixel-perfect synthetic
  render it intermittently fails to find a symbol that is demonstrably there, deterministically
  for a given key, at every render size and every quiet zone. `PURE_BARCODE` skips the hunt and
  reads the module grid directly. `decodeFromImage` now tries the photo detector first — a
  photo of someone else's screen is the case `PURE_BARCODE` cannot handle — and falls back to
  the grid reader, which covers the screenshots and exported images that are the common import
  path. The fallback cannot produce a wrong answer: a QR carries its own error-correction
  codewords, so a misread fails the checksum and throws rather than returning bad key material.

  **Three hypotheses were wrong before that one was right, and the wrong turns are worth
  recording.** (a) *Payload too large, or too few pixels per module* — refuted: the armor is
  579 bytes, nowhere near capacity, and it decodes at 640, 1024, 1280 and 2048. (b) *The quiet
  zone is out of spec at `MARGIN = 1`* — refuted: a spec-conformant 4-module margin fails on
  exactly the same keys. (c) *Error-correction level L is the culprit* — refuted by the table
  above; L was briefly changed to M on the evidence of a single certificate and reverted once
  40 were measured, since M was no better and in that sample worse. The lesson is the cheap
  one: the encoder was never at fault, and each hypothesis was plausible enough to ship a fix
  on. `QrDetectionRegressionTest` now pins the exact certificate that reproduces it, so the
  regression is deterministic and costs no key generation.

  Two follow-ups this surfaced and did not close: `decodeFromImage` swallows every exception
  into `null`, which is what turned a one-round diagnosis into five — worth narrowing. And
  this is desktop-only code, so if the Android app's QR export made the same decode choice it
  has the same gap; worth a look upstream. Whether a real phone camera struggles with these
  symbols is **untested** — it needs a camera pointed at a screen and belongs on the manual
  validation list, not in this file as a finding.

- **Fix5 — "Password Store" was untranslated in all five non-English locales.** Found by the
  de/ja pass, reported against Japanese, where an English rail label next to 鍵束 / 暗号化 /
  ハードウェア鍵 / 設定 is impossible to miss; it was equally wrong in de, es, fr and pt-BR.
  The cause: the rail, the Keys menu item and the screen header all read the VENDORED Android
  key `pass_store_title`, which Android ships as "Password Store" in every locale because it
  treats the `pass` tool's name as a proper noun. That is defensible on the phone, where the
  string is a screen title; as a navigation label sitting in a column of translated words it
  is not. The desktop layer had meanwhile already named that tab in each locale — the empty
  state said パスワードストア while the rail three inches away said "Password Store" — so the
  app was contradicting itself. Fixed by minting `d_pass_store_title` and repointing the three
  UI call sites at it, taking each locale's own existing wording (de Passwortspeicher, es
  Almacén de contraseñas, fr Gestionnaire de mots de passe, ja パスワードストア, pt-BR Cofre de
  senhas). German's `d_settings_pass_show_tab` said "Password-Store-Tab anzeigen" while its
  empty state said "Passwortspeicher"; realigned to the translated noun.

  This is the reuse-vs-mint rule from D11 doing its job — reuse the Android key when the
  English differs only stylistically, mint a `d_` key when reuse would be a content
  regression. Untranslated copy in five locales is a content regression. `DesktopPassStore`'s
  literal `"Password Store"` fallback is deliberately NOT touched: that value is persisted
  into `PassStoreRef.displayName`, so it is stored data rather than copy (D11 notes).

### After D12

**D13 — packaging, signing, release:** signed and notarized dmg, deb, msi + winget, `.asc`
signatures and a signed SHA256SUMS, `desktop.php` on pgpony.app, plus the OS-level
file-association registration deferred from D9.

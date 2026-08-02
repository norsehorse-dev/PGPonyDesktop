# PGPony Desktop 1.1.0 Planning

Status: draft
Base: 1.0.3 (`Config.VERSION`, `build.gradle.kts` packageVersion)
Origin: field report, Jul 30 2026, Windows 11 22H2 running 1.0.3. Same reporter filed three iOS items against 8.0.0; those are tracked in `PGPony_8_1_0_Planning.md`.
Supersedes the `PLANNING_DESKTOP_1_0_4.md` draft (Aug 2 scope decision): the same field report now ships as a minor release instead of a patch, because item 3 — the Message/Files restructure — is included, and a release that moves controls and adds a visible badge is not a patch. There will be no 1.0.4.
Plan of record for the 1.0.0 line remains `PLANNING_DESKTOP_1_0_0.md` in the PGPonyAndroid repo root; the next major is scoped in `PLANNING_DESKTOP_2_0_0.md`.

## Theme

Everything the field report asked for, in one coherent release: the Remove/add fixes (one root cause, wider blast radius than reported, both fixes contained), the hardware-key indicator in the certificate list, and the Message/Files restructure the reporter was right about. The restructure got the written IA note this doc previously demanded — it is §3's design section below.

Russian localization moves out of this release entirely: it is scoped in `PLANNING_DESKTOP_2_0_0.md` §4, still gated on PGPonyAndroid shipping `values-ru` and a confirmed native reviewer.

## 1. File list Remove does nothing (reported), plus two unreported siblings

### The report

"When adding a file for encryption, and when I want to delete it from the added ones, I click the Remove button at the end of the line, but nothing happens. Only the Clean button cleans everything, not deletes a single file."

Reproduced by inspection and confirmed empirically.

### Root cause

`java.nio.file.Path` implements `Iterable<Path>`, iterating over its own name components. That makes both Kotlin stdlib overloads applicable at every call site where a single `Path` is added to or removed from a `List<Path>`:

```kotlin
operator fun <T> Iterable<T>.minus(element: T): List<T>
operator fun <T> Iterable<T>.minus(elements: Iterable<T>): List<T>
```

Overload resolution picks the `Iterable` one. Verified on kotlinc 2.2.20 against JDK 21:

```kotlin
val a = Path.of("/Users/kevin/Docs/report.txt")
val b = Path.of("/Users/kevin/Docs/notes.txt")
var list: List<Path> = listOf(a, b)
list = list - a          // size stays 2. Nothing removed.

var l2: List<Path> = listOf(a)
l2 = l2 + b              // size 5: [report.txt, Users, kevin, Docs, notes.txt]
```

So `- path` subtracts the path's *components* from the list, matches nothing, and is a silent no-op. `+ path` appends the components as separate entries. Neither produces a compile error or a warning.

### The three affected sites

| File | Line | Expression | Symptom |
|---|---|---|---|
| `CryptoScreen.kt` | 288 | `fileList = fileList - p` | Files-tab Remove is a no-op. **This is the reported bug.** |
| `CryptoScreen.kt` | 629 | `attachments = attachments - p` | Bundle-attachment Remove is a no-op. Not reported, same defect. |
| `CryptoScreen.kt` | 169, 170, 171 | `fileList = fileList + a.path` | Opening a *single* file adds its path components as bogus rows instead of the file. Not reported. |

The third is the one that matters most and is the reason this should not ship as a one-line patch. Those three lines are the `OpenAction` handlers for `pendingOpen`, and `Gui.onOpenFiles` routes exactly one path there:

```kotlin
paths.size == 1 -> pendingOpen = DesktopFileRouter.classify(paths.first())
paths.size >  1 -> onFilesDropped(paths.map { it.toFile() })
```

So double-clicking a single `.gpg` or `.asc` file in Explorer or Finder, opening one from the CLI, or forwarding one into a running instance through `SingleInstance` all hit the broken overload. Drag-and-drop of one file goes through `onFilesDropped` with a `List`, which is correct, which is very likely why this was never caught by hand: the drop path and the multi-file picker both pass lists and behave.

D13 registered the file associations. This bug means the primary payoff of that work, double-clicking an encrypted file, has been landing users on a Files tab full of path fragments since 1.0.0.

### Fix

- Make the intent explicit at each site rather than relying on resolution: `fileList.filterNot { it == p }` for removal, `fileList + listOf(p)` (or `fileList.plusElement(p)`) for the single-path adds.
- Add a `CryptoScreenListOpsTest` covering all three: remove one of two queued paths, remove one of two attachments, add one path and assert size 1 with the path intact. Pure list logic, no Compose needed.
- Sweep the rest of the desktop source for the same shape. Confirmed clean today, but the trap is invisible and will be re-introduced by anyone writing the obvious code.
- Consider a lint or detekt rule for `Path` in `plus`/`minus` element position if one can be expressed cheaply. Lower priority than the sweep.

### Also worth doing while in here — DECIDED: icon button

Remove is a `TextButton` with a text label at the end of a `WrapRow`; on a narrow window the wrap can put it under the filename, where a bare word doesn't read as a control. Decision (Aug 2): once it works, it becomes an `IconButton` (Close glyph) wrapped in the desktop `TooltipArea`, with `contentDescription` and tooltip both reusing the existing `d_common_remove` key — no new strings. Applies to both the Files-tab rows and the bundle-attachment rows so the two Remove controls stay the same shape.

## 2. Hardware-key indicator in the certificate list (reported)

### The report

"I would suggest adding an icon in the general list of certificates that has a link to the hardware key, and not just the word Card in the certificate properties."

Correct, and cheap. `KeyringScreen.KeyCard` draws its badge group as:

```kotlin
BrandBadge(key.algorithm.displayName)
if (key.isKeyPair)  BrandBadge(tr("d_keydetail_badge_secret"), BadgeTone.Brand)
if (key.isDefault)  BrandBadge(tr("key_detail_badge_default"))
if (key.isRevoked)  BrandBadge(tr("key_card_revoked_badge"), BadgeTone.Error)
if (key.isExpired)  BrandBadge(tr("d_keydetail_badge_expired"), BadgeTone.Error)
```

`isCardBacked` is not among them, and `KeyDetailDialog` line 102 already renders the string key `d_keydetail_badge_card` ("CARD") for exactly this. So the row badge is one line using a key that is already translated into all six locales.

### Work

- Add the CARD badge to `KeyCard`'s `WrapRow`. It sits in the existing `WrapRow`, so the D12 overflow behaviour is inherited and there is no layout risk on long user IDs.
- Badge versus icon — DECIDED (Aug 2): badge only. The badge group is the established vocabulary on this screen and the key is already translated in all six locales. The avatar-tile third treatment (card rows currently render washed, same as a bare public key) is noted but deferred — revisit if the badge alone reads weakly in practice.
- Check the same gap on iOS. Filed as a cross-check in the 8.1.0 plan.

## 3. Message versus Files tab structure (reported)

### The report

The Encrypt / Decrypt / Sign / Verify tabs sit as siblings of a Files tab that itself carries operation radio buttons. He suggests a Message tab mirroring the Files tab, so the top level splits by what you are operating on and the operation is a control inside.

### Assessment

He is describing a real inconsistency. The current `CryptoTab` enum mixes two axes:

```kotlin
ENCRYPT, DECRYPT, SIGN, VERIFY,   // operations
FILES                             // an object type, with its own FileOp radio group
```

The header comment in `CryptoScreen.kt` already records why: four of the five labels are Android string keys, because the phone app has those four tabs and Files is a sub-mode of Encrypt there. The desktop inherited a phone IA and then bolted a fifth tab of a different kind onto it.

His proposal, Message and Files at the top with a shared operation selector inside each, is more coherent than what exists. It also collapses five tabs to two, which helps the narrow-window and long-translation cases that D12 spent effort on.

This was previously deferred pending a written IA note before any code. This release is that item, and the section below is that note.

### Design (the IA note)

Two top-level tabs, split by what you operate on; the operation is a control inside each:

```kotlin
private enum class CryptoTab(val labelKey: String) {
    MESSAGE("d_crypto_tab_message"),   // NEW desktop-owned key
    FILES("d_crypto_tab_files")        // existing
}
private enum class MessageOp(val labelKey: String) {
    ENCRYPT("main_tab_encrypt"),          // the four former tab labels,
    DECRYPT("main_tab_decrypt"),          // demoted from tabs to the
    SIGN("encrypt_action_sign"),          // radio row — no Android key
    VERIFY("verify_file_verify_button")   // is orphaned
}
```

- The Message tab renders the same radio-row shape the Files tab already uses for `FileOp` (a `WrapRow`, which has already proven the German-overflow case), selecting between the four existing text surfaces unchanged. The earlier worry that this "orphans four Android string keys" dissolves on inspection: the keys move from tab labels to radio labels, and the only minted key is `d_crypto_tab_message` — one word ("Message"), six locales, all common vocabulary.
- The per-tab input map (the "text typed in Encrypt used to follow you to Decrypt" fix) becomes per-`MessageOp`, preserving that behaviour exactly. Switching op clears banner, output and decrypted attachments, as switching tab does today.
- Nothing outside `CryptoScreen.kt` moves: `CryptoTab` is private to the file, and every external entry point already routes through `OpenAction` / `droppedFiles` (verified by sweep). `DecryptText` lands on Message+Decrypt, file actions land on Files with the op forced, drops land on Files with the op classified — same as today, one tab-hop shorter.
- The divergence from Android's IA is deliberate and recorded here: the phone's four-tabs-plus-file-submode shape is where the desktop inherited the inconsistency from, and the desktop is the platform where a fifth sibling tab made it visible. Whether the phones follow is filed as a 2.0.0-doc follow-up, to be decided on 1.1.0 field feedback.

## 4. Russian localization (NOT in 1.1.0 — analysis kept here, scheduling in the 2.0.0 doc)

Requested by the same reporter, primarily against iOS. If it ships on one platform it should ship on both. Decision (Aug 2): it does not ride in 1.1.0 — `PLANNING_DESKTOP_2_0_0.md` §4 owns the scheduling and points back at this section for the substance, which follows.

### What makes desktop harder than iOS

- **The strings are vendored.** `vendor/app-strings/` holds Android's six `strings.xml` files byte-identical, refreshed by `tools/sync-strings.sh`, never hand-edited here. The desktop-owned layer under `i18n/` covers only desktop-specific wording. So a Russian desktop build requires `values-ru` in **PGPonyAndroid first**, then a sync, then `i18n/values-ru/strings.xml` for the desktop layer. Translating only the desktop layer would produce an app that is Russian on the file-association and PC/SC screens and English everywhere else.
- **`trQuantity` only knows two plural categories.** `Strings.kt` line 348:

  ```kotlin
  val quantity = if (count == 1L) "one" else "other"
  ```

  Every shipping locale needs only `one`/`other`, so this has always been sufficient. Russian needs `one`/`few`/`many`/`other`, selected on the last digit and the tens (1 but not 11, 2 to 4 but not 12 to 14, and so on). With the current selector, "3 keys" and "5 keys" would both render the `other` form and read as broken Russian. There are 50 plural entries in `i18n/values/strings.xml` alone.

  Work: replace the two-way branch with a CLDR plural-category selector. `java.text.ChoiceFormat` will not do this; the practical options are ICU4J's `PluralRules` (a new dependency on a plain-JVM module that currently has none for this) or a small hand-written rule table keyed by language tag. The hand-written table is roughly twenty lines for the languages actually shipped and keeps the dependency list flat, which matches how this repo has handled similar choices.

- **Registration surfaces.** `I18n.SUPPORTED` and `I18n.DISPLAY_NAMES` ("Русский") in `Strings.kt`, and `tools/i18n-audit.py` needs to pass on the new files.
- **Layout.** Russian runs roughly 15 to 30 percent longer than English. D12's `WrapRow` work already handles the German overflow cases, so this is a verification pass rather than expected rework, but the file-operation radio row and the badge group are the places to look.

### Translation quality

Machine translation is the only option in house, and it is meaningfully weaker for Russian than for the Western European locales already shipping. The reporter has been asked whether he will review the strings the way a native speaker reviewed Chinese for iOS. Ship Russian when a reviewer is confirmed; hold it otherwise rather than shipping a machine pass over PIN prompts, trust levels and verification results.

Note that Chinese is an iOS-only locale today. Desktop and Android ship six locales; iOS has a seventh, `zh-Hans`, in its catalog. If Russian lands on both, the locale sets should be reconciled deliberately rather than drifting further.

## 5. Cross-platform note: KDF-DO is already handled here

The same reporter's second iOS finding is a correct card PIN being rejected while the retry counter decrements, with the same card working in Kleopatra. The leading hypothesis there is the OpenPGP KDF data object (`00F9`).

Desktop is **not** affected, and the reason is worth recording:

- `vendor/app-crypto/com/pgpony/android/crypto/card/CardKdf.kt` implements KDF-DO parsing and the RFC 4880 iterated-and-salted S2K derivation, byte-compatible with libgcrypt's `GCRY_KDF_ITERSALTED_S2K`.
- `OpenPgpCardSession` probes `00 CA 00 F9 00` before the first PIN command of a session; `OpenPgpCardSigningTest.verifySendsHashedPinWhenCardReportsKdf` pins the hashed-PIN behaviour, and the absent-DO reply path is covered too.
- `CardKdf.kt`'s header records that this exact failure was reported against **Android 4.0.3** and fixed in 4.0.4: "the card was fine, PGPony was sending the wrong bytes."

`PcscCardTransport` sits under that whole vendored stack, so desktop inherited the fix for free. iOS has an independently written Swift card layer with no `00F9` read anywhere in it, which is why the same card behaves differently on the phone.

Action for this doc: none in code. Point the iOS work at `CardKdf.kt` and `CardKdfTest.kt` as the reference implementation, and at the 4.0.3 to 4.0.4 Android history as the precedent. No re-derivation needed.

## 6. Release mechanics

Version lives in two places that must move together:

- `src/main/kotlin/com/pgpony/desktop/Config.kt` line 20, `const val VERSION = "1.0.3"`
- `build.gradle.kts` line 174, `packageVersion = "1.0.3"`

Then the `RELEASING.md` run: tag `v1.1.0`, three-runner CI build, sign and notarize from environment secrets, upload, `--latest`, and the downstream `winget/` and `packaging/aur/` bumps. `UpdateCheck` picks the new release up from there.

A drift check between `AppVersion.VERSION` (the const lives in `object AppVersion`, in Config.kt) and `packageVersion` would be a cheap addition to `SelfTest` or a unit test, since these are two files that must agree and nothing enforces it today. Done in this release as `VersionDriftTest`.

## 7. Test matrix

| Area | Case | Expected |
|---|---|---|
| Files tab | Add 3 files, Remove the middle one | 2 remain, correct two |
| Files tab | Add 3, Remove all three one at a time | Empty state returns |
| Files tab | Clean with 3 queued | Empties list and results |
| Bundle attachments | Add 2, Remove one | 1 remains |
| File association | Double-click one `.gpg` in Explorer | One row, full path, op auto-routed to Decrypt |
| File association | Double-click one `.asc` detached signature | One row, op routed to Verify |
| CLI / second instance | `pgpony <one file>` into a running instance | One row, not path fragments |
| Drag and drop | Drop 1 file, then drop 3 | 1 row, then 4 rows, no duplicates |
| Keyring | Card-paired row | CARD badge visible without opening detail |
| Keyring | Long user ID plus CARD badge, narrow window | Badge group wraps, nothing clipped |
| Keyring | Card row in each of the six locales | Badge fits |
| IA | Message tab: each op reachable, four surfaces unchanged | Radio row selects; output/banner clear on switch |
| IA | Text typed under Encrypt, switch to Decrypt and back | Encrypt text still there (per-op inputs) |
| IA | Double-click `.gpg` / paste-armor open / tray Encrypt | Land on the correct tab AND op |
| IA | Message radio row in German, narrow window | Wraps, nothing compressed (the D12 FileOp case) |
| IA | Remove icon button, hover | Tooltip shows the translated Remove label |

Run the file-association cases on Windows and macOS both, since D13's registration differs per platform and this is the first release to exercise it after a fix.

If Russian ships: every plural key at counts 1, 2, 3, 5, 11, 21, 101, plus a full-screen pass at the widest strings.

## 8. Risks

- The `Path` overload trap is invisible and unlinted. The sweep is the fix for today's instances; nothing prevents tomorrow's.
- The single-file open path has been broken since 1.0.0 and nobody reported it, which suggests either that file associations are little used or that users assumed it was intended. Worth a line in the release notes so people retry the feature.
- The restructure moves controls users have had since 1.0.0. A minor release with release notes that lead with the new shape (and the reporter's rationale) is the mitigation; the operations themselves are unchanged and one click away.
- Muscle memory: anyone scripted around window-automation of the five tabs breaks. Unlikely audience, worth one release-note line.

## 9. Open questions

Resolved Aug 2: 1.1.0 ships all three reported items and holds Russian (→ 2.0.0); badge only for card rows; icon button for Remove. Still open:

- ICU4J dependency or a hand-written CLDR rule table for plurals? (Leaning hand-written; decided in the 2.0.0 doc's terms.)
- Does the Message/Files restructure apply to iOS too, given the desktop inherited the current shape from the phone?
- Reconcile locale sets across the three platforms, or let iOS keep `zh-Hans` alone and desktop add `ru` alone?

## 10. Follow-ups outside the code

- Reply to the reporter. Drafted Jul 30, covering all three desktop items plus the iOS three and the Russian question — update it: all three desktop items are now shipping in 1.1.0, not two-plus-a-deferral.
- Ask PGPonyAndroid whether `values-ru` is in scope before 2.0.0 commits Russian on desktop.
- Point the iOS 8.1.0 KDF work at `CardKdf.kt`, `CardKdfTest.kt`, and the Android 4.0.3 to 4.0.4 notes.
- Add the `Path` overload trap to the working conventions in `CLAUDE.md`. It is exactly the kind of repo-specific hazard that file exists for.

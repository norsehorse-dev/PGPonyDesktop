# PHASE_D8_NOTES.md — password store (plan D8)

## D8 (2026-07-25)

### What shipped

- **The `pass` layer stops being excluded.** `crypto/pass/**` was one blanket exclude since D1;
  it's now three named ones, so `PassModels.kt`, `PassEntryParser.kt` and the new `PassTotp.kt`
  compile **vendored-live**. The entry format, the parser's tolerances and the TOTP generator
  are therefore the same code on Android and desktop — not a copy that can drift.
- **`DesktopPassStore`** (desktop replacement for the SAF-bound `PassStoreService`) — the store
  over `java.nio`: `defaultStorePath()` honoring `$PASSWORD_STORE_DIR` then `~/.password-store`,
  `buildRef()` (a dot-folder gets the display name "Password Store"), `walkTree()` /
  `walkChildren()` (folders before entries, each `lowercase()`-sorted; dotfiles and non-`.gpg`
  files skipped, so `.git/`, `.gpg-id` and `README.md` never appear), `flatten()`, `search()`
  (every space-separated term must appear somewhere in the path), `folderAt()`, `readGpgId()` /
  `recipientsForEntry()` (nearest ancestor `.gpg-id` wins, walking up), and `readEntryBytes()`.
  `MAX_DEPTH = 24` stops a symlink loop; every relative path is resolved through
  `resolveLeaf()`, which refuses `..`, empty segments, backslashes and anything that escapes the
  store root.
- **`DesktopPassStorePrefs`** (same-package twin, declares `object PassStorePrefs`) — the store
  list over `java.util.prefs` + org.json, matched/upserted by `treeUri`. A `java.util.prefs`
  value caps at `Preferences.MAX_VALUE_LENGTH` (8192), so `save()` trims the OLDEST entries
  until the blob fits rather than throwing away the write.
- **`DesktopPassDecrypt`** (same-package twin, declares `PassRoute` + `object
  PassDecryptCoordinator`) — the recipient-matching router, retyped to `DesktopKeyRepository`:
  `Software(rings)` when a held secret key matches a PKESK, `Card` when the match is a
  card-backed key, `NoMatch` otherwise. Same three outcomes Android routes on.
- **`PassScreen`** — the Android trio (store list / browser / entry) collapsed into one two-pane
  window: a store bar (switch, `Add store…`, a one-click `Use ~/.password-store` when that
  folder exists and isn't already listed, `Rescan`, `Remove`), a browse pane with search and
  folder breadcrumbs, and an entry pane running Android's PassEntryScreen state machine name for
  name — `Locked → Working → (PassphraseNeeded | CardNeeded | CardWaiting) → Shown | Failed`.
  Browsing never decrypts; one entry at a time; the tree walk runs on `Dispatchers.IO`.
- **`DesktopClipboard`** — the auto-clearing clipboard every secret copy in the app now goes
  through. On by default, 60 s (clamped 5–600). The timer clears the clipboard **only if it
  still holds what PGPony put there**, so copying something else in the meantime is left alone.
- **`PassTotp` (upstream, shared core)** — RFC 6238, written once in
  PGPonyAndroid `crypto/pass/` and vendored: `parse()` for the Key Uri Format (base32 secret
  with lenient separators and optional padding, SHA1/SHA256/SHA512, 6–8 digits, any sane period,
  issuer from the label or the query), `code()`, `secondsRemaining()`, `grouped()`. TOTP only —
  `hotp` returns null, because a counter-based code has to be written back and the pass
  integration is read-only on every platform. Never throws; a URI it can't use falls back to
  being displayed.
- **Settings** — a "Password store" section: the enable toggle (see below), the default location
  with a status line, and the clipboard controls (auto-clear on/off, the seconds field with
  Apply, and Clear now).
- **Navigation** — `Destination.Pass` with a ⌘4 / Ctrl+4 menu item, both gated on the toggle.

### Decisions worth remembering

- **The tab is off by default**, exactly as on Android: a keyring app shouldn't grow a
  password-manager tab for the majority of users who have no `pass` store. The gate is mirrored
  into `DesktopState.passEnabled` rather than read from `java.util.prefs` at composition time,
  because `Destination.enabled` is a compile-time constant and the rail iterates
  `Destination.entries` — a runtime gate needs a snapshot-state source to recompose. Turning it
  off while the user is standing on the Pass screen also moves them to Keyring rather than
  stranding them.
- **Biometrics → auto-relock.** Android gates the entry screen behind a biometric prompt and sets
  `FLAG_SECURE`. The desktop has neither across three OSes, so the substitute is time: decrypted
  content is dropped after `RELOCK_SECONDS` (120) on screen and on every selection change.
- **TOTP is live now, and shared.** The plan called for RFC 6238 once in the shared core so both
  apps light up together (Android 4.1.0 §7). That's what landed: the generator and its RFC
  vector test are upstream files, and Android's side is a UI change in `PassEntryScreen.kt`
  against the same `PassTotp` object — no second implementation. The desktop shows the code, a
  "rolls in Ns" countdown that turns red under 5 s, and the issuer/algorithm/digits line; the
  setup URI is folded away behind a toggle (it carries the shared secret) but stays copyable, so
  an entry can still be moved to another authenticator.
- **Read-only, and it says so.** Nothing in D8 writes to the store — no add, no edit, no
  `git` anything. `Remove` removes the store from PGPony's list and leaves the folder untouched
  (the status line says as much).
- **Re-reading the tree.** The store is read in place, so a `git pull` or a Syncthing sync can
  change it underneath a long-open window; `Rescan` re-walks without re-selecting the store.

### Vendor sync note

`PassTotp.kt` and `PassTotpTest.kt` were written **upstream first** (PGPonyAndroid
`app/src/main/java/com/pgpony/android/crypto/pass/` and
`app/src/test/kotlin/com/pgpony/android/crypto/pass/`) and copied into `vendor/` as an
**addition-only** sync — no deletions, so nothing else in the vendored trees moved. The next
full `tools/sync-vendor.sh` run picks both up in place with no change.

### Validation

1. `./gradlew test` — `PassStoreTest` (17 cases: the walk's ordering and dotfile/non-`.gpg`
   skipping, entry naming, `folderAt`, search, nearest-`.gpg-id` resolution, the path-escape
   refusals, a missing store reading as null, the store-list round trip and its corrupt-blob
   tolerance, the default-off toggle, the clipboard clamps, the parser cases, and a real
   ED25519_CV25519 keypair encrypting a fixture entry that then routes → decrypts → parses,
   plus the stranger-recipient and wrong-passphrase failures) and `PassTotpTest` (RFC 6238
   Appendix B for SHA1/SHA256/SHA512, defaults, step boundaries, base32 lenience and rejects,
   label/issuer parsing, and the refusals).
2. Settings → Password store → tick "Show the Password Store tab". The rail gains the item
   immediately.
3. Password Store → `Use ~/.password-store` (you have one). Browse: folders sort before entries,
   `.git` and `.gpg-id` are invisible, search narrows on multiple terms.
4. Open a software-key entry → passphrase → password + fields + notes. Copy the password; the
   countdown appears and the clipboard clears itself (paste after it to confirm), and copying
   something else in between leaves your clipboard alone.
5. Open an entry encrypted to a **card** key → the PC/SC dialog (PIN + touch) → same content.
   This is the D7 path reused; it needs the reader plugged in.
6. An entry with an `otpauth://` line shows a rolling code — check it against your authenticator
   app for the same account; they must agree digit for digit.
7. Leave an entry open for two minutes: it relocks itself.
8. Sanity: PGPony must never modify the store. `git -C ~/.password-store status` stays clean
   after all of the above.

### Fix log

**Fix1 — `Unresolved reference 'D'` in PassScreen.kt:769.** The TOTP metadata line was
authored through a scripted edit whose em-dash placeholder variable leaked into the emitted
Kotlin: `config.label + " " + D + " " + config.algorithm` instead of
`config.label + " — " + config.algorithm`. Compile-only; nothing behavioural. (Same class of
slip as the `src/—/` rendering in vendor/README.md earlier the same day — scripted edits that
carry literal dashes now get a post-write grep for bare single-letter identifiers, not just the
NUL check.)

**Fix2 — `Platform declaration clash: setPassEnabled(Z)V` in Gui.kt.** `var passEnabled … private
set` still emits a JVM `setPassEnabled(Z)V` (private, but it occupies the signature), so the
side-effecting `fun setPassEnabled(value: Boolean)` next to it was a second declaration with the
same JVM signature. Renamed to `showPassStore(value: Boolean)` — the one call site is the
Settings toggle. Worth remembering generally: on a Compose-state property with a restricted
setter, never add a hand-written `setX` companion function; pick a verb.

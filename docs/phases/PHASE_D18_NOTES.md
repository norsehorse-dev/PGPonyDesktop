# PHASE_D18_NOTES.md — 2.0.0 files at desktop scale: watch folders (plan 2.0.0 §3c)

## D18 (2026-08-02)

"Anything landing in ~/Backups is encrypted to the offsite key" is now a sentence a user can
say. A watch rule is folder + glob + recipients → encrypt arrivals, over
`java.nio.file.WatchService` (stdlib), riding the D17 streaming encrypt.

### Encrypt-only is the whole security argument

Every design choice falls out of one decision: rules **encrypt only**. Encryption needs only
PUBLIC keys, so a rule that runs while the user is away never holds a passphrase, never touches
a PIN, and a tampered rules file can at worst encrypt things to keys already in the keyring.
There is no field on a `WatchRule` that could ask for a secret, and the engine calls
`encryptFile` with `signerFingerprint = null`, `signerPassphrase = null`. Sign and decrypt stay
interactive, permanently — the plan's line, enforced structurally.

### Model + pure logic — `WatchRule.kt`

- **`WatchRule`** (`@Serializable`): folder, glob (default `*`), recipient fingerprints,
  optional output dir, `deleteOriginal` (default **off** — an unattended delete is the one
  irreversible thing a rule could do), `armor`, `enabled`. **`WatchRules`** wraps a versioned
  list. **`WatchRulesStore`** persists to `<dataDir>/watch-rules.json` (a missing/corrupt file
  loads empty, never throws) and holds the master on/off pref, **off by default** — the
  agent/sentinel posture.
- **`globMatches`** goes through the platform `PathMatcher` (`glob:` syntax); it matches a bare
  filename, so a pattern with `/` never matches (intended), and a malformed glob matches
  nothing rather than throwing (a bad rule is inert).
- **`QuiesceTracker`** is the half-copied-file guard, pure and testable: a file is acted on only
  once its size has held steady across two observations, so an arrival mid-copy is left alone
  until it's been quiet ~2 s.

### The engine — `WatchFolderService.kt`

One daemon `pgpony-watch-folders` thread. It registers each enabled rule's folder with a
`WatchService`, polls with a 1 s timeout so every tick is also a quiesce sweep, and on a stable
match encrypts to the rule's recipients. The anti-loop guard is explicit: a hidden file, a temp
(`.pgpony-enc`), or anything that already `looksEncrypted` is skipped, so the produced `.gpg`
landing back in the watched folder never re-triggers the rule. A file matching several rules on
one folder is encrypted for each; `deleteOriginal` runs only after every matching rule
succeeded. Outcomes go two places — a bounded snapshot-state log the Settings pane renders, and
a tray notification via **`TrayOutbox`** (the watcher thread can't compose, so it hands messages
to the window, the `TrayNav` idiom; `Gui` drains them onto the real `TrayState`).

`encryptFile` gained an optional `outputDir` (defaults to beside-the-source) so a rule can send
ciphertext to a different folder; it keeps the D17 temp+move, so a watched-folder encrypt is
also never-partial.

### Lifecycle + UI

- `DesktopState.enableWatch` starts/stops the service on the master toggle; `refreshWatch`
  reloads rules into a running watcher after an edit; an enabled watcher resumes at launch.
- **`WatchSettings.kt`** (Compose only, kept out of SettingsScreen like the other sections): the
  master toggle, the rules list (per-rule enable / remove), a recent-activity pane, and an
  add-rule dialog — folder + output pickers (a Swing `JFileChooser` in directories-only mode,
  the cross-platform way to pick a folder), glob field, recipient multiselect (the usable-
  recipient rule: a card row needs its public cert), armor and delete-original checkboxes with
  the delete warning shown inline. 20 new `d_settings_watch_*` / `d_watch_notif_*` strings in
  all six locales; strict i18n audit green at 534/534 per locale.

### Verification

`WatchRule` compiled with the real kotlinx-serialization plugin (serializers generated) and
`WatchRuleTest` (9 cases: glob matching incl. filename-not-path and malformed-is-inert, the
quiesce fire/reset/forget semantics, and JSON round-trip + add/remove/toggle persistence) was
compiled and RUN green under JUnit4 in the container. The full main tree compiled with BC +
coroutines + serialization; `WatchRule` and `WatchFolderService` are internally clean (only the
Compose-runtime import flags, as everywhere), the `Gui`/`SettingsScreen`/`FileCryptoOps` wiring
resolves, and `WatchSettings` shows only the standing Compose-absence cascade (its Brand/Layout
helper calls were signature-checked by hand). The WatchService thread itself — copy 3 files in
slowly → 3 outputs after quiesce; restart with rules present → resume, nothing double-encrypted
— is the manual matrix (§8), since a filesystem-event test is flaky by nature. The gradle suite
on the Mac is the gate.

### Deferred / next in the pillar

- **§3d verify-a-download** — pair + hash + `SHA256SUMS` + verify, one verdict banner; the
  `pairDetached` logic already exists. The last file leg.
- Pillar 2 (context menus, clipboard sentinel) remains mostly installer work atop `open --op`.

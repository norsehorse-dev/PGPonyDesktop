# PGPony Desktop 3.1.0 Planning

Status: Rev 3, 2026-11-02 (Rev 0 seed 2026-10-08). Base: 3.0.2.
Split Nov 2: TPM and Secure Enclave keys (was 3c), OS key wrap (Q2), the apt repository (Q4) and the desktop
screens for the Android 4.7.0 engine moved to 4.0.0 (PLANNING_DESKTOP_4_0_0.md).
Release model: as 3.0.0, no release candidates; each stage is self-tested on the Mac, the Windows VM and Linux.

Size tags: S (an evening), M (a few evenings), L (a week or more of evenings).

## Theme

The first item is a duress PIN, asked for by a user for every platform (Android 4.7.0 item 32, iOS 8.4.0 item
1.4). On desktop it needs an app lock first, because PGPony Desktop has none: anyone at an unlocked computer can
open it. 3.1.0 also takes the Android v4.7.3 engine (section 3, the vendor sync; its desktop screens are 4.0.0),
#14 (3f) and portable mode (3e). Section 3b closes the few places where English still shows in a translated build.

## 1. Rules for this cycle

- Same rules as 3.0.0: vendor from an Android tag, never hand-edit vendored files, fixes to vendored code land
  upstream first, and a recorded exception in `vendor/README.md` when desktop takes a file ahead of the tag.
- The duress behavior matches Android and iOS: same names, same setup wording, same result.
- No personal names or handles in this doc, commits or release notes. Issue numbers or "a user" only.
- No em dashes or en dashes.

## 2. App lock and duress PIN

### 2.1 App lock with a PGPony PIN (M, prerequisite)

Today: SessionPolicy holds passphrases for a set time, and ScreenLock / ScreenLockWatch drop them when the
computer locks, but the window itself is never locked.

Work:

- Settings > Security: "Lock PGPony" with a PGPony PIN (6 to 16 digits, or a passphrase), stored as an Argon2id
  hash with its own salt in the preferences node, never the PIN itself.
- Locks at launch, after an idle time the user picks, and when ScreenLockWatch sees the computer lock. The lock
  covers the main window and the tray menu; nothing behind it is drawn until it is unlocked.
- Wrong attempts are counted, with a growing delay after a few.

### 2.2 Duress PIN (M)

- With a PIN set, an optional duress PIN, different from the PIN. Each attempt checks both the same way, so the
  time taken does not tell them apart. Setup says it cannot be undone and is never tested by entering it.
- Entering it runs ClearAllData.run without its confirmation steps (it already covers every key including Recently
  Deleted, the key files overwritten before deletion, settings, watch rules, the agent socket, SOP scratch, held
  PINs and passphrases), with no prompt or progress that says a wipe is happening. ClearAllData closes the app
  afterwards; for the duress path, relaunch straight into first run instead, so it looks like a fresh install.
- Optional, off by default: wipe after a set number of wrong attempts, on the same path.
- Said in the setup text: keys on a hardware key and backups saved elsewhere are not touched. On an SSD or a
  copy-on-write file system (APFS, btrfs) overwriting a file does not guarantee the old blocks are gone, so a
  secret key without a passphrase may be recoverable by someone with the disk. Keys with a passphrase stay
  protected by it. See Q2.

### 2.3 Background services while locked (S to M, see Q1)

The ssh-agent, the git signing shim, the SOP CLI, watch folders and the pass store all use keys without the
window. Decide what each does while the app is locked (Q1), and stop them all as part of a duress wipe (ClearAllData
already stops the agent, the watch folders and the shim bridge).

Test: unit tests for the PIN hashing, the duress check and the attempt counter (ClearAllData already has
dataDirOverride and prefsRootOverride for tests); on each OS, the duress PIN leaves no keys, no Recently Deleted,
no settings, and opens first run; the real PIN unlocks; idle and screen-lock locking; the agent and shim behave as
decided while locked.

### 2.4 Built (Nov 2)

Built on Android's own lock core, vendored verbatim as `vendor/app-lock/` (Android 4.7.0 item 32: PIN hashing,
duress check, counter and delay, wipe flag, file store), so the PIN rules, the timings and the duress behavior are
Android's exactly. Where the build differs from 2.1 to 2.3 as first written:

- PIN only, 6 to 16 digits (Android's PinRules); no passphrase choice. Hashed with Argon2id (32 MiB, 2 passes),
  stored in the data folder (`app_lock`, beside the keyring, so a portable copy carries it), not the preferences
  node. Wrong PINs are counted with Android's growing delay, measured on a clock that a changed wall clock cannot
  rewind (`/proc/uptime` on Linux, `kern.boottime` on macOS, both tied to the boot).
- Locks at launch, after 1, 5 (default), 15, 30 or 60 idle minutes or never, when the computer locks or sleeps,
  and by hand (File > Lock PGPony, Cmd or Ctrl+L, and the tray). While locked the window shows only the PIN screen,
  the menu bar is only Quit, and expiry notices wait.
- Duress PIN and wipe after 5, 10 or 20 wrong PINs (off by default) as Android. Both run ClearAllData with no
  prompt and relaunch straight into first run. The wipe flag is written before anything is deleted, so a wipe cut
  short finishes at the next start (app or CLI).
- 2.3 as answered: the ssh-agent lists no keys and signs nothing, the git shim refuses with "PGPony is locked", and
  `pgpony` asks for the PIN on the terminal (refused with no terminal; the duress PIN wipes and the command runs on
  the empty keyring). `pgpony sop` and the watch folders are outside it.
- Settings > App lock: turn on, change PIN, duress PIN on or off, wipe after, lock after, Lock PGPony, turn off.
  Changing these asks for the PIN once per unlock.

Tests: `DesktopAppLockTest` (unlock, count and delay, duress and wipe, wipe limit, resume after a cut-short wipe,
the CLI gate, agent and shim while locked, idle, both clocks, the relaunch command) and the vendored
`AppLockCoreTest`. Still to do on each OS: the manual pass in the Test line above.

## 3. Android 4.7.0 watch list

Desktop picks these up when Android verifies them, mostly through the vendor re-sync: streaming ML-DSA signatures
for large files (item 23), own-key re-import (item 24, #78), SHA-1 User ID bindings kept and marked weak (item 27),
key certification (item 31), trust levels and Don't use (item 10), offline primary keys (item 22). Already on
desktop: keytocard, per-file encryption, Clear All Data emptying Recently Deleted (Android item 33 is that bug).

Nov 2: done as a full vendor sync to the PGPonyAndroid `v4.7.3` tag (vendor/README.md). The engine for every
item above is in; the desktop UI for items 24, 27, 31, 10 and 22 moved to 4.0.0 (section 4 there). Item 23 is
wired (3f).

## 3a. Blank GTK file chooser on some Linux launches (#12)

Origin: #12 (antiX Linux 26.1). The file chooser opens blank with "drawing failure ... error occurred in
libfreetype", the #1 symptom. Oct 23: it works when PGPony is started cold from the file manager with a .asc
file, and fails when it is started some other way first. The wrapped launcher (tools/linux-wrap-launcher.sh,
packaging/appimage/AppRun) preloads the system libfreetype; every launch that skips it (another menu entry, a
shortcut to PGPony.bin, the lowercase `pgpony` launcher) gets Skiko's FreeType bound into GTK. Oct 23 follow-up:
.deb install, IceWM, usually started from a shortcut that points straight at the executable, and the LD_PRELOAD
workaround from the first reply fixes it. The AppImage fails the same way for them (launch method not given), so
also check AppRun's ldconfig pick on a multiarch system: `ldconfig -p` can list an i386 libfreetype first, and the
awk takes the first line whatever its architecture. Match the x86-64 (or aarch64) entry for the running arch.

Work: make the fix independent of the launcher. On Linux, at the top of main, when LD_PRELOAD does not name a
libfreetype, find the system one the way the wrapper does and re-exec the same command with it set (a guard
variable stops a loop; skipped for CLI verbs that never open a window). Keep the wrappers as the first line.

Nov 2: built. `FreetypePreload.kt` runs just before a GUI launch takes the single-instance guard: on Linux, when
LD_PRELOAD names no libfreetype, it finds the system copy with PcscLibrary's search (distribution directories, a
64-bit ELF file for this architecture) and starts the same launcher (`jpackage.app-path`) again with LD_PRELOAD
set, then exits with its exit code. `PGPONY_FT_PRELOADED` marks the second process; `PGPONY_NO_FT_PRELOAD`
turns it off. Skipped under Flatpak and for the CLI, the shim and SOP. The wrapper and AppRun now take this
architecture's entry from `ldconfig -p` and search the architecture's own directories first (the old glob reached
`i386-linux-gnu` before `x86_64-linux-gnu`). Tests: `FreetypePreloadTest`. Still to do: the antiX VM check with a
shortcut straight at PGPony.bin, and a reply on #12 once a build is out.

## 3b. Translations: close the remaining gaps (S to M)

Every language is already complete. Desktop ships the same eleven languages as Android and iOS, the
desktop-owned layer (`i18n/`, 791 keys) is translated in all ten, Russian included, and Russian has been in since
3.0.0. A request for Russian on desktop most likely came from a build older than 3.0.0. What is left is a short
list of places where English gets through, found Oct 23 on the 3.0.2 tree:

- Korean in the vendored Android strings (synced Sep 27) is missing 437 of 2,010 keys. Four reach the desktop
  UI today (the expired-key blocks and the Allow expired keys setting).
- English that skips `tr()` in desktop-owned code: the two network refusals in DesktopHttpClientFactory (the
  .onion guard and the failed proxy), the four "slot returned no RSA ..." errors in DesktopCardKeygen, and the
  `t.message ?: t::class.simpleName` fallbacks (26 sites), which can show raw exception text or a class name
  such as IOException. Left alone on purpose: the CLI (pinned to English), the trust-level names in
  `PGPonyApp.getString` (a backup wire value, see KeyDetailDialog) and the product names in AppLinks.
- `tools/i18n-audit.py --layer vendor` (the command in the D11 notes) matches no layer and prints only
  "0 error(s)", so the vendor audit has never run. The layer is named `vendor/app-strings`. Run that way, it
  also counts the 7 `translatable="false"` keys as missing in every locale. CI audits only `i18n/`.

Work:

1. Pick up Android's Korean with the string re-sync that comes with section 3 (`tools/sync-strings.sh`).
2. Route the desktop-owned English above through `tr()`: new `d_` keys for the network refusals and the card
   keygen errors, and one shared "something went wrong" sentence in place of `simpleName`, with the raw message
   kept for the log only. New keys go into all eleven languages, translated by one agent and re-read by a second.
3. Fix the audit: accept `vendor` as a name for `vendor/app-strings` and fail on an unknown layer name, skip
   `translatable="false"` keys, and add the vendor layer to build.yml. Correct the D11 notes and the "six
   locales" comment in build.yml.
4. 3.1.0's own new strings (app lock, duress PIN) land in all eleven languages, same two-agent pass.

Test: strict audit green on both layers and I18nTest green; an .onion key server with no proxy and a card error
show in the selected language.

Nov 2: built, except item 1.
1. The v4.7.3 re-sync did not bring Korean: Android's own Korean was missing 389 `err_*` messages. Fixed upstream
   (PGPonyAndroid af491ba, four translators and two readers) and synced here from main ahead of the 4.8.0 tag, a
   recorded exception for resources only (vendor/README.md). Every locale is now complete in both layers.
2. `errorText(t)` in Strings.kt replaces the 21 `message ?: simpleName` sites in the GUI and services (CLI, SOP,
   selftest and the PC/SC cause chain stay English on purpose): the message when there is one, else
   `d_err_unexpected`, with the class name in the debug log. The three network refusals (one reuses Android's
   `err_proxy_turned_but_no_proxy_host`) and the four card keygen errors go through `tr()`. `d_crypto_err_generic`
   is gone (its one caller uses `errorText` now). Seven new keys in all eleven languages, two agents.
3. The audit takes `vendor` (or `android`, `desktop`) as a short layer name, refuses an unknown one, and skips
   `translatable="false"` keys. build.yml audits the vendor layer (not strict, so Android's missing Korean warns)
   and says eleven locales; the D11 notes carry a correction.
4. Done with section 2 (13 keys, two agents).

## 3c. Keys generated in the computer's TPM or Secure Enclave

Moved to 4.0.0 (PLANNING_DESKTOP_4_0_0.md section 1) on Nov 2.

## 3d. SOP: v5 signatures in encrypted messages with several signers (left from 3.0.3)

Deferred on Nov 2: 3.1.0 ships before Android 4.8.0, which carries the engine change, and 4.0.0 does not wait for it
either. It lands in the first desktop release after the 4.8.0 tag (PLANNING_DESKTOP_4_0_0.md, "Not in 4.0.0").

3.0.3 checks LibrePGP v5 signatures in `pgpony sop` (SopLibrePgpV5.kt). A v5 signature over an inline message
hashes the literal data packet's format, file name and date. `inline-verify` reads those from the message, but
`decrypt --verify-with` cannot see them: the literal packet is inside the encryption and DecryptResult does not
carry its fields. There the wrapper takes the engine's graded result instead, which covers one signature. So an
encrypted message signed by a v5 key and another key gets a VERIFICATIONS line for the v5 signature only when the
engine graded that one. A single v5 signer, which is what GnuPG writes, always gets its line.

Work: have DecryptResult carry the literal data fields (format, raw file name, date). That is an upstream change
in PGPonyAndroid, so it comes with the sync, then SopLibrePgpV5 checks every v5 packet with its block. Small (S)
once upstream has it.

Nov 2: v4.7.3 does not have it. The engine already builds the bytes while it decrypts (`st.literalExtra` in
`PGPCryptoService`, from `LibrePgpV5Sig.literalExtra(format, rawFileName, modificationTime)`) and uses them for its
own v5 check, but `DecryptResult` and `DecryptStreamResult` do not return them. The upstream change is one additive
field on each (`literalExtra: ByteArray? = null`), set from `st.literalExtra`. Blocked on PGPonyAndroid (4.8.0) and a
tag; the desktop side is then a few lines in `SopLibrePgpV5`.

Nov 2, later: done upstream in PGPonyAndroid af491ba (DecryptResult, DecryptStreamResult and CardDecryptResult carry
`literalExtra`, tested on every decrypt path), for the 4.8.0 tag.


## 3e. Portable mode: run from a USB drive (M, user request, see Q7)

Request: a copy of PGPony Desktop that runs from a USB drive with nothing installed. Decided: all three platforms
are tried, it ships in 3.1.0, and portable mode refuses to store an unprotected secret key (3e.5).

Today the app already runs without installing (the Linux tarball and AppImage, and every build carries its own
Java), but its state does not travel. `Config.dataDir` puts the keyring on the host (`%APPDATA%\PGPony`,
`~/Library/Application Support/PGPony`, `~/.local/share/pgpony`), and the 16 `Preferences.userRoot()` call sites
write settings to the Windows registry, a macOS plist or `~/.java`. Portable mode moves both onto the drive.

### 3e.1 Turning it on

Portable mode is on when a folder named `PGPony-data` sits beside the app. No guessing whether a drive is
removable: the folder is the switch, and deleting it makes the copy an ordinary install. Where "beside" is:

| Build | The folder that must hold `PGPony-data` | Read from |
| --- | --- | --- |
| Windows app folder | the folder holding `PGPony.exe` | `jpackage.app-path` |
| Linux tarball | the folder holding the `PGPony/` app folder | `jpackage.app-path` (`PGPony/bin/PGPony`) |
| Linux AppImage | the folder holding the `.AppImage` file | `APPIMAGE` environment variable |
| macOS | the folder holding `PGPony.app` | `jpackage.app-path`, translocation resolved (3e.4) |

The CLI launchers (`pgpony`, `pgpony sop`, the git shim) resolve the same folder from their own
`jpackage.app-path`, so a command run from the drive uses the drive's keyring. A `--data-dir <path>` flag on
both the app and the CLI covers anyone who wants the folder somewhere else; it beats the folder check.

### 3e.2 Settings on the drive

A small file-backed `java.util.prefs.PreferencesFactory` stores the preference tree in
`PGPony-data/settings.properties` (atomic replace on write). `Main` sets `java.util.prefs.PreferencesFactory` to it
before any other code runs, beside `Flatpak.apply()`, so the 16 call sites stay as they are and nothing reaches the
registry, the plist or `~/.java`. Outside portable mode nothing changes.

Everything that keeps state goes through dataDir or Preferences, so the 3.1.0 items follow it: the app lock PIN
and duress state (section 2) live on the drive with the keyring. Two things cannot travel and are turned off in
portable mode: keys generated in the TPM or Secure Enclave (4.0.0 section 1, bound to one computer), and key-file
wrapping with an OS-held key (Q2, 4.0.0 section 2).

### 3e.3 What changes on a drive

- Folder permissions. `OwnerOnlyPaths` locks the data folder at every start. FAT32 and exFAT have no permissions,
  so on those it logs once and carries on instead of failing. NTFS keeps its ACLs.
- ssh-agent socket (macOS, Linux). A Unix socket cannot be created on FAT32 or exFAT, so in portable mode it goes
  in a 0700 folder under the host's temp directory and is removed on exit.
- Watch folders and remembered file locations are host paths. One that does not exist on this computer is
  skipped quietly, not reported as an error.
- No file associations, Start menu entry, login item or git shim setup: that is the point. The docs say that a
  git config pointing at the drive breaks when Windows gives the drive another letter.
- Update check: points to the portable download. Updating means replacing the app and keeping `PGPony-data`.

### 3e.4 Platforms

- Windows: the release job zips the installed msi image (both launchers, same files as the msi) with a
  `PGPony-data` folder as `PGPony-windows-portable.zip`, then unzips it, runs `pgpony-cli list-keys` and fails
  if anything appears in `%APPDATA%\PGPony` or the Java preferences key in the registry.
- Linux (Q7): a portable tarball per architecture, `PGPony-linux-x86_64-portable.tar.gz` and
  `PGPony-linux-aarch64-portable.tar.gz`: the wrapped app from the plain tarball in a `PGPony-portable` folder beside
  `PGPony-data`. CI unpacks it, runs `list-keys` and fails if `~/.local/share/pgpony` or `~/.java` appears. The
  plain tarball and the AppImage also turn portable with a `PGPony-data` folder beside them.
- macOS: `PGPony-macOS-portable.zip` and `PGPony-macOS-intel-portable.zip`, each the notarized app plus an empty
  `PGPony-data`, made from the release dmgs by `packaging/release/make-portable-macos.sh` (stapled again as an
  app, Gatekeeper-checked). Gatekeeper runs a quarantined app from a hidden read-only copy (App
  Translocation), so `jpackage.app-path` points into `/private/var/folders/...`. The hidden copy is a nullfs
  mount of the original, so PGPony reads the mount table (`/sbin/mount`) for the original location and looks for
  `PGPony-data` there. No native code and no new dependency (the Security framework route would have needed JNA).
  If the lookup fails the app cannot tell whether portable was meant: it says so on stderr with the
  `xattr -dr com.apple.quarantine` fix and runs as an ordinary install. exFAT drives get AppleDouble `._` files
  beside the data; harmless.

### 3e.5 Secret keys on the drive

Whoever has the drive has the keyring, so in portable mode every secret key stored there must carry a
passphrase:

- Key generation hides the no-passphrase choice.
- Import, restore from backup, GnuPG import and pairing: an unprotected secret key opens the set-passphrase step
  (`DesktopKeyEdits` change passphrase) before it is saved. Cancelling stores the public key only and says so.
- Card-linked keys are unaffected (the secret is on the card).

The database (notes, trust, contacts, revocation certificates) is not encrypted, and the docs say so plainly,
with a recommendation to keep the folder on an encrypted drive (BitLocker To Go, or a VeraCrypt container). They
also say what portable mode is not: the host still sees clipboard contents, the OS's recent-files lists and temp
files. Leaving no trace on the host is a different product (Tails).

### 3e.6 Site and release

- `desktop.json` gets a `portable` block (Windows and both macOS zips, with sha256), `/desktop` a portable section
  with the Linux instructions, and the mirror copies the zips. A new download type needs both the
  `track-click.php` allowlist and the DB ENUM migration (PonyHTML/DEPLOY.md).
- RELEASING.md: the portable files join `FILES` (14 files, 15 signatures with SHA256SUMS). The macOS zips are made after
  the stapler check, from the stapled app.
- winget and AUR unchanged.

Nov 3: done with the release. `/desktop` has a "Portable (run from a USB drive)" table (five builds, each row behind its
own checksum, mirror-aware on the onion and i2p sites), `desktop.json` a `portable` list, and clicks file under three new
values (`desktop_portable_macos`, `_windows`, `_linux`; `api/migrate_add_desktop_portable.php`). The plain Linux tarball
is now labelled "Tarball" beside them. The two Linux portable tarballs counted as `desktop_linux_tar` until then.

### 3e.7 Tests

- Unit: the folder rule for each build type (fake `jpackage.app-path` / `APPIMAGE`), `--data-dir` precedence, the
  preferences factory (round trip, nodes, flush, a crash mid-write leaves the old file), permission fallback on a
  filesystem without POSIX support, the unprotected-key refusal on each import path.
- Windows VM: unzip to a FAT32 stick and an exFAT stick, generate, import, encrypt, decrypt, quit. Process Monitor
  must show no write to the registry outside the OS's own and nothing under `%APPDATA%` or `%LOCALAPPDATA%`.
  Then the same stick on a second Windows account: the keyring is there.
- macOS: download the zip with a browser (so it is quarantined), unzip onto an exFAT stick, launch from Finder
  without clearing the quarantine; the data must land in `PGPony-data`. `fs_usage` shows nothing written under
  `~/Library` beyond the OS's own.
- Linux (Debian VM): tarball and AppImage on an exFAT stick, the same flow, and `~/.local/share/pgpony` and
  `~/.java` stay absent.

## 3f. ML-DSA signing of large files (#14) (S, done)

#14: encrypting and signing a large file with an ML-DSA key failed with "ML-DSA signing reads the whole file
into memory and is limited to 512 MB", the same bug Android fixed in 4.7.0 item 23. With the 4.7.3 engine the
composite signature hashes the content as it streams: `EncryptOps.encryptStream` passes the composite signer, so
single files and folders no longer buffer (the 512 MB limit and its string are gone), detached signing uses
`CompositeDocumentSigner.signDetachedStream`, and detached verify streams the content for composite and classical
signatures alike (it used to read the whole file for both). On decrypt the engine now returns the streamed
composite signature (`DecryptStreamResult.compositeStreamed`) instead of the content bytes; `SignatureSummary`
grades it through `CompositeSignerGate.verifyStreamed`, or a good signature would read "signed by a key not held".
Tests: `MlDsaFileStreamingTest` (file, folder, detached, tamper; a gated 600 MB run passes with a 256 MB heap).

## 4. Questions for Kevin

- Q1. While PGPony is locked, should the ssh-agent and git shim refuse (and say "PGPony is locked"), keep working
  with passphrases already held, or keep working as now? Answered Nov 2: they refuse while locked.
- Q2. Worth wrapping the key files with an OS-held key (macOS Keychain, Windows DPAPI, libsecret) so a duress wipe
  can destroy that one key and make the files unreadable at once, whatever the disk does? A larger change; could
  be its own item later. Answered Nov 2: in 3.1.0, for installed copies only (a portable copy cannot hold an
  OS key, so it keeps the passphrase-only rule of 3e.5). Moved to 4.0.0 (section 2 there) with the split.
- Q4. An apt repository on pgpony.app, signed with the release key, so `apt upgrade` picks up new .deb releases
  (#12: the in-app update notice sends Linux users to download the .deb by hand)? Worth it now, or later?
  Answered Nov 2: in 3.1.0. Moved to 4.0.0 (section 3 there) with the split.
- Q3. Does the CLI (`pgpony` and SOP) ask for the PGPony PIN when the lock is on, or stay outside it? Answered
  Nov 2: `pgpony` asks; `pgpony sop` stays outside (it never touches the keyring).
- Q5. TPM / Secure Enclave keys (3c) are an L item. Keep them in 3.1.0 after the app lock, or move them to the
  next cycle so 3.1.0 stays app lock, duress and Android 4.7.0? Answered Nov 2: keep them in 3.1.0. Then, the
  same day, moved to 4.0.0 with the split (3.1.0 grew too large for a minor version).
- Q6. Linux TPM route: tpm2-pkcs11 through SunPKCS11 (less code, user installs and sets up a token) or libtss2
  through JNA (more code, works with just the `tss` group)? Answered Nov 2: libtss2 through JNA (4.0.0).
- Q7. Portable mode (3e): ship zips for Windows and both Macs and only instructions for Linux, as above, or a
  portable Linux tarball too? Answered Nov 2: a portable Linux tarball too (3e.4).

## 5. Status of this document

Nov 3: released as 3.1.0 (tag v3.1.0, 14 files, GitHub, pgpony.app with its portable section, the onion and i2p
mirror, AUR). The Mac files went up a second time after a reset upload; RELEASING.md now checks the asset count before
publishing.
Nov 3: first run of the test suite on Windows (23 failures, none seen on macOS or Linux). The app lock store's
atomic write used File.renameTo, which cannot replace an existing file on Windows, so every save after the first PIN
failed there: fixed upstream (PGPonyAndroid, Files.move with ATOMIC_MOVE) and taken ahead of the tag as a recorded
exception. Git for Windows checked the GnuPG fixtures out with CRLF line endings: .gitattributes keeps test fixtures
byte-exact. The portable-mode and GnuPG-import tests spelled paths POSIX-style: now real paths for the OS running them.
The duress relaunch and the #12 restart drop the jpackage launcher's _JPACKAGE_LAUNCHER variable (Debian run).
Rev 3 (Nov 2): 3a and 3b built; 3d deferred to the first desktop release after the Android 4.8.0 tag; Korean
strings synced from Android main as a recorded exception.
Rev 2 (Nov 2): split into 3.1.0 and 4.0.0; section 2 built (2.4); 3.1.0's new strings in all eleven languages.
Rev 1 (Nov 2): Q1 to Q7 answered. Rev 0 was the seed with the duress PIN request.
Oct 23: section 3b added (remaining translation gaps; every language, Russian included, is already complete).
Oct 23: section 3c added (keys generated in the TPM / Secure Enclave, user request), with Q5 and Q6.
Nov 1: section 3e added (portable mode, user request): all three platforms, 3.1.0, unprotected secret keys refused; Q7.
Nov 2: section 3 synced (vendor at v4.7.3), 3f added and done (#14), 3e built (portable mode; translocation by
mount table instead of JNA).
Nov 2: Q1 to Q7 answered (section 4); Linux portable tarballs added to 3e.4 and the release workflow.

# PGPony Desktop 3.1.0 Planning

Status: Rev 0 (seed), 2026-10-08. Base: 3.0.2.
Release model: as 3.0.0, no release candidates; each stage is self-tested on the Mac, the Windows VM and Linux.

Size tags: S (an evening), M (a few evenings), L (a week or more of evenings).

## Theme

The first item is a duress PIN, asked for by a user for every platform (Android 4.7.0 item 32, iOS 8.4.0 item
1.4). On desktop it needs an app lock first, because PGPony Desktop has none: anyone at an unlocked computer can
open it. The rest of 3.1.0 follows Android 4.7.0 once its items are verified there (section 3). Section 3b closes the
few places where English still shows in a translated build.

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

## 3. Android 4.7.0 watch list

Desktop picks these up when Android verifies them, mostly through the vendor re-sync: streaming ML-DSA signatures
for large files (item 23), own-key re-import (item 24, #78), SHA-1 User ID bindings kept and marked weak (item 27),
key certification (item 31), trust levels and Don't use (item 10), offline primary keys (item 22). Already on
desktop: keytocard, per-file encryption, Clear All Data emptying Recently Deleted (Android item 33 is that bug).

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

## 3c. Keys generated in the computer's TPM or Secure Enclave (L, user request, see Q5)

Origin: a user, Oct 2026: generate hardware-backed keys on the device itself (no separate hardware key), to use
in workflows that link his devices together.

Today: hardware-backed keys exist only through an OpenPGP card over PC/SC (YubiKey, Token2, Nitrokey):
on-card generation (DesktopCardKeygen, RSA; vendored EdDSA path), keytocard, and card sign / decrypt / ssh-agent.
There is nothing for the computer's own TPM 2.0 (Linux, Windows) or the Mac's Secure Enclave. Outside the app,
GnuPG 2.3+ has `keytotpm` (Linux, tpm2d), which moves an existing software key into the TPM; it does not
generate one there, and the key existed in software first.

Limits that shape the feature:

- TPM 2.0 and the Secure Enclave do P-256 (TPMs also RSA 2048, some 3072). No Ed25519 / X25519 on most TPMs and
  none on the Enclave, and no ML-DSA / ML-KEM anywhere. So these keys are OpenPGP v4 ECDSA P-256 (algo 19)
  primary + ECDH P-256 (algo 18) subkey, which gpg, Sequoia, OpenKeychain and PGPony mobile all read.
- The private key never leaves the chip: no backup, no export, no move to another computer. Clearing the TPM
  (fTPM reset on a firmware update, "clear TPM" in the BIOS, a new motherboard) or replacing the Mac loses it.
  For several devices the model is one key per device, shared as public keys (pairing already moves those).

Work:

1. Platform key seam. Mirror the card path, which already splits the private operation from the OpenPGP
   packets: a PlatformPGPContentSigner next to CardPGPContentSigner, a PlatformPublicKeyDataDecryptorFactory
   next to CardPublicKeyDataDecryptorFactory (reusing Rfc6637 / EcdhCipherData for the KDF and key unwrap),
   and P-256 ECDSA / ECDH public-key packet building next to CardKeyPacketBuilder (today hardcoded to EdDSA /
   Cv25519; the RSA twin is desktop-only). The P-256 packet code is portable, so it lands upstream in
   PGPonyAndroid first and is vendored (it would also serve Android Keystore / StrongBox later); only the OS
   bindings are desktop twins.
2. OS bindings:
   - Windows: CNG Platform Crypto Provider through JNA (`NCryptOpenStorageProvider` with
     `MS_PLATFORM_CRYPTO_PROVIDER`, ECDSA_P256 for signing, ECDH_P256 with `NCryptSecretAgreement` for decrypt).
     Nothing to install.
   - Linux: TPM 2.0. Either `tpm2-pkcs11` through the JDK's SunPKCS11 provider (least new code, but needs the
     user to install and init a token) or `libtss2-esys` through JNA (more code, needs `/dev/tpmrm0` access via
     the `tss` group). See Q6.
   - macOS: Secure Enclave P-256 through Security.framework (`kSecAttrTokenIDSecureEnclave`, sign and
     `SecKeyCopyKeyExchangeResult`). Needs the signed and notarized build with a keychain-access-groups
     entitlement, so it only works from the release dmg. A small Swift helper or JNA on Security.framework.
3. UI: "Generate on this computer" beside "Generate on card" in key creation, with an optional PIN (TPM
   authValue / Enclave user presence or Touch ID). The certificate list gets the same kind of badge planned for
   card-linked keys. Setup says plainly that the key cannot be backed up and suggests also encrypting to a second
   key (another device or a card).
4. Everywhere a card key works, a platform key works: sign, decrypt, git signing shim, ssh-agent (ecdsa-sha2-nistp256),
   SOP CLI. Backup and Clear All Data handle a key whose secret is a handle, not key material; Clear All Data and
   the duress wipe (2.2) also delete the TPM / Enclave key.

Test: per OS, generate, sign, decrypt, and a message encrypted by gpg and by PGPony Android to the new public key
opens; the key ring file copied to another computer decrypts nothing; deleting the platform key makes decrypt
fail with a plain message; an offline test with a software P-256 key in place of the chip checks the packets and
fingerprint against real gpg, the same way the RSA card keygen test does.

## 3d. SOP: v5 signatures in encrypted messages with several signers (left from 3.0.3)

3.0.3 checks LibrePGP v5 signatures in `pgpony sop` (SopLibrePgpV5.kt). A v5 signature over an inline message
hashes the literal data packet's format, file name and date. `inline-verify` reads those from the message, but
`decrypt --verify-with` cannot see them: the literal packet is inside the encryption and DecryptResult does not
carry its fields. There the wrapper takes the engine's graded result instead, which covers one signature. So an
encrypted message signed by a v5 key and another key gets a VERIFICATIONS line for the v5 signature only when the
engine graded that one. A single v5 signer, which is what GnuPG writes, always gets its line.

Work: have DecryptResult carry the literal data fields (format, raw file name, date). That is an upstream change
in PGPonyAndroid, so it comes with the sync, then SopLibrePgpV5 checks every v5 packet with its block. Small (S)
once upstream has it.


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
portable mode: keys generated in the TPM or Secure Enclave (3c, bound to one computer), and any key-file wrapping
with an OS-held key (Q2), if that is adopted.

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

- Windows: the release job also zips the app image (`createDistributable`) with an empty `PGPony-data` as
  `PGPony-windows-portable.zip`.
- Linux: no new file. The tarball and AppImage gain the folder check; the docs say to make `PGPony-data` beside
  them. (A portable tarball with the folder inside would be a third Linux tarball for one empty folder.)
- macOS: `PGPony-macOS-portable.zip` and `PGPony-macOS-intel-portable.zip`, each the notarized, stapled
  `PGPony.app` plus an empty `PGPony-data`. Gatekeeper runs a quarantined app from a hidden read-only copy (App
  Translocation), so `jpackage.app-path` points into `/private/var/folders/...`. PGPony asks the Security
  framework for the original location (`SecTranslocateIsTranslocatedURL` and
  `SecTranslocateCreateOriginalPathForURL`, as Sparkle does) and looks for `PGPony-data` there. That call needs
  JNA, a new dependency pinned in `gradle/verification-metadata.xml` (3c's libtss2 route would need it too). If
  that fails, it says so and explains how to clear the quarantine, never falling back to the host's Application
  Support in silence. exFAT drives get AppleDouble `._` files beside the data; harmless.

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
- RELEASING.md: the zips join `FILES` (12 files, 13 signatures with SHA256SUMS). The macOS zips are made after
  the stapler check, from the stapled app.
- winget and AUR unchanged.

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

## 4. Questions for Kevin

- Q1. While PGPony is locked, should the ssh-agent and git shim refuse (and say "PGPony is locked"), keep working
  with passphrases already held, or keep working as now?
- Q2. Worth wrapping the key files with an OS-held key (macOS Keychain, Windows DPAPI, libsecret) so a duress wipe
  can destroy that one key and make the files unreadable at once, whatever the disk does? A larger change; could
  be its own item later.
- Q4. An apt repository on pgpony.app, signed with the release key, so `apt upgrade` picks up new .deb releases
  (#12: the in-app update notice sends Linux users to download the .deb by hand)? Worth it now, or later?
- Q3. Does the CLI (`pgpony` and SOP) ask for the PGPony PIN when the lock is on, or stay outside it?
- Q5. TPM / Secure Enclave keys (3c) are an L item. Keep them in 3.1.0 after the app lock, or move them to the
  next cycle so 3.1.0 stays app lock, duress and Android 4.7.0?
- Q6. Linux TPM route: tpm2-pkcs11 through SunPKCS11 (less code, user installs and sets up a token) or libtss2
  through JNA (more code, works with just the `tss` group)?
- Q7. Portable mode (3e): ship zips for Windows and both Macs and only instructions for Linux, as above, or a
  portable Linux tarball too?

## 5. Status of this document

Rev 0 seed with the duress PIN request. Goes to Rev 1 when Q1 to Q3 are answered and Android 4.7.0's scope settles.
Oct 23: section 3b added (remaining translation gaps; every language, Russian included, is already complete).
Oct 23: section 3c added (keys generated in the TPM / Secure Enclave, user request), with Q5 and Q6.
Nov 1: section 3e added (portable mode, user request): all three platforms, 3.1.0, unprotected secret keys refused; Q7.

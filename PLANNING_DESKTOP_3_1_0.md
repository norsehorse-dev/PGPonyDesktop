# PGPony Desktop 3.1.0 Planning

Status: Rev 0 (seed), 2026-10-08. Base: 3.0.2.
Release model: as 3.0.0, no release candidates; each stage is self-tested on the Mac, the Windows VM and Linux.

Size tags: S (an evening), M (a few evenings), L (a week or more of evenings).

## Theme

The first item is a duress PIN, asked for by a user for every platform (Android 4.7.0 item 32, iOS 8.4.0 item
1.4). On desktop it needs an app lock first, because PGPony Desktop has none: anyone at an unlocked computer can
open it. The rest of 3.1.0 follows Android 4.7.0 once its items are verified there (section 3).

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

## 4. Questions for Kevin

- Q1. While PGPony is locked, should the ssh-agent and git shim refuse (and say "PGPony is locked"), keep working
  with passphrases already held, or keep working as now?
- Q2. Worth wrapping the key files with an OS-held key (macOS Keychain, Windows DPAPI, libsecret) so a duress wipe
  can destroy that one key and make the files unreadable at once, whatever the disk does? A larger change; could
  be its own item later.
- Q3. Does the CLI (`pgpony` and SOP) ask for the PGPony PIN when the lock is on, or stay outside it?

## 5. Status of this document

Rev 0 seed with the duress PIN request. Goes to Rev 1 when Q1 to Q3 are answered and Android 4.7.0's scope settles.

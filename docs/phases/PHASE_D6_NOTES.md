# PHASE_D6_NOTES.md — Backup / restore (plan D6)

## D6 (2026-07-24)

### What shipped

- **`vendor/app-backup/`**: the backup codecs vendored verbatim — `CrockfordBase32` (120-bit
  code, typo-tolerant normalize) and `UstarArchive` (strict ustar) — plus `BackupCodecTest`
  into the test tree. `BackupService.kt` is Gradle-excluded (app-coupled: KeyRepository,
  org.json, Android settings).
- **`DesktopBackupService`** — the twin, mirrored from the Android implementation:
  - Export: meta-first strict-ustar (`pgpony-meta.json` with `platform:"desktop"`,
    `keys/<fp>.asc` per key), sealed SKESK v4 / AES-256 / iterated-salted SHA-256 / SEIPDv1+MDC
    (`useAead=false, useArgon2=false` — the gpg-compat posture), armored with
    `Comment: PGPony Backup v1` and no Version header. Card-backed keys export public-only.
  - Restore: normalize → decrypt (wrong-code vs corrupt distinguished the same way) → strict
    untar → per-key merge-import mapped onto the five report buckets — a held secret is never
    overwritten — trust reapplied from meta for changed rows only.
  - **OpenKeychain restore** (the Succession): `detectKind` by armor header, `numeric9x4` code
    rebuilt WITH hyphens, payload exploded into per-ring merge imports.
  - Desktop writes no `pgpony-settings.json` yet (network settings arrive at D4; the entry is
    additive-optional by spec) and ignores one on restore — `settingsApplied` stays false.
    Wire it up in D4's closing pass.
- **Settings UI**: Back up keyring… (code display + copy + the format's **forced re-entry**
  before the file can be written) and Restore backup… (file picker with kind detection, code
  entry, full merge report). Keyring reloads after restore.
- **Tests** (4 + vendored codec suite): round-trip with sloppy code entry (lowercase, hyphens,
  o→0/l→1) + trust reapplication + public-only preservation + idempotent re-restore; upgrade
  path + wrong-code error; card-backed public-only rule; numeric9x4 rebuild.

### Validation (closes D6 when green)

1. `./gradlew test`.
2. `./gradlew run` — Settings → Back up keyring…: copy the code, re-enter it (try typing it
   sloppily), save; Restore into place → everything "already up to date".
3. **The cross-restore triangle** (the real point):
   - Android → desktop: make a backup on the phone, restore it here — expect your keys with
     trust intact, secrets present, card keys public-only.
   - Desktop → Android: restore this backup on the phone (or a scratch profile).
   - iOS → desktop if you have an iOS backup handy (`Androidbackupref.pgpony`-era files
     qualify — the format doc was reverse-engineered from one).
4. gpg posture check: `gpg --decrypt backup.pgpony` with the hyphen-stripped code decrypts the
   container (the tar inside is the plaintext).
5. If you have an OpenKeychain backup around: restore it via the same dialog (auto-detected).

### Fix log

- **Fix1 (first run): trust reapply no-opped** — "expected VERIFIED but was UNKNOWN." The
  engine stores fingerprints UPPERCASE while the backup format lowercases them everywhere;
  `byFingerprint` tried exact + lowercase but never uppercase, so `updateTrustLevel` (and the
  restore-report labels) matched nothing — silently, because mutations tolerate missing rows.
  Fix: `byFingerprint` now falls back to the uppercase form too. This is the D2c
  "normalized-fingerprint scan" gap biting exactly where predicted; the full
  KeyDeduplicationService port remains the complete answer.

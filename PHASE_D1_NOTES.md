# PHASE_D1_NOTES.md — PGPony Desktop skeleton (plan D1)

> First executable phase of `PLANNING_DESKTOP_1_0_0.md` (PGPonyAndroid repo root). Everything
> here was authored against the RelayPonyDesktop-proven toolchain; the build itself runs on
> Kevin's machine (the authoring environment has no Maven access — see "Validation" for the
> checklist that closes this phase).

## What D1 ships

- **Project skeleton** mirroring RelayPonyDesktop: plain `kotlin("jvm")` build, Kotlin 2.2.10,
  Compose Multiplatform 1.11.1, Gradle wrapper 9.4.1 (wrapper files copied from
  RelayPonyDesktop verbatim), one binary with GUI + CLI faces, jpackage nativeDistributions
  (Dmg/Deb/Msi) preconfigured including the macOS env-var signing/notarization contract and a
  fresh MSI upgradeUuid.
- **The vendored engine**: `vendor/app-crypto` = verbatim `crypto/` tree from PGPonyAndroid
  4.0.3 — PGPCryptoService, Signing/Verify/ClearSigned, KeyExpiration, Revocation, the full
  card protocol stack, the PQC composite layer (both wire formats), MIME, util. Two Gradle
  excludes + three shims (inventoried in `vendor/README.md`); everything else compiles as-is.
  `modules("jdk.smartcardio")` is already in the runtime image for D7.
- **Keyring (bootstrap)**: import from file (native picker) and pasted armor, multi-block
  splitting, dedupe-by-fingerprint with public→secret upgrade (a held secret is never
  overwritten — the BACKUP_FORMAT_4_0_0 restore rule, applied from day one), list UI with
  algorithm/SECRET pills and grouped fingerprints.
- **Theme**: the exact Android A12 palette (both schemes verbatim), System/Light/Dark picker
  persisted via java.util.prefs.
- **CLI**: `selftest` (BC provider + v4 round-trip + v6 round-trip + store round-trip) and
  `version`. Full verb set is D10.
- **Tests**: engine round-trips (v4 + v6) and store merge/persistence semantics.

## Decisions + deviations recorded

1. **JSON bootstrap store instead of Room** (plan said Room in D1). Room+KSP is the most
   version-fragile piece of the whole port and the authoring environment cannot resolve
   Maven artifacts to verify a pinning. Rather than risk a broken first build, D1 uses a
   deliberately thin JSON store (`KeyringStore`) that keeps each key's FULL armored block —
   secrets stay inside their own S2K protection (D0-3 posture; the store adds no crypto).
   **Room KMP is the first work item of D2**, on a machine where Gradle can iterate live;
   migration = re-import of the stored armored blocks, which is why they are kept verbatim.
2. **Vendor excludes are references-driven, not paranoia-driven.** The only crypto files that
   couldn't vendor: `pass/**` (Room repository import) and `CardPinCache` (Context +
   PGPonyApp). `OpenPgpCardSession` calls `CardPinCache.clear()/remember()` only, so the
   desktop twin preserves that exact API. `RevocationService` needed only the plain
   `RevocationReason` enum — shimmed verbatim, deleted again when the entity vendors in (D2).
3. **Icons deferred**: no `packaging/` icon set yet; installers use the default icon until
   D12 (generate .icns/.ico/.png from the shipped app icon set — `android_icons/` upstream).
4. **`packageVersion = "1.0.0"`** (jpackage version-format constraints); the in-app version
   string is `1.0.0-dev.D1` until release.
5. Vendored `.DS_Store` copies: the bridge can't delete files — if any survived under
   `vendor/`, delete them by hand (or run `tools/sync-vendor.sh`, whose copy strips them).

## Validation (closes D1 when green)

On the Mac, in `~/Apps/PGPonyDesktop`:

1. `chmod +x gradlew tools/sync-vendor.sh` (bridge-written files land 0600/without exec).
2. `./gradlew test` — 4 tests green (2 engine round-trips, 2 store suites).
3. `./gradlew run --args=selftest` — 4 ✓ lines, `PASS`.
4. `./gradlew run` — window opens; import a public `.asc` (file + paste paths); relaunch and
   confirm the key survives; flip the theme and relaunch (persists).
5. Cross-check: export a public key from PGPony Android, import it here; fingerprints match.
6. (Later, D1 stretch) same `run` + `test` pass on a Linux box/VM and Windows — or wait for
   the D12 CI matrix to prove it.

Compile fixes discovered during validation belong in this file's "Fix log" as
`PHASE_D1_Fix1_NOTES.md`-style entries if they grow beyond a line or two.

## Fix log

- **Fix1 (2026-07-24, first Mac build):** `Unresolved reference 'CardPinCache'` in the vendored
  `OpenPgpCardSession`. Cause: Kotlin source-set `exclude` patterns are **set-wide** (they apply
  to every srcDir, including `src/main/kotlin`), so `exclude("**/card/CardPinCache.kt")` removed
  the desktop twin along with the vendored copy — RelayPony never hit this because its
  replacement file (`DesktopDiscovery.kt`) had a different name. Fix: the twin file is renamed
  `DesktopCardPinCache.kt` (still declares `object CardPinCache`, unchanged API). **Rule for
  future twins: never share the vendored file's NAME.**
- Benign, expected at configure time: the `compose.material3` / `compose.materialIconsExtended`
  accessor deprecation warnings (CMP 1.11 pins icons-extended at 1.7.3). Migrating to explicit
  artifacts / Material Symbols is D12 hygiene, not a D1 concern.

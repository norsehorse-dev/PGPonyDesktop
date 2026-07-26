# PHASE_D2_NOTES.md — Keyring parity (plan D2)

> D2 runs in slices: **D2a** (this entry) = the Room data layer. **D2b** = keygen + key detail
> read view + export flows + dedup/merge port. **D2c** = key-detail mutations (expiration,
> revocation, trust, notes) + search/sort/reorder. Slicing is an execution decision, not a scope
> change — the D2 definition in `PLANNING_DESKTOP_1_0_0.md` stands.

## D2a — Room KMP data layer (2026-07-24)

### What shipped

- **Version pins** (the fragile part, verified against Maven metadata + androidx release
  notes): KSP `2.2.10-2.0.2` (exact Kotlin 2.2.10 match), Room `2.8.4` + `sqlite-bundled`
  `2.6.2` (same-day androidx release train, 2025-11-19).
- **Upstream move-only refactor in PGPonyAndroid** (approved): the six `MIGRATION_*` vals moved
  verbatim from `data/PGPKeyEntity.kt` to new `data/RoomMigrations.kt` (same package — every
  reference resolves unchanged); the entity file's two Android-only imports dropped; two
  comment lines updated (entity header + `PGPonyApp.kt` builder note). The edit was performed
  mechanically (head/sed/tail on the live file) and diff-verified to touch exactly those lines.
  **Android is otherwise untouched; run any Android compile/test at the next convenient window
  to confirm (expected: no-op).**
- **`vendor/app-data/`**: the `data/` tree vendored verbatim (post-move). Compiled into the
  desktop build: `PGPKeyEntity.kt` (TrustLevel + converters + RevocationReason + entity + DAO +
  `PGPDatabase` v7), `ApiClientEntity.kt`, `AutocryptPeerEntity.kt`. Everything else excluded
  with documented paths back (`vendor/README.md`).
- **`Db.kt`**: the vendored `PGPDatabase` opened on the JVM — `Room.databaseBuilder<PGPDatabase>`
  + `BundledSQLiteDriver` + IO query context. No migration chain registered: fresh desktop DBs
  create at v7. Same filename as Android (`pgpony.db`).
- **`KeyMaterialStore`**: desktop counterpart of SecureKeyStore — armored key halves as files
  under `keys/`, 0600, D0-3 GnuPG posture (secrets keep their own S2K protection; the store
  adds no crypto).
- **`DesktopKeyRepository`**: import (single / multi-block / bytes with explode fallback),
  resolutions mirroring Android's vocabulary (`INSERTED` / `UPGRADED_TO_KEY_PAIR` /
  `ALREADY_IN_KEYRING`; card-pairing and material-merge resolutions arrive D7/D2b), exports,
  delete, fingerprint lookup, and the **one-shot D1 `keyring.json` migration** (imports the
  stored armored blocks, renames the file `.migrated`).
- **UI**: keyring rows now render from the vendored entity (its `formattedFingerprint`,
  version-aware `longKeyId`, `isExpired`, `algorithm.displayName`), plus copy-public-to-clipboard
  and delete-with-confirmation (secret-loss warning). D1's `KeyringStore`/tests retired to
  `_to_delete/`.
- **New shim** `AndroidAppShim.kt`: vendored `TrustLevel.localizedName()` reaches inline into
  `PGPonyApp.instance.getString(R.string.trust_level_*)`; the shim supplies both symbols with
  the English values from Android's `strings.xml`. The `RevocationReason` shim is deleted — the
  real enum now vendors in.

### Decisions + upstream candidates recorded

1. **No migration chain on desktop** — Room only runs migrations on version upgrades, and
   desktop has no pre-v7 databases. Future schema bumps add KMP-style (`SQLiteConnection`)
   migrations desktop-side while Android keeps its `SupportSQLiteDatabase` chain, both derived
   from the same entity change.
2. **Upstream cleanup candidate (not done):** `TrustLevel.localizedName()/localizedDescription()`
   belong in a UI-layer extension, not on the entity-file enum — the entity file would then
   carry zero app/R references and `AndroidAppShim.kt` dies. Needs one import line added per
   call site in the Android app; propose alongside the next Android UI change.
3. **Upstream seam candidates carried:** CardPinCache KeyValueSettings interface (D1);
   KeyRepository's `SharedPreferences` parameter (blocks vendoring the full repository — the
   desktop twin covers D2a needs meanwhile).
4. **Fingerprint normalization**: material filenames lowercase; DAO lookups try exact then
   lowercase. The full case/format-variant scan is the dedup service port (D2b).

### Validation (closes D2a when green)

In `~/Apps/PGPonyDesktop`:

1. `./gradlew test` — 6 tests green (2 engine round-trips + 4 repository suites: semantics,
   delete, legacy migration, multi-block).
2. `./gradlew run --args=selftest` — 4 ✓ including "Room keyring: import → reopen → read".
3. `./gradlew run` — if you had imported keys in D1, expect a "Migrated D1 store" status line
   and the same keys listed (now from Room); import/copy/delete all work; relaunch persists.
4. In `~/Apps/PGPonyAndroid`: any compile (e.g. `./gradlew compileFossDebugKotlin`) to confirm
   the migrations move is the expected no-op.

### Fix log

- (none yet)

## D2b — Keygen, key detail, exports (2026-07-24)

### What shipped

- **`DesktopKeyRepository.generateKey`** — the Android KeyRepository.generateKey sequence:
  generate → store both armored halves → derive expiry from the generated master key →
  pre-cache a NO_REASON revocation certificate via the vendored `RevocationService` (catching
  `RevocationError` non-fatally, as upstream) → insert entity.
- **Generate dialog** with the full generatable roster — the exact branches of the vendored
  `generateKeyPair`: Ed25519+Cv25519 (default), v6 Ed25519, **ML-KEM-768+X25519 (IETF v6)**,
  **ML-KEM-768+X25519 (LibrePGP)**, RSA-4096, RSA-2048 — plus passphrase + confirm with an
  unprotected-key warning. (The Android Pro gate on key count is not ported — desktop
  monetization is an open question in the plan.)
- **Key detail (read-only)**: status pills (SECRET/CARD/REVOKED/EXPIRED/trust), click-to-copy
  fingerprint, version-aware key ID, notes display, and a per-key **subkey list** built from
  the vendored helpers (`detectAlgorithm`, `SubkeyCapability` self-sig key-flags with heuristic
  fallback, `fingerprintHex`).
- **Exports**: Copy public (the ForSharing armor variant — comment header semantics matching
  Android's share surfaces), Export public…, Export secret… (native save dialog; secret keeps
  its S2K protection, said in the UI).
- **Tests**: v4 generate (pair + both halves + revocation cert + 2 subkeys with capability
  labels), v6 generate (64-char fingerprint), and a **composite PQC generate** — the vendored
  `CompositeKeyGen` running on the desktop JVM.

### Upstream find (report to PGPonyAndroid 4.1.0 roster)

**The Android pre-cached revocation certificate appears to be dead code.** `generateKey` builds
`importResult` from `crypto.importKeyData(result.publicKeyData)` — public bytes — then reads
`importResult.secretKeyRing` for cert generation. A public-only import cannot carry a secret
ring, so `preCachedRevocationCert` is always null and shipped 4.0.3 never pre-caches certs at
generation (the Phase A6 doc comment describes the intended behavior). The desktop port
generates the cert from the private armor instead (intent-true), and `GenerateKeyTest` asserts
it non-null. Suggested Android fix: parse the secret ring (e.g.
`crypto.importArmoredKey(result.armoredPrivateKey).secretKeyRing`) at the pre-cache site, plus
a regression test on `entity.revocationCertificate != null`.

### D2b re-slice note

The dedup/merge port (KeyDeduplicationService, MERGED_NEW_MATERIAL) moves from D2b to **D2c**,
joining the mutation set — it touches the same rows the mutations do.

### Validation (closes D2b when green)

1. `./gradlew test` — 9 tests (2 engine, 4 repository, 3 generate incl. PQC).
2. `./gradlew run` — New key… generates each algorithm you care to try (RSA-4096 takes a
   moment; the dialog shows busy); the new key lands in the list with SECRET pill; click a card
   → detail shows subkeys + capabilities; Copy public / Export public… / Export secret… work;
   exported secret re-imports elsewhere (e.g. gpg --show-keys) cleanly.
3. Cross-check: a desktop-generated v6 or PQC public key imports clean on Android/iOS.

### Fix log (D2b)

- (none yet)

## D2c — Mutations, merge, search/sort (2026-07-24)

### What shipped

- **Mutations** (the Android KeyRepository update section, ported onto the vendored services):
  trust level (radio set in detail), notes (editor dialog), default signing key (clears the
  previous default — DEFAULT pill on cards + detail), **expiration editing** (vendored
  `KeyExpirationService.setExpirationSoftware` re-sign; never/date + passphrase dialog;
  card-backed keys refused with a D7 pointer, as upstream), and the **Danger Zone revoke flow**
  (reason picker with the five RFC 4880 reasons + descriptions, optional comment, passphrase,
  cannot-be-undone confirm; vendored `RevocationService` generate→apply→persist sequence;
  post-revocation the cert exports via save dialog, and REVOKED pills appear everywhere).
- **Merge-new-material** — the dedup-service subset for re-imports: byte-identical public
  material → ALREADY_IN_KEYRING; differing material → `PGPPublicKeyRing.join` into the stored
  ring (trust/notes/secret/card columns untouched), with revocation detection flipping
  `isRevoked` when the incoming material carries one. `MERGED_NEW_MATERIAL` joins the report
  vocabulary.
- **Search + sort** in the keyring: query over name/email/fingerprint, sort by
  Recent/Name/Algorithm.
- **Tests**: trust/notes/default round-trips; revocation (entity stamped + ring carries the
  self-sig); expiration set + removal; merge (clean import → revoked re-import merges and flips
  isRevoked; identical re-import reports already).

### Deliberately deferred / dropped

- **Manual drag-reorder** (Android SortMode.MANUAL): needs `sh.calvin.reorderable` proven on
  desktop — deferred to a later slice rather than risking a dependency on a mutation phase.
- **Contact link** UI: dropped on desktop (plan §2) — the columns persist untouched for backup
  round-trips.
- **Full normalized-fingerprint dup scan** (case/format variants beyond exact+lowercase) and
  `runDedupeSweepIfNeeded`: still with the KeyDeduplicationService port question (upstream
  SharedPreferences/Log seams), revisit at D6 where restore semantics need it most.

### Validation (closes D2c when green)

1. `./gradlew test` — 13 tests.
2. `./gradlew run` — on a generated key: set trust (pill updates), add notes, make default
   (DEFAULT pill moves between keys), edit expiration (date + passphrase; card shows new date;
   wrong passphrase surfaces a readable error), then revoke a throwaway key (REVOKED pill,
   revocation cert exports, encrypt-side exclusion arrives with D3); re-import the revoked
   public over a clean copy elsewhere → status shows "merged new material".
3. Search narrows across name/email/fingerprint; sort modes reorder sensibly.

### Fix log (D2c)

- **Fix1 (first Mac build):** `KeyExpirationService.UpdatedRings.secretRing` is nullable (the
  card expiration path carries no secret ring) — the desktop persist now guards with `?.let`,
  matching Android's `persistExpiration`.

## D2c — (pending)

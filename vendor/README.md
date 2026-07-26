# vendor/ — verbatim PGPonyAndroid sources

Verbatim copies from `PGPonyAndroid/app/src/main/java/com/pgpony/android/`:

- `app-crypto/` = the `crypto/` tree (OpenPGP engine: packet handling, v4/v6 keys, PQC
  composite, card protocol, MIME, util). Synced D1. The `pass/` subtree joined the compile
  at D8: `PassModels.kt`, `PassEntryParser.kt` and `PassTotp.kt` (RFC 6238, added upstream
  in D8) are pure Kotlin/JDK and compile VERBATIM; the three Android-coupled files there
  are excluded with twins (table below).
- `app-data/` = the `data/` tree (Room entities, DAOs, `PGPDatabase` schema v7,
  services). Synced D2a — after the upstream move-only refactor that relocated the
  migration chain from `PGPKeyEntity.kt` into `data/RoomMigrations.kt`.
- `app-backup/` = the `backup/` tree (Crockford recovery codes, strict-ustar archive). Synced
  D6. `BackupService.kt` excluded (app-coupled: KeyRepository, org.json, Android settings) —
  desktop twin `src/…/desktop/DesktopBackupService.kt`.
- `app-network/` = the `network/` tree (KeyServerRepository, WkdService, DTOs) + the
  `keyserver/` tree (MultiKeyServerService + the excluded KeyServerDirectory). Synced D4. The
  ktor "Android" client engine is a plain-JVM artifact, so the vendored services run
  unchanged; three Android-coupled files are excluded with twins (table below).
- `app-strings/` = the six `res/values*/strings.xml` files (en, de, es, fr, ja, pt-rBR). Synced
  D11. NOT compiled — mounted as RESOURCES by `processResources` under `/i18n/android/…`, beside
  the desktop-owned `i18n/` tree at `/i18n/desktop/…` (the two use Android's identical directory
  shape, so they need distinct prefixes or they overwrite each other in the jar). A key belongs
  to whichever layer's ENGLISH file declares it, so a desktop key can later be retired in favor
  of an upstream one with no call-site change. Refreshed by `tools/sync-strings.sh`, NOT by
  `sync-vendor.sh`. A placeholder or parity finding in this tree is an UPSTREAM bug — fix it in
  PGPonyAndroid and re-sync.
- `app-crypto-tests/` = the crypto unit-test suite (+ `data/PGPKeyEntityKeyIdTest.kt`,
  `backup/BackupCodecTest.kt`) and `app-test-resources/` = its fixtures (rfc9580 vectors, pqc
  interop artifacts). Synced D5/D6; compiled into the desktop `test` source set, gates
  (`-DrunInterop`, `-DiosSecPass`) preserved.

Last sync: 2026-07-25 (D11 — `app-strings/`, the six strings.xml files, a new tree with its own
script. D8 — addition-only: `crypto/pass/PassTotp.kt` and the test
`crypto/pass/PassTotpTest.kt`, both written UPSTREAM in PGPonyAndroid first and copied in.
D4 — network + keyserver trees; other trees unchanged since 2026-07-24), from
PGPonyAndroid 4.0.3 (versionCode 403) + the D2a migrations move + the D8 TOTP core.
Re-sync: `tools/sync-vendor.sh` (delete-and-recopy), then `./gradlew test` — EXCEPT
`app-strings/`, which is `tools/sync-strings.sh` (also delete-and-recopy, and it runs
`tools/i18n-audit.py` at the end).
NEVER hand-edit files here — fix upstream in PGPonyAndroid and re-sync.

## Excluded in build.gradle.kts

Excludes are SET-WIDE (every srcDir, including `src/`), so a desktop twin must never share an
excluded file's name (D1 Fix1).

| Path | Why | Path back |
|---|---|---|
| `crypto/pass/PassStorePrefs.kt` | SharedPreferences | Desktop twin `src/…/android/crypto/pass/DesktopPassStorePrefs.kt` (declares `object PassStorePrefs` over java.util.prefs + org.json; oldest-store trimming to fit `Preferences.MAX_VALUE_LENGTH`) |
| `crypto/pass/PassStoreService.kt` | SAF `DocumentFile` tree access | Desktop replacement `src/…/desktop/DesktopPassStore.kt` (java.nio; same tree/entry/`.gpg-id` semantics, no SAF) |
| `crypto/pass/PassDecryptCoordinator.kt` | imports the Android KeyRepository | Desktop twin `src/…/android/crypto/pass/DesktopPassDecrypt.kt` (declares `PassRoute` + `object PassDecryptCoordinator` over `DesktopKeyRepository`) |
| `crypto/card/CardPinCache.kt` | `Context` + `PGPonyApp` SharedPreferences | Desktop twin `src/…/card/DesktopCardPinCache.kt` (declares `object CardPinCache`, java.util.prefs). Upstream seam candidate: KeyValueSettings interface |
| `data/ArmorCommentSettings.kt` | DataStore + Context | Shim `src/…/data/ArmorCommentShim.kt`; superseded by the D2b+ Settings port |
| `data/SecureKeyStore.kt` | Android Keystore | Desktop counterpart `src/…/desktop/KeyMaterialStore.kt` (armored files, 0600, D0-3 posture) |
| `data/KeyDeduplicationService.kt` | Android platform imports | D2b — port with the normalized-dup scan |
| `data/SubkeyMigrationService.kt` | Android-only one-time migration | Never needed on desktop |
| `data/KeyRefreshService.kt` | Imports the Android KeyRepository | Desktop mirror `src/…/desktop/DesktopKeyRefresh.kt` (same five steps, same result vocabulary, directory-wide entry point) |
| `network/HttpClientFactory.kt` | Context-typed client cache | Desktop twin `src/…/network/DesktopHttpClientFactory.kt` (same object, signature-keyed cache, ktor Android engine + SOCKS) |
| `network/ProxyPrefs.kt` | SharedPreferences | Desktop twin `src/…/network/DesktopProxyPrefs.kt` (java.util.prefs; MODE_ORBOT = local Tor daemon; prefsOverride test hook) |
| `keyserver/KeyServerDirectory.kt` | Context + DataStore | Desktop twin `src/…/keyserver/DesktopKeyServerDirectory.kt` (declares `KeyServer` verbatim + the directory over java.util.prefs; no serversFlow — every caller uses readOnce) |
| `data/PgpSubkeyEntity.kt` | Not in `PGPDatabase.entities` — Android-side vestige | Follows upstream if it ever rejoins the schema |
| `data/RoomMigrations.kt`, `data/migrations/**` | `SupportSQLiteDatabase` is Android-only; fresh desktop DBs create at v7 | Future desktop schema bumps join the chain KMP-style |
| `data/repository/**` | Android KeyRepository (SharedPreferences seam) | Desktop twin `src/…/desktop/DesktopKeyRepository.kt`; grows toward full parity D2b/D2c |

## Shims (desktop-side, packages com.pgpony.android.*)

| Shim | Stands in for | Superseded by |
|---|---|---|
| `src/…/android/data/ArmorCommentShim.kt` | `ArmorCommentHeader` / `ArmorCommentDefaults` (DataStore-coupled file excluded) | D2b+ armor-comment Settings port |
| `src/…/android/AndroidAppShim.kt` | `PGPonyApp.instance.getString` + `R.string.trust_level_*` reached inline from vendored `TrustLevel` | The upstream cleanup moving localized helpers off the enum (logged in PHASE_D2_NOTES.md). D11 deliberately left its eight strings in English: nothing under `src/` calls them — the UI maps `TrustLevel` to a key at the boundary in `trustName()` — so the shim exists only to make the vendored entity file compile (see PHASE_D11_NOTES.md) |
| `src/…/android/crypto/card/DesktopCardPinCache.kt` | The excluded Android CardPinCache (java.util.prefs; D7 added a `prefsOverride` test hook) | Upstream KeyValueSettings seam, or stays as the permanent twin |
| `src/main/kotlin/android/util/Log.kt` | `android.util.Log` (diagnostic Log.d/w/e in vendored network code; stdout when `-Dpgpony.debug=true`) | An upstream logger seam, if one ever lands |

## Desktop replacements for Android-only packages (not vendored, not excluded)

Some Android packages have no vendored copy at all — they're platform glue with a
desktop-native equivalent under `src/…/desktop/`:

| Android package | Desktop replacement | Notes |
|---|---|---|
| `nfc/` (IsoDep transport + reader) | `desktop/PcscCardTransport.kt` (+ `DesktopCardReader`) | D7. Implements the vendored `CardTransport` seam over `javax.smartcardio` (PC/SC/USB). The rest of `crypto/card/` is vendored verbatim and runs unchanged. Needs the `java.smartcardio` JDK module (wired in build.gradle.kts). |
| `intent/IntentHandler` (Android Intent/Uri routing) | `desktop/DesktopFileRouter.kt` | D9. Same open-a-file decision tree and thresholds, over `java.nio.file.Path` + bytes instead of `Intent`/`ContentResolver`. |
| `notifications/KeyExpirationService` (AlarmManager) | `desktop/ExpirationNotifier.kt` (+ Compose `Tray` notifications in Gui) | D9. Same 30/7/1/0-day windows; scan-on-change instead of scheduled OS alarms. |

The declared end state (plan D0-1) is that this whole directory shrinks as portable pieces are
promoted into PGPonyCore-Kotlin and consumed as a versioned dependency by both apps.

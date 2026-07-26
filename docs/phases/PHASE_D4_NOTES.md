# PHASE_D4_NOTES.md — Keyservers, WKD, refresh, Tor (plan D4)

## D4 (2026-07-25)

### What shipped

- **`vendor/app-network/`** (7 files): the `network/` tree (KeyServerRepository, WkdService,
  dto/KeyServerDto) + the `keyserver/` tree (MultiKeyServerService, KeyServerDirectory)
  vendored verbatim. The ktor **"Android" client engine is a plain-JVM artifact**
  (HttpURLConnection-based), so the vendored services — WKD advanced→direct with the manual
  RFC 4880 armor wrap, the WKD → directory → Hagrid lookup ladder with source attribution,
  VKS upload + auto request-verify, HKP `/pks/add` fallback, per-server verification status —
  compile and run unchanged. Dependencies added: ktor 2.3.12 (same version as Android),
  org.json (bundled on Android, a real dependency here).
- **Three twins + one shim** (inventoried in `vendor/README.md`):
  - `DesktopHttpClientFactory.kt` — same `object HttpClientFactory`, signature-keyed client
    cache, HttpTimeout split (20s direct / 45s proxied), `ProxyBuilder.socks` wiring.
  - `DesktopProxyPrefs.kt` — same `object ProxyPrefs` over java.util.prefs. MODE_ORBOT
    survives as "local Tor daemon" (127.0.0.1:9050 — Tor Browser or the tor service);
    `effectiveBaseUrl` rewrites keys.pgpony.app → its onion only while proxied + mirror on.
  - `DesktopKeyServerDirectory.kt` — declares `data class KeyServer` VERBATIM (same JSON
    codec, so the persisted list is platform-interchangeable; same R5 `mayNotAccept`) + the
    directory API over prefs. No serversFlow — every caller uses `readOnce()`.
  - `android/util/Log.kt` — Log.d/w/e shim (stdout under `-Dpgpony.debug=true`); first
    consumer is KeyServerRepository's diagnostic lines.
- **`DesktopKeyRefresh`** — the excluded `data/KeyRefreshService.kt` mirrored onto
  DesktopKeyRepository: fetch → **mandatory fingerprint verification** → merge (trust, notes,
  secrets, card backing preserved) → primary-key revocation scan (reason read from the sig's
  REVOCATION_REASON subpacket) → stamp lastCheckedAt on every attempt. Entry point is
  `refreshAcrossDirectory`: desktop ships the multi-server directory from day one, so the
  detail-screen refresh IS the Android Phase 5/7 worker pipeline — every lookup-enabled
  server, row re-read between servers, revocation on ANY server propagates. Precedence:
  RevokedUpstream > Merged > UpToDate > FingerprintMismatch > Failed > NotFound — transport
  failure beats NotFound so "no network" never reads as "not published".
- **Repository additions**: `markKeyServerChecked` / `markKeyServerUploaded` (the KS1
  stamps), `markRevokedFromUpstream` (caller guards the locally-revoked case from the
  PRE-merge row — the desktop merge itself flags isRevoked off the joined ring),
  `mergeFetchedPublicMaterial`, and the merge path now **recomputes expiresAt from the merged
  primary** (an upstream expiration extension/removal lands on refresh — matches the Android
  dedup service).
- **UI**: Keyring "Search servers…" (email or fingerprint, provenance-labeled result,
  identity preview before import, UNKNOWN-trust reminder). Key detail "Key servers" section
  (Last uploaded / Last checked, "Refresh from key servers", "Publish…" with per-server
  checkboxes, the non-coercive R5 key-type warning, per-server outcomes + verification-email
  notes). Settings "Network" section (proxy Off/Tor/Custom-SOCKS radios, onion-mirror
  toggle, the ordered directory — lookup/publish toggles, reorder, add, remove non-seeds,
  reset — and the auto-refresh switch). DesktopState runs a session ticker: first pass 15s
  after launch, then every 12h, keys stale after 24h; quiet unless something merged or a
  revocation landed.
- **Tests** (9 offline + 3 gated live):
  - `KeyServerDirectoryTest` — KeyServer JSON round-trip + Android-default optionals, R5
    matrix (classic v4 passes everywhere; v6/PQC flag only on the verified-email VKS),
    directory persistence/toggles/move/reset, corrupt-JSON fallback, ProxyPrefs mode model +
    onion rewrite scoping. Runs on an in-memory `AbstractPreferences` via the twins'
    `prefsOverride` hooks — the suite never touches real prefs.
  - `DesktopKeyRefreshTest` — the pipeline offline with manufactured "server responses":
    identical copy → UpToDate + stamp; wrong key for the fingerprint → FingerprintMismatch,
    material untouched; upstream revocation → flag + reason from the sig + idempotent
    re-refresh keeps local stamps; upstream expiration extension → Merged + expiresAt
    recomputed.
  - `NetworkLiveTest` (gated `-DrunNetwork=true`, real traffic) — Hagrid by-fingerprint,
    WKD for torbrowser@torproject.org, and the unified findByEmail with fingerprint
    verification against EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290.
- `tools/sync-vendor.sh` syncs the two new trees (all trees together — D5 Fix1 rule);
  vendor/README.md inventory updated; `-DrunNetwork` forwarded to the test JVM.

### Validation (closes D4 when green)

1. `./gradlew test` — the offline suite.
2. `./gradlew test -DrunNetwork=true --tests 'com.pgpony.desktop.NetworkLiveTest'` — live.
3. `./gradlew run`:
   - Keyring → Search servers… → your own email → expect a hit (source-labeled) → Import.
   - Key detail → Refresh from key servers on your NorseHorse key → "up to date" (or a
     merge, if the server copy has sigs you don't).
   - Key detail → Publish… a test key to keys.pgpony.app → published ✓; check the
     verification-email note if the address is new to the server.
   - Settings → Network → switch proxy to Tor with Tor Browser running → Search servers…
     again (traffic over 127.0.0.1:9050; keys.pgpony.app rides its onion while the mirror
     toggle is on). Switch back to Direct.
4. Cross-device: publish from the phone, Refresh on desktop (and the reverse) — same key
   material lands both ways.

### Fix log

- **Environment (first run): `:kspKotlin` FileNotFoundException `…/transforms/…/output.bin`**
  — a Gradle artifact-transform cache entry got half-written while the new ktor/org.json
  dependencies downloaded, and the daemon kept serving the stale entry. Not a code failure.
  Remedy: `./gradlew --stop`, delete `~/.gradle/caches/9.4.1/transforms`, re-run (derived
  cache — rebuilt on demand, no re-downloads).
- **Fix1 (first run): `upstreamExpirationExtensionMergesAndRestamps` — expiresAt null after
  merge.** The merge recomputed expiry from the JOINED ring; BC's `getValidSeconds` picks the
  newest self-signature with a strict `>` on creation time, so a re-sign landing in the same
  second as the original self-sig ties and resolves by iteration order — the joined ring
  reported the stale no-expiry sig. Sig timestamps have 1-second granularity, so this is
  reachable in the field (not just in tests) whenever an expiration edit happens within a
  second of the previous self-sig. Fix: derive expiry from the INCOMING ring's primary — the
  exact value Android's KeyRefreshService computes from the fetched ring and hands to
  `resolveDuplicate` — which after a re-sign carries only the new self-signature. (Noted for
  the record: Android's dedup "merge" REPLACES stored public bytes with the incoming copy;
  desktop keeps the strictly-safer BC ring join from D2c, which preserves local-only
  certifications, and takes only the expiry-derivation contract from Android.)

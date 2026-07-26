# PHASE_D5_NOTES.md — PQC interop (plan D5)

> The flagship phase: the same composite codecs Android ships, validated on desktop against
> the same fixtures — plus a desktop-local gpg harness that replaces the adb loop. The engine
> itself needed nothing here (crypto/pqc vendored since D1; composite keygen/encrypt/decrypt
> already exercised by D2b/D3 tests); D5 is about porting the PROOF.

## D5 (2026-07-24)

### What shipped

- **The Android crypto unit suite, vendored verbatim** (`vendor/app-crypto-tests`, 41 files +
  14 fixtures): RFC 9580 vectors, v6 keygen/signing/encryption, BC validation, integrity
  verification, symmetric, signing/verify, multi-key import routing, SubkeyCapability, the
  full `pqc/` suite (KEM, PKESK, LibrePGP encrypt/decrypt, keygen, IETF artifact, v5 probe),
  card protocol tests, MIME tests, util vectors — all compiled into the desktop test task.
  The gated members (`CompositeIosInteropTest`, `CompositeReverseInteropTest`) keep their
  `-DrunInterop=true` / `-DiosSecPass` gates and their `~/pgpony-interop` working-dir
  convention, now shared between the Android and desktop checkouts of the same harness.
- **`GpgInteropTest`** — the desktop-native harness (gated identically; gpg found on the
  usual paths or `-Dpgpony.gpg`); throwaway `GNUPGHOME` per run:
  - classic v4 and v6: both directions, gpg reporting **Good signature** on desktop-signed
    messages;
  - LibrePGP composite: gpg 2.5.x encrypts to a desktop-generated algo-8 key → desktop
    decrypts (the validated direction);
  - desktop detached signatures verify in `gpg --verify`.
  The gpg-decrypts-our-composite-secret direction is deliberately absent — that is the
  upstream `PLANNING_4_1_0.md` §1 blocker (gpg cannot import any standard-form algo-8
  secret), tracked there, not here.
- **Build plumbing**: test-source vendoring in `build.gradle.kts` + the Android pattern for
  forwarding `-DrunInterop` / `-DiosSecPass` / `-Dpgpony.gpg` into the test JVM;
  `tools/sync-vendor.sh` now syncs the test tree + fixtures too.

### First interop run (2026-07-24): 320 tests, 315 green, 5 in the live-gpg lane

- The two vendored two-phase manual harnesses (`CompositeReverseInteropTest` phase 2,
  `CompositeIosInteropTest` direction A) failed **by protocol**: running the whole suite
  executes phase 1 (emit — regenerates the keypair) in the same invocation, so phase 2
  decrypted against messages encrypted to the SUPERSEDED key. The emit phase left fresh
  exports in `~/pgpony-interop/`; redo the gpg step against them (below), then rerun phase 2
  alone. The iOS direction additionally needs the iPhone-side steps whenever convenient.
- The three `GpgInteropTest` failures were environmental; hardened (Fix2): gpg discovery now
  prefers the shell's `gpg` (the binary manual validation used) over fixed paths, GNUPGHOME
  moved to /tmp (the /var/folders default parks the agent socket at macOS's 104-byte
  `sun_path` limit, which silently breaks secret-key import), `--no-tty` added, and the gate
  prints the chosen binary + version into the test output. Second run: v4 + composite +
  detached green.
- **Fix3 — the v6-vs-gpg case was asserting the ecosystem-impossible.** GnuPG does not
  implement RFC 9580 v6 (the LibrePGP split); the app's own `docs/V6_INTEROP_MATRIX.md`
  deliberately routes v6 interop through Sequoia/SOP tools and doesn't list gpg at all. The
  harness now mirrors that: the v6 case drives `sqop` (matrix rows A — sqop encrypts to a
  desktop v6 cert, desktop decrypts — and B — desktop encrypts to a sqop-generated rfc9580
  key, sqop decrypts), skipping with an explanatory message when sqop isn't installed.
  gpg keeps the lanes it actually owns: classic v4 both directions and LibrePGP composite.

Refresh for the reverse harness (with the gpg you validate against — 2.5.x):

```sh
gpg --import ~/pgpony-interop/pgpony-lp-pub.asc
echo "PGPony reverse interop OK" | gpg --armor --encrypt --trust-model always -r reverse@test.local -o ~/pgpony-interop/gpg-to-pgpony-lp.asc
./gradlew test -DrunInterop=true --tests "*CompositeReverseInteropTest*" --rerun-tasks
```

### Validation (closes D5 when green)

1. `./gradlew test` — the full suite: 31 desktop tests + the vendored Android crypto suite
   (gated members auto-skip). Expect a substantially larger test count than D3's 26.
2. Interop live run:
   `./gradlew test -DrunInterop=true --rerun-tasks` — the four GpgInteropTest cases green
   against your local gpg 2.5.x (plus any vendored gated tests you choose to feed via their
   `~/pgpony-interop` conventions).
3. Record the gpg version used in this file (house pattern: the fixtures note their tool
   versions).

### Fix log

- **Fix1 (first build): `CardKdfTest` → unresolved `CardKdf`.** Vendor-freshness skew: the
  main `crypto/` tree was snapshotted at D1 (early 2026-07-24), the test tree at D5 (same day,
  evening) — and `crypto/card/CardKdf.kt` landed upstream in between. Main trees re-synced to
  the same instant as the tests (crypto now 55 files; CardKdf has zero platform imports).
  **Rule: any vendor sync syncs ALL trees together** — `tools/sync-vendor.sh` already does
  (run it after upstream Android work before building desktop); bridge-side syncs must overlay
  every tree in one pass.

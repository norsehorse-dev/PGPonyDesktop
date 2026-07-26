# PGPony Desktop

OpenPGP for **macOS, Linux, and Windows** — the desktop member of the
[PGPony](https://pgpony.app) family.

Encrypt, decrypt, sign, and verify messages and files, manage your keyring, and (from D7) use a
hardware security key over USB — all on device. Like the phones: no accounts, no ads, no
analytics, no tracking.

## Not a rewrite

This app compiles the **exact** OpenPGP engine the PGPony Android app ships — packet handling,
v4 + v6 (RFC 9580) keys, the post-quantum composite layer (both wire formats), the OpenPGP
smart-card protocol stack, MIME — vendored verbatim under [`vendor/`](vendor/) from the
PGPonyAndroid repository, on the same Bouncy Castle version. One tested implementation means
guaranteed interop across every device, and far less code that could drift. Only
`com.pgpony.desktop` under [`src/`](src/) is desktop-specific (Compose UI, CLI, file-backed
stores), plus three small shims inventoried in [`vendor/README.md`](vendor/README.md).

## Build & run

Requires a JDK 17 or newer.

```sh
./gradlew run                      # launch the GUI
./gradlew run --args="selftest"    # verify the engine runs on this JVM (keygen + round-trips)
./gradlew run --args="list-keys"   # the pgpony CLI (D10) — shares the app's keyring
./gradlew test                     # unit suite
```

The same binary is both the GUI and the `pgpony` CLI: a bare launch (or a file argument)
opens the app; a verb (`encrypt`, `decrypt`, `sign`, `verify`, `import`, `export`,
`list-keys`, `gen-key`) runs the command line. `pgpony <verb>` with no options prints its
usage.

## Native installers

```sh
./gradlew packageDmg               # macOS  → build/compose/binaries/main/dmg/
./gradlew packageDeb               # Linux  → build/compose/binaries/main/deb/
./gradlew packageMsi               # Windows → build/compose/binaries/main/msi/ (WiX 3.x required)
```

jpackage builds an installer only for the OS it runs on. The Java runtime is bundled — users need
no separate JDK. Signing/notarization and the full release pipeline follow the RelayPony Desktop
pattern and land in phase D13.

## Status

D1 skeleton ✓ (window shell + theme, import, selftest). D2a ✓ (Room data layer: the same
`PGPDatabase` schema the Android app ships, bundled SQLite, armored material files, D1-store
migration). D2b ✓ (keygen incl. both PQC composites, key detail with subkey capabilities,
export flows). D2c ✓ (trust/notes/default/expiration/revocation mutations, merge-new-material
imports, search + sort). D3a ✓ (the four text surfaces: signed multi-recipient encrypt,
decrypt with verification banners, clear/detached sign, verify with input-type routing).
D3b ✓ (file operations on the streaming APIs, drag-drop onto the window, detached file
signatures, never-overwrite outputs). D3c ✓ (PGP/MIME bundles both directions, .eml compose,
structured decrypt with attachments) — D3 complete. D5 ✓ (the Android crypto unit suite +
fixtures vendored into the desktop test task; desktop-local gpg harness: v4/v6 both
directions with Good-signature checks, LibrePGP composite gpg→desktop, detached sigs in
`gpg --verify` — gated by `-DrunInterop=true`). D6 ✓ (.pgpony backup export/restore with the
forced-re-entry recovery code, five-outcome merge report, card keys public-only, OpenKeychain
restore — cross-restore triangle pending manual validation). D4 ✓ (the vendored network
stack: WKD → directory → Hagrid lookup with source attribution, per-server VKS/HKP publish
with verification emails and the key-type warning, the five-step refresh pipeline with
upstream-revocation propagation, ordered keyserver directory management, Tor/SOCKS proxy with
the keys.pgpony.app onion mirror, 12-hour auto-refresh — live tests gated by
`-DrunNetwork=true`). D7 ✓ (hardware keys over USB PC/SC: the vendored OpenPGP card stack on a
`javax.smartcardio` transport — read/pair, on-card keygen, PW1/PW3 lifecycle, card decrypt +
sign + sign-and-encrypt across the text and file surfaces, the PW1 cache with TTL — offline
tests green; YubiKey 5 / Token2 hardware matrix pending). D9 (batch 1) ✓ (desktop integration:
open-a-file routing mirroring the Android IntentHandler tree, single-instance with second-launch
forwarding, native menu bar + shortcuts, system tray, key-expiration reminders, macOS Finder
open-file handler, QR render + import-from-image via ZXing — OS-level file-association
registration is jpackage config handled at D13). D10 ✓ (the `pgpony` CLI sharing the app's
keyring: encrypt/decrypt/sign/verify/import/export/list-keys/gen-key, `--armor`/`--output`,
stdin·stdout streaming, key selectors, passphrase via env/fd/prompt, stable exit codes).
D8 ✓ (read-only `pass` store over java.nio: `.gpg-id` resolution nearest-first, browse and
search without decrypting, software and card entries, an auto-clearing clipboard, and live
RFC 6238 TOTP from a new shared-core `PassTotp` — one generator, both apps). D11 ✓ (six
languages — en/de/es/fr/ja/pt-BR — over two string layers: Android's `strings.xml` files
vendored verbatim and reused for 143 keys, plus 433 desktop-owned keys in `i18n/`, mounted
side by side and resolved by whichever layer's English declares a key. Live language switching
with no restart, endonym picker, the CLI pinned to English so scripted output stays stable).
D12 ✓ (UI overhaul — native chrome, bold interior: a brand token layer carrying the app icon's
own gradient, the app mark on all four surfaces (window/dock, tray, nav rail, About), one set
of screen-chrome composables adopted across all five screens, real empty states, a wrapping
row layout that stops German button groups being crushed, unified chrome across all twelve
dialogs, and a new About dialog behind a Help menu — 480 desktop-owned keys, six locales;
de/ja visual layout pass pending). Next: D13 packaging.
Phase roster:
`PLANNING_DESKTOP_1_0_0.md` (PGPonyAndroid repo root); phase records:
[`docs/phases/`](docs/phases/).

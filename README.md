# PGPony Desktop

OpenPGP for **macOS, Linux, and Windows** — the desktop member of the
[PGPony](https://pgpony.app) family.

Encrypt, decrypt, sign, and verify messages and files, manage your keyring, and use a hardware
security key over USB — all on device. Like the phones: no accounts, no ads, no analytics, no
tracking.

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
./gradlew run --args="list-keys"   # the pgpony CLI — shares the app's keyring
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
no separate JDK. Released installers are signed, and the macOS build is notarized; the full
procedure is in [`RELEASING.md`](RELEASING.md).

## Status

**1.0.0 — released.** Signed and notarized `.dmg` (macOS, arm64), `.deb` (Linux, amd64) and
`.msi` (Windows, x64), each with a detached PGP signature and a signed `SHA256SUMS`.
Downloads and checksums: [pgpony.app/desktop](https://pgpony.app/desktop).

Everything below is complete and covered by the test suite:

| | |
| --- | --- |
| **Keyring** | The Android app's `PGPDatabase` schema on bundled SQLite. Keygen including both PQC composites, subkey capabilities, trust/notes/expiration/revocation, merge-on-import, search and sort. |
| **Crypto surfaces** | Encrypt, decrypt, sign and verify across text and files, on the streaming APIs, with drag-and-drop, detached signatures and never-overwrite outputs. PGP/MIME both directions, `.eml` compose, structured decrypt with attachments. |
| **Post-quantum** | ML-KEM composites in both the IETF (v6) and GnuPG/LibrePGP wire formats, cross-checked against gpg and sq. |
| **Backup** | `.pgpony` export and restore with the forced-re-entry recovery code, five-outcome merge report, OpenKeychain restore. |
| **Keyservers** | WKD → directory → Hagrid lookup with source attribution, per-server VKS/HKP publish, the five-step refresh pipeline, ordered directory management, Tor/SOCKS with the onion mirror. |
| **Hardware keys** | The vendored OpenPGP card stack over USB PC/SC — read/pair, on-card keygen, PW1/PW3 lifecycle, decrypt, sign and sign-and-encrypt, PIN cache with TTL. |
| **Password store** | Read-only `pass` over `java.nio` — `.gpg-id` nearest-first, browse and search without decrypting, auto-clearing clipboard, live RFC 6238 TOTP. |
| **Desktop integration** | Open-a-file routing mirroring Android's `IntentHandler`, single-instance forwarding, native menu bar, system tray, expiration reminders, QR render and import, OS file associations. |
| **CLI** | `pgpony` sharing the app's keyring: encrypt/decrypt/sign/verify/import/export/list-keys/gen-key, stdin·stdout streaming, passphrase via env/fd/prompt, stable exit codes. |
| **Localization** | Six languages — en/de/es/fr/ja/pt-BR — over two string layers, switchable with no restart. |

Phase-by-phase records, including the reasoning behind decisions that are not obvious from the
code, are in [`docs/phases/`](docs/phases/). The plan of record is `PLANNING_DESKTOP_1_0_0.md`
in the PGPonyAndroid repository. Releases are cut per [`RELEASING.md`](RELEASING.md).

Pending manual validation: the YubiKey 5 / Token2 matrix across all three OSes, the backup
cross-restore triangle (phone ↔ desktop ↔ iOS), and clean-machine installs on Linux and Windows.

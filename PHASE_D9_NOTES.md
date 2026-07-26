# PHASE_D9_NOTES.md — Desktop integration (plan D9)

## D9 — batch 2 (2026-07-25): QR

### What shipped

- **`QrCode`** (ZXing — the same library Android uses, so QR wire format matches) — `encodeToPng`
  renders text to a PNG (error-correction L for maximum capacity), returning null on
  WriterException so the UI shows a "too large — share the .asc" message instead of a broken
  image (the 4.1.0 §11 posture; a full RSA-4096 certificate won't fit a QR). `decodeFromImage`
  reads a key QR out of any ImageIO-readable file (screenshot, photo export) — no camera in 1.0.
- **Key detail → "Show QR…"** renders the public key QR (via Skia → Compose `ImageBitmap`),
  with "Save PNG…", and the too-large fallback for big keys.
- **Keyring → "Import QR…"** picks an image, decodes it, and imports the armored key (with clear
  status when there's no QR or it isn't an OpenPGP key).
- **Tests** (`QrCodeTest`): text and Ed25519-public-key round-trips (decoded armor re-imports to
  the same fingerprint), oversized-content soft failure (null, no throw), and a blank image →
  null.

D9 is now complete (QR + the batch-1 integration layer). Only OS-level file-association
registration remains, and that is jpackage installer config handled at D12.

## D9 — batch 1 (2026-07-25): open-a-file, menu, tray, notifications, single-instance

### What shipped

- **`DesktopFileRouter`** — the open-a-file decision tree, a byte-for-byte mirror of Android's
  `IntentHandler.handleFileUri`: `.pgpony`/"PGPony Backup"/"Passphrase-Format" → Restore;
  `multipart/encrypted` → Decrypt(file); armored KEY → Import (size-exempt); armored ≤32KB →
  detached-sig→Verify / MESSAGE→Decrypt(text) / else Encrypt(text); armored >32KB → Verify or
  Decrypt(file); binary tag-2 packet → Verify(file); binary parsed as encrypted → Decrypt(file);
  anything else → Encrypt(file). Same 32KB / 1KB-head-sniff thresholds. Pure; unit-tested.
- **`SingleInstance` + `AppOpen`** — one window, not many. The first process locks
  `dataDir/.instance.lock` and serves a loopback socket (port in `.instance.port`); a later
  launch forwards its file arguments to the running instance and exits, and the primary raises
  its window. `AppOpen` is the bus: initial CLI args, macOS Finder opens, and forwarded paths
  all funnel through it, queuing until the UI registers a handler. Fails SAFE — if the IPC is
  unreachable (stale port file), the second process just runs as its own instance.
- **`Main.kt`** — a launch argument that resolves to an existing file opens it (routed by type)
  instead of being a CLI verb; bare/`gui`/file launches go through the single-instance guard.
- **Menu bar** (`MenuBar`) — the native macOS app menu (a window menu elsewhere) with
  cross-platform accelerators (⌘ on macOS, Ctrl elsewhere): Keyring (⌘1), Encrypt/Decrypt
  (⌘2), Hardware keys (⌘3), New key… (⌘N), Restore backup…, Quit (⌘Q). Navigation targets a
  hoisted `DesktopState.destination`; dialog-opening items ride a small `uiRequest` field the
  owning screen consumes.
- **System tray** (`Tray`) — quick actions (Open, Encrypt, Keyring, Quit) and the channel the
  expiration reminders post to. Tray→window navigation crosses the application/window scope via
  the `TrayNav` bridge.
- **Key-expiration reminders** (`ExpirationNotifier` + tray notifications) — the desktop analog
  of Android's `KeyExpirationService`: no OS alarm scheduler, so it scans whenever the keyring
  changes (it loads async at launch) and daily thereafter, posting a tray `Notification` at the
  30/7/1/0-day and already-expired windows, once per (key, window) per session. Only renewable
  (secret, non-revoked, has-expiry) keys report. Pure scan; unit-tested.
- **macOS open-file handler** — `java.awt.Desktop.setOpenFileHandler` routes Finder
  double-clicks / "Open With" into the running app (fires once the packaged app declares
  `CFBundleDocumentTypes`; harmless no-op elsewhere). Windows/Linux use the CLI-arg +
  single-instance path.
- **Screen wiring** — CryptoScreen consumes text/file opens (preloads the right tab or the
  Files list with the operation set); KeyringScreen opens the generator on the menu's New
  key…; SettingsScreen opens Restore from the menu or from opening a `.pgpony` (the restore
  dialog gained an optional preset file).
- **Tests**: `DesktopFileRouterTest` (every routing branch from real key/message bytes) and
  `ExpirationNotifierTest` (window bucketing, renewable-only filter, dedupe-key separation).

### Deferred to D12

- **OS file-association registration** — the metadata that tells macOS/Windows/Linux that
  PGPony *owns* `.asc`/`.pgp`/`.gpg`/`.sig`/`.pgpony` (macOS `CFBundleDocumentTypes`, Windows
  registry, Linux `.desktop` MimeType) is installer-image config produced by jpackage, so it's
  built and verified at **D12** alongside signing/packaging. The runtime routing that fires
  once an association delivers a file is done and testable now via a CLI file argument.

### Validation

1. `./gradlew test` — the offline suite incl. the two new tests.
2. `./gradlew run --args="/path/to/pubkey.asc"` → opens to Keyring, key imported.
   `--args` with an armored message → Decrypt tab preloaded; with a `.pgpony` → Settings restore
   preloaded; with a `.sig` → Files/Verify; with any other file → Files/Encrypt.
3. Single instance: `./gradlew run` (leave it open), then `./gradlew run --args="/path/x.asc"`
   in another terminal → the SECOND exits, the FIRST window comes forward and routes the file.
4. Menu bar: ⌘1/⌘2/⌘3 navigate; ⌘N opens the key generator; Restore backup… opens the dialog.
5. Tray: the icon appears; its menu navigates and raises the window.
6. Expiration: generate a key expiring in ~5 days (or set expiry), relaunch → a tray reminder
   fires. (D12 will verify the same from the packaged app on each OS.)

### Fix log

- **Fix1 (test only): `nonPgpFileRoutesToEncryptFile` failed on a PNG fixture.** A PNG's first
  byte `0x89` decodes as an OpenPGP old-format packet **tag 2 (Signature)**, so the binary
  detached-signature sniff correctly routes it to Verify — the *exact* behavior Android's
  `isBinaryDetachedSignature` produces (kept for parity; a PNG opening to Verify is a
  pre-existing Android quirk, and diverging here would break the "same routing everywhere"
  guarantee). The test fixture was wrong, not the router; switched it to plain text + a JPEG
  (`0xFF 0xD8` → new-format tag 63, not a signature) as the non-PGP cases.

# PHASE_D25_NOTES.md: 3.0.0 stage 4, encrypt and decrypt surfaces and hardening (plan 7, 8)

## D25 (2026-09-27)

Checkpoints: 4a (recipient surfaces and the armor comment), 4b (session policy), 4c (zip
transport and the animated QR), 4d (the desktop hardening pass, plan section 8).

### Checkpoint 4a: recipients and the armor comment

- **Subkey selector** (Android 4.5.0 item 13): a selected recipient whose key offers more than
  one encryption subkey gets a picker (automatic pick first, then each subkey with its algorithm,
  post-quantum or classical, and key ID). The choice reaches text, MIME bundle, file and folder
  encryption through `EncryptOps.Plan.subkeyChoices`, and the ML-DSA-to-v4 check uses it. A v4
  interop key has no picker: it always receives on its ML-KEM subkey. The hardware-key signer
  paths keep the automatic pick.
- **Post-quantum weak link** (item 2): with two or more recipients where some receive
  post-quantum and some classical, a warning names the classical ones. Desktop decides
  "post-quantum" per chosen subkey and counts a v4 interop key as post-quantum (Android reads the
  v4 key's base ring, so it would warn about one; worth a look upstream).
- **Email under the name** (item 31) in the recipient rows, so same-name keys tell apart.
- **Password result** (#53, verify): a passphrase-encrypted message shows no recipient count on
  encrypt and a plain "Decrypted · no signature" on decrypt. Nothing to change.
- **Armor comment** (plan 7): Settings, Armor comment: the Comment line on or off for messages
  and for exported public keys, and its text, with a live preview. The store lives in the armor
  comment shim (`ArmorCommentPrefs`, Android's validator rules) and `Main.main` loads it for every
  face of the binary, so the CLI, the git shim and watch folders read the current setting (the
  Android 4.5.3 lesson). Desktop has no first-run screen; Settings is the one place.
- **Argon2id toggle**: not built (plan decision).

Tests: `EncryptSurfacesTest` (the chosen subkey is the PKESK recipient, weak-link rule, armor
comment validator and cache).

### Checkpoint 4b: session policy

- **One duration** (Android 4.3.0 #15, plan 7): Settings, Session: 1 minute, 5, 15, 1 hour,
  until cleared, or until the screen locks, with what is held now and Clear now.
  `SessionPolicy` reads it through the settings seam on every call, so a change applies to
  secrets already held. The card PIN cache keeps its own on/off switch on the Cards screen and
  takes its duration from here; a card-only duration set before 3.0.0 carries over once.
- **Passphrase cache** (`PassphraseCache`, new on desktop): memory only, per key. Filled after a
  typed passphrase works: a decrypt (text, MIME, files), a signature in the app, the SSH agent
  prompt, git signing. A blank passphrase field then uses the key's remembered one: signing
  uses the signer's; decrypting tries each key alone with its own (the #34 cascade), and a
  streamed file uses the remembered passphrase of a key the message names. A remembered
  passphrase that stops working is dropped. Changing a key's passphrase, deleting the key and
  Clear All Data forget it. Before 3.0.0 desktop remembered nothing; this is the Android
  behavior, default 5 minutes. Release notes should say so.
- **SSH agent**: a protected key prompts once and is then served for the session length.
- **git shim** (the #15 shape: pgpony-gpg is its own process): the shim holds no passphrase and
  reads no session setting. A key without a passphrase signs in the shim as before; a protected
  key is signed by the running app through `ShimBridge`, which uses the remembered passphrase or
  prompts in the app window ("git asked PGPony to sign with ..."). Before 3.0.0 the shim refused
  every protected key. With the app closed it still refuses, and says to open PGPony. The
  channel is a loopback port plus a 32-byte token in `dataDir/.shim-bridge` (0600, rewritten each
  launch, removed on exit); it serves signing only, two requests at a time, bounded sizes. It is
  new surface, so it is on the 4d hardening list.
- **Until the screen locks**: the JVM has no lock event. `ScreenLock` asks the system (ioreg on
  macOS, loginctl LockedHint on Linux, LogonUI.exe on Windows) every 4 seconds while that choice
  is selected. Where nothing answers, Settings does not offer it. Needs a manual check on each OS:
  pick it, unlock a key, lock the screen, unlock, and confirm Settings shows nothing held.

Tests: `SessionPolicyTest` (one duration, carry-over, expiry, Clear now, the lock probes, the
decrypt cascade with remembered passphrases, a streamed file), `ShimBridgeTest` (wire format and
token, endpoint file permissions, reachable only while running, the app side's remembered
passphrase and prompt, composite keys).

### Checkpoint 4c: zip transport and the animated QR

- **Zip output** (Android #31, 4.4.1 audit item 9): Files, Encrypt, "Wrap in .zip" (remembered,
  Android's key). The finished .gpg or .asc (or a folder's .tar.gpg) becomes the one entry of
  `<name>.zip`, streamed. Packaging for channels that mangle .gpg, not encryption; gpg reads the
  entry after an unzip. `ZipTransport` is the port of Android's ZipPackaging (app layer, not
  vendored). Not wired: the hardware-key signer batch and watch folders.
- **Decrypting a zip**: Files, the file router and `pgpony decrypt` take a .zip holding one PGP
  entry (.gpg, .pgp, .asc). The entry is extracted, bounded (entry count and payload caps, as
  Android 4.6.0), into a hidden scratch folder beside the zip, decrypted there, and the result
  moves out beside the zip; the scratch folder always goes. Entry names are reduced to a base
  name on write and read. None or several PGP entries is an error, not a guess. The router sends
  any other zip (a .docx, an archive of files) to Encrypt, as before.
- **Animated QR** (4.4.1 audit item 10): Key Detail, Public key QR. A key over 1,200 characters
  splits into `PGPONY1:` frames of 1,000 characters (`QrChunking`, byte-identical to Android's
  format, up to 32 frames), each at its natural module size scaled by a whole number (the 4.5.1
  density, #63). Rotates every 500 ms like Android, with pause, previous and next, "Part n of m"
  and the PGPony-only note. Save PNG saves the part on screen. Behavior change: keys between
  1,200 characters and one symbol's ceiling used to be one dense symbol and are now frames.
- **QR import**: the image picker takes several images, and every QR in each (the multi reader,
  then the single passes) goes to `QrCode.importFrom`: a complete key opens the import preview;
  missing parts say how many were read; frames of two keys say so.
- Manual checks (plan matrix): an ML-DSA-87 key's animated QR scanned by PGPony Android imports
  with the same fingerprint; a zipped file decrypts with gpg after unzip.

Tests: `TransportTest` (zip round trips for a file and a folder with nothing left behind, no or
several entries, a hostile entry path, router, frame format and reassembly, a post-quantum key
through framed PNGs, import outcomes).

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

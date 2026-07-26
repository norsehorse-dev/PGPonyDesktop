# PHASE_D3_NOTES.md — Encrypt / Decrypt / Sign / Verify (plan D3)

> D3 runs in slices: **D3a** (this entry) = the four text surfaces. **D3b** = file operations
> (encrypt/decrypt files, detached file signatures, multi-file, drag-drop). **D3c** = PGP/MIME
> both directions + Bundle compose (.eml/.asc) + structured decrypt with attachments.

## D3a — Text surfaces (2026-07-24)

### What shipped

- **Encrypt · Decrypt destination live** in the rail: a four-tab surface (Encrypt, Decrypt,
  Sign, Verify) with input left, output + outcome banner right, copy/clear actions.
- **Encrypt**: public-key mode (multi-recipient checkboxes; revoked and expired keys excluded —
  the Android availableRecipients rule) with **Sign as** checked by default when a signer
  exists (sign-by-default parity; default key preselected), or **passphrase mode**
  (symmetric, `encryptSymmetricMessage` with the engine's shipped defaults). The SEIPDv2/AEAD
  all-v6 gating is inside the vendored `encrypt` — nothing to port, nothing to drift.
- **Decrypt**: `decryptArmored` with every held secret ring and all public rings as
  verification keys; banner distinguishes VERIFIED (signer resolved against the keyring) /
  signed-by-unheld-key (raw key ID shown) / unsigned — the provider-grade signature-state
  fields (`hasSignature`, `signatureKeyIDRaw`) doing exactly what they were added for.
- **Sign**: clear-sign or detached (armored) via the vendored `SigningService`.
- **Verify**: `detectInputType` routing — clear-signed verifies directly; detached takes the
  original text in a second field; encrypted input is pointed at the Decrypt tab. The sealed
  `VerificationResult` drives the banner (Verified with signer identity / Invalid / UnknownSigner
  / Unsigned).
- **Tests** (5): signed encrypt→decrypt round-trip with verification, symmetric round-trip,
  clear-sign + tamper detection, detached + wrong-content detection, unknown-signer
  classification.

### Notes

- Passphrase prompting is inline per-operation in D3a; the passphrase-cache port
  (ProviderPassphraseCache pattern, TTL) is a later refinement alongside D7's PIN cache.
- Multiple key pairs with different passphrases: decrypt currently takes one passphrase for
  the attempt — matching keys with a different passphrase surface a readable error. Per-key
  prompting (the Android picker flow) can come with D3b's larger decrypt surface if it bites.

### Validation (closes D3a when green)

1. `./gradlew test` — 18 tests.
2. `./gradlew run` — round-trip a message to yourself (encrypt signed → decrypt shows
   VERIFIED with your identity); symmetric round-trip; clear-sign then verify (then alter a
   word and watch it flag INVALID); detached sign/verify via the two-field flow.
3. Cross-app: encrypt on desktop to your Android key → decrypts on Android with a verified
   signature; and the reverse direction back to desktop. gpg smoke:
   `gpg --decrypt` a desktop-encrypted message to a gpg-held key.

### Upstream find #2 (report to PGPonyAndroid 4.1.0 roster)

**The Android in-app decrypt UI collapses "signed by an unheld key" into "not signed."**
Field-diagnosed via desktop→phone: a desktop message signed by a key the phone didn't hold
decrypted fine but showed as unsigned. The artifact provably carried a valid signature
(two-recipient trick: desktop's own decrypt showed VERIFIED). Root cause: the decrypt-tab UI
state carries only `signatureVerified: Boolean` — the ViewModel's own comment says
"'no signature' and 'verification failed' both end up with signatureVerified=false." The
distinguishing fields (`hasSignature`, `signatureKeyIDRaw`) were added in 4.0.0 P2b-1 for the
provider path only. Suggested Android fix: thread both fields into the decrypt/share result
states and render the amber "Signed by unknown key (key ID …) — tap to look up" row —
`SignerLookupSheet` already exists for exactly this flow. (Desktop's D3a banner already makes
the three-way distinction; it's how the field report was diagnosed.)

### Fix log (D3a)

- **Fix1 (field report: desktop→phone arrived unsigned):** the Encrypt tab's signer-ring load
  used `?.let { loadSecretKeyRing(...) }`, so a null load silently downgraded to an UNSIGNED
  encrypt with a success banner — the exact bug class the engine's Phase A3 comment warns
  about, and inconsistent with the Sign tab (which already hard-failed). Now: Sign-as on ⇒ a
  loadable secret ring is required or the whole encrypt aborts with the signer's fingerprint
  named; the success banner states the signing identity + fingerprint, or says ", UNSIGNED"
  explicitly. Two possible outcomes on retry disambiguate the root cause: an abort names the
  unloadable key (load-path bug — report it); a signed send that the phone calls
  "signed by unknown key" means the desktop signer's PUBLIC key isn't on the phone yet —
  export it from desktop and import on Android, then verification goes green.

## D3b — File operations + drag-drop (2026-07-24)

### What shipped

- **Files surface** (fifth tab on Encrypt · Decrypt) with four operations over a file list:
  encrypt (multi-recipient, optional sign-as under the no-silent-downgrade rule, binary `.gpg`
  default with `.asc` armor toggle), decrypt (literal-packet filename restoration, falls back
  to stripping the known extension), detached sign (`.sig`/`.asc`), and detached verify with
  automatic signature↔content pairing (sibling-name rule, or exactly-two-files fallback).
- **Streaming end to end**: all four run on the vendored `encryptStream` / `decryptStream` /
  `signDetachedStream` / `verifyDetachedStream`, so file size is bounded by disk, not heap.
- **Window drag-drop** via an AWT `DropTarget` on the Compose window (no experimental Compose
  APIs): dropped files jump to the Files tab, and the operation auto-routes (all `.gpg/.pgp/
  .asc` → Decrypt, else Encrypt) until the user picks one manually. Multi-select native picker
  ("Add files…") behaves the same.
- **Never-overwrite outputs**: `name.gpg → name-1.gpg → …`; decrypts landing next to an
  existing original get the same numbered treatment.
- **Per-file results** with ✓/✗, detail (including signature state on decrypts — VERIFIED /
  unheld key ID / none), and output paths.
- **Tests** (4): 200 KB binary signed round-trip with filename restoration from the literal
  packet, armored round-trip + no-overwrite naming, detached file signature + tamper
  detection, multi-file loop + both pairing modes.

### Notes

- Symmetric (passphrase) file encryption is deliberately not in the Files UI yet — the vendored
  symmetric path is byte-array based; it joins in D3c or when a streaming variant lands
  upstream.
- Drops are files-only; folder drops are ignored (recursive folder handling can join D9's
  open-file routing).

### Validation (closes D3b when green)

1. `./gradlew test` — 22 tests.
2. `./gradlew run` — drop a PDF on the window: it lands in Files with Encrypt preselected;
   encrypt signed to yourself → `.gpg` appears next to it; drop the `.gpg` → Decrypt
   preselected, passphrase, run → original name restored with `-1` suffix, signature line
   VERIFIED. Detached-sign a file, verify it, edit a byte, verify again → INVALID.
3. Cross-app: a desktop-encrypted `.gpg` file decrypts on Android (share-in) and via
   `gpg --decrypt`; an Android-encrypted file drops onto the desktop window and decrypts.

### Fix log (D3b)

- (none yet)

## D3c — PGP/MIME + Bundle compose (2026-07-24)

### What shipped

- **Bundle compose** on the Encrypt tab: Attach files… turns the message into a PGP/MIME
  bundle — body + attachments as `multipart/mixed` inside the encryption
  (`MimeBuilder.buildMixed`, content types via `Files.probeContentType`), in both public-key
  (signed under the no-silent-downgrade rule) and passphrase modes.
- **Save .eml…** on any encrypted output: the RFC 3156 `multipart/encrypted` envelope
  (`MimeBuilder.wrapEncrypted`) under a minimal Subject header — a complete .eml a mail
  client can carry.
- **Structured decrypt**: the Decrypt tab accepts an armored message *or a pasted full .eml*
  (`MimeParser.pgpMimeEncryptedPayload` strips the envelope — the exact Android ViewModel
  routing), parses the plaintext for a MIME bundle, shows the body in the output pane and the
  attachments beside it with per-attachment Save; non-MIME plaintext passes through untouched.
- **Per-tab input fix** (field report): text typed on one tab no longer follows to the others —
  each tab keeps its own input; outputs stay transient on switch.
- **Tests** (4): signed bundle round-trip with an 80 KB binary attachment surviving base64,
  non-MIME passthrough, .eml wrap + extraction + direct .eml decrypt, symmetric bundle.

### Validation (closes D3c — and D3 — when green)

1. `./gradlew test` — 26 tests.
2. `./gradlew run` — Encrypt with two attachments to yourself, signed → decrypt the output:
   body in the pane, attachments listed with working Save; Save .eml… and paste the .eml file's
   contents straight into Decrypt → same result. Type in Encrypt, switch tabs → each tab keeps
   its own text.
3. Cross-app: a desktop bundle decrypts on Android with the structured attachment screen;
   an Android Bundle-compose message pastes into desktop Decrypt and shows its attachments.

### Fix log (D3c)

- **Fix1 (field report: saved .eml fails to decrypt on the Files tab — "invalid header
  encountered"):** the Files decrypt path fed raw bytes to `decryptStream`, which can't read a
  MIME envelope; only the text Decrypt tab knew to strip .eml wrappers. `decryptFile` now
  peeks the head: MIME/armored text routes through `pgpMimeEncryptedPayload` /
  armored-block extraction on the byte path — and when the plaintext is a bundle, it unpacks
  into a sibling FOLDER (body.txt + each attachment as a real file, never-overwrite naming
  throughout). Binary ciphertext keeps the heap-free streaming path. Regression test covers
  the exact reported flow (.eml through the Files tab) plus a bare .asc message file.

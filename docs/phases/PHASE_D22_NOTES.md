# PHASE_D22_NOTES.md: 3.0.0 stage 1, the foundation (plan 3.0.0 section 2)

## D22 (2026-09-26)

The first stage of the 3.0.0 parity release (`PLANNING_DESKTOP_3_0_0.md`). Two checkpoints:
the sync and schema (compiled and green on the Mac), then the recipient, signing and signature
work on top of it.

### Checkpoint 1: sync, settings seam, schema

- Vendor re-synced from PGPonyAndroid at v4.6.1 plus the 4.7.0 settings seam (the recorded
  exception in `vendor/README.md`), and the LiteralFilenameTest split so the vendored test
  compiles here.
- Settings seam: `data/settings/KeyValueSettings.kt` upstream; `DesktopPrefsSettings` (java.util.prefs,
  node `app/pgpony/desktop/kv/<name>`) installed first thing in `main()`. KeyPublicationStore,
  RemovedUserIdStore, WkdLookup and FallbackPrefs now compile verbatim.
- Schema 9 to 12: `DESKTOP_MIGRATION_9_10/10_11/11_12`, same SQL as Android. `DbUpgradeTest`
  builds real v9 and v7 databases (seed a current one, drop what later migrations add, reset
  user_version) and lets Room upgrade and validate them.
- Proxy fixes ported into `DesktopHttpClientFactory` (Android 4.6.0 item 17.8): the SOCKS5
  stream-isolation credentials were filtered on requestorType PROXY and never sent (unreleased on
  desktop, main only); identity encoding on every request; a proxy mode with no host fails closed.

### Checkpoint 2: recipients, signing, signatures

- **Raw-octet key import** (`DesktopKeyRepository.importArmoredKeyDetailed`): composite ML-DSA keys
  and v4 Ed25519 + algo-35 keys are recognized first and stored as armored raw octets, as Android
  does. Before this, desktop could not import someone else's composite key at all, and a v4
  algo-35 key lost its post-quantum subkey on import (BouncyCastle cannot parse it). Binary key
  files of both kinds take the same path (`importBytes`).
- **Merge on octets** (plan 2.5): re-import and key-server refresh merge through CertificateMerge
  on the stored bytes, so the algo-35 subkey survives. Key pairs are authoritative; a fetched copy
  may not remove or shorten a stored primary expiry (Android item 24 guard) unless it brings a
  revocation; refresh only honors a revocation the primary verifiably made (item 17.1).
- **One recipient loader** (plan 2.6): `loadRecipients` / `requireRecipients` (BouncyCastle rings,
  the v4 algo-35 channel, and a hard stop naming every unusable key, Android 4.6.1 #67). Every
  encrypt path goes through it: text, bundle, file, folder, card-signed variants, watch folders
  (via `encryptFile`), the CLI.
- **EncryptOps** (plan 2.7, 2.8): one plan per operation: recipients, the expired-key rule
  (`KeyUsePolicy`, Settings > Keys > Allow expired keys, off by default), and the signer, classical
  or composite ML-DSA. The old "ML-DSA cannot sign while encrypting" refusal is gone. A composite
  signature into a SEIPDv1 container (a v4-only recipient) asks Sign anyway / Send unsigned /
  Cancel in the GUI (once per file batch); the CLI signs and warns on stderr. Composite signing of
  files and folders buffers in memory (the engine has no streaming composite signer) under a
  512 MB ceiling with a clear error past it.
- **File signing with ML-DSA** (Android 4.5.3 #65): detached file signatures through
  CompositeDocumentSigner.
- **Git shim**: signs with an unprotected ML-DSA key, verifies composite detached signatures, refuses
  expired keys, and emits TRUST_ULTIMATE / TRUST_FULLY / TRUST_UNDEFINED after VALIDSIG from the
  signer's trust level, so git's %G? tells a confirmed signer ("G") from an unconfirmed one ("U").
- **SignatureSummary** (plan 2.9): one reading of a signature for every surface. Valid from an
  UNKNOWN / UNVERIFIED key reads "signed, key not verified" (amber); a composite inline signature
  inside a decrypted message (DecryptResult.compositeInline) is now verified instead of reading as
  unsigned. The streaming file decrypt now passes the composite and v4 algo-35 secret rings.
- **File router** (plan 2.10, the Android 4.7.0 item 2 / #67 bug): a binary detached signature must
  parse as signature packets only, within 64 KiB; PNG, JPEG, GIF, WebP, PDF and ZIP never qualify.
  A PNG opened with PGPony used to go to Verify.

### Strings

Six new desktop keys in all seven languages (machine-translated for de, es, fr, ja, pt-BR, ru; due
the usual review): `d_err_recipient_unusable`, `d_file_sig_unconfirmed`, `d_file_sig_invalid`,
`d_file_err_composite_too_large`, `d_file_verify_ok_unconfirmed`,
`d_crypto_banner_decrypted_unconfirmed`. Everything else reuses vendored Android keys
(`encrypt_expired_*`, `settings_allow_expired_*`, `settings_section_keys`, `pqc_v4_sign_*`).

### Tests added

`DbUpgradeTest`, `DesktopPrefsSettingsTest`, `RecipientsAndSigningTest` (v4 algo-35 import, encrypt,
decrypt and merge survival; composite import into a second keyring and ML-DSA encrypt-and-sign
read back as a verified inline signature; fail-closed recipients; expired-key rule), two refresh
tests (expiry downgrade refused; the rule itself), three router tests.

### Left for later stages

Section 6 key-server UI (upload status, out-of-date marker, custom servers, WKD surfacing) is
stage 3. Mime bundle attachment names are still sanitized by hand in FileCryptoOps; they move to
LiteralFilename in the stage 4 hardening pass.

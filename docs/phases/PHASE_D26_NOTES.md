# PHASE_D26_NOTES.md: 3.0.0 stage 5, SOP, GnuPG import and Flathub (plan F2, F3, 13a)

## D26 (2026-09-28)

Checkpoints: 5a (the SOP command line), 5b (import from GnuPG), 5c (the Flathub build).

### Checkpoint 5a: pgpony-sop (F2, Android 4.7.0 #64)

A Stateless OpenPGP command line over PGPony's engine, for the sequoia-pgp OpenPGP
interoperability test suite. Reached as `pgpony-sop` (launcher name, like pgpony-gpg) or
`pgpony sop <subcommand>`; `tools/pgpony-sop` is the wrapper the suite's configuration points
at.

- **Subcommands**: version (`--backend`, `--extended`, `--sop-spec`), list-profiles,
  generate-key, extract-cert, sign, verify, inline-sign, inline-verify, encrypt, decrypt,
  armor, dearmor. Others answer UNSUPPORTED_SUBCOMMAND (69); an option not implemented answers
  UNSUPPORTED_OPTION (37). Indirect inputs take a file, `@ENV:` or `@FD:`; outputs refuse an
  existing file (59).
- **Stateless on the engine**: each invocation loads the key and certificate files it was given
  into a scratch keyring (database and key store in an owner-only temporary folder, deleted on
  exit), so encryption, decryption, composite ML-DSA and ML-KEM and v4 interop keys run through
  the same code as the app. The user's keyring, settings and passphrase cache are never touched;
  the dispatch runs before the settings seam is installed, and expired keys follow SOP rules,
  not the app's "Allow expired keys" (`KeyUsePolicy.forced`).
- **Profiles** (generate-key): `draft-koch-eddsa-for-openpgp-00` (v4 Ed25519 and Cv25519, the
  default), `rfc9580` (v6 Ed25519 and X25519), `draft-ietf-openpgp-pqc` (v6 ML-DSA-65+Ed25519
  with ML-KEM-768+X25519), `rfc4880` (v4 RSA 3072). encrypt: `rfc9580`.
- **Verifications**: each signature packet is checked on its own (VerifyService for classical,
  CompositeDocumentVerifier for ML-DSA, the signer graded as in the app) and reported as
  `<time> <signing key fp> <primary fp> mode:binary|text`. `SopSigInfo` reads a signature's
  time, issuer and type without BouncyCastle, which cannot parse composite signatures.
- **Engine hooks, upstream first** (PGPonyAndroid, 4.7.0 #64): SigningService.signDetached and
  PGPCryptoService.sign take `textMode` (a type 0x01 canonical text signature), and
  DecryptResult / DecryptStreamResult carry `signaturePackets`, every signature in the message,
  so each one can be reported. Tests: Android `SopHooksTest`, vendored with the sync.
- **Not supported yet** (answers 37): session keys, a password mixed with certificates or
  signing, more than one password, signing inside encryption with more than one key or in text
  mode, inline-sign with more than one key, composite inline text signatures, generate-key
  without a User ID, `--signing-only` outside the rfc9580 profile, armor `--label`, and the
  subcommands not listed above (revoke-key, change-key-password, inline-detach, the card ones).
  The suite's results will show where these matter.
- `--sop-spec` reports `~draft-dkg-openpgp-stateless-cli-11` (the tilde: partial); check it
  against the draft the suite runs before submitting.

Tests: `SopTest` (round trips for three profiles, verification lines, armor, passwords and
protected keys, the exit codes).

Next for 5a: run the suite locally against `tools/pgpony-sop`, fix what it finds (engine fixes
upstream first), then ask the suite maintainers to add PGPony to the public runs.

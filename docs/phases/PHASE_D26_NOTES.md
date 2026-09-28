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

## 5b: Import from GnuPG (plan F3)

Keyring gets **Import from GnuPG…**, and the CLI gets `pgpony import-gnupg [--homedir DIR]
[--secret] [--no-trust]`. Both read one GnuPG home: `$GNUPGHOME`, else `%APPDATA%\gnupg` on
Windows (Gpg4win), else `~/.gnupg` (GPG Suite, Linux). The dialog can point at another folder.
PGPony only reads: nothing in the GnuPG folder is written or changed.

- **With gpg** (found on PATH or in the usual install places): public keys through `--export`,
  trust through `--export-ownertrust` plus the validity column of `--list-keys`, secret keys
  through `--export-secret-keys`, one key per call, so gpg's own pinentry asks for each
  passphrase and the key arrives protected by it, as it was. Keys on a smartcard, and keys
  whose primary secret gpg holds only as a stub, are skipped with a reason (a card is added
  under Hardware Keys instead).
- **Without gpg** (not installed, or inside the Flatpak sandbox, where running host gpg is not
  possible): public keys from `pubring.kbx` (each OpenPGP blob in the keybox holds one keyblock)
  or the older `pubring.gpg`, trust from `trustdb.gpg` (40-byte records; a trust record carries
  a v4 fingerprint and the ownertrust). The dialog says that secret keys need gpg, or an export
  and a file import.
- **Trust mapping**: ultimate ownertrust or validity becomes Ultimate; full becomes Verified;
  marginal, unknown and never carry nothing over. Trust in PGPony is only ever raised, never
  lowered, so running the import twice, or after verifying keys in PGPony, changes nothing
  that was already higher.
- **Bounds** (the 4d rules): every file read and every gpg output is capped, each gpg call has
  a timeout (five minutes for a secret key, which waits on a person at a pinentry), and gpg
  runs with `--batch --no-auto-check-trustdb`, so the import never rebuilds GnuPG's trustdb.

Tests: `GnupgImportTest` (keybox, trustdb and ownertrust export parsing, the colon listing and
the trust mapping, and a whole import from a home without gpg, run twice). The gpg path is
to be checked by hand: a GPG Suite home on the Mac with public keys, an ultimately trusted own key
and a passphrase-protected secret key; a card key shows its skip note.

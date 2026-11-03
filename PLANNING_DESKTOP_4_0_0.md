# PGPony Desktop 4.0.0 Planning

Status: Rev 0, 2026-11-02. Base: 3.1.0.
Release model: as 3.0.0, no release candidates; each stage is self-tested on the Mac, the Windows VM and Linux.

Size tags: S (an evening), M (a few evenings), L (a week or more of evenings).

## Theme

Split from 3.1.0 on Nov 2, when 3.1.0 grew too large for a minor version. 3.1.0 keeps the vendor sync to
Android v4.7.3, #14 (ML-DSA large files), portable mode, and the app lock with the duress PIN. 4.0.0 takes the
items that change how keys are held and how the app is installed: keys generated in the computer's TPM or Secure
Enclave (section 1), key files wrapped with an OS-held key (section 2), an apt repository (section 3), and the
desktop screens for the Android 4.7.0 engine that 3.1.0 already carries (section 4). It does not wait for Android
4.8.0 (see "Not in 4.0.0").

## 0. Rules for this cycle

- Same rules as 3.0.0 and 3.1.0: vendor from an Android tag, never hand-edit vendored files, fixes to vendored code
  land upstream first, and a recorded exception in `vendor/README.md` when desktop takes a file ahead of the tag.
- No personal names or handles in this doc, commits or release notes. Issue numbers or "a user" only.
- No em dashes or en dashes.
- New strings land in all eleven languages, translated by one agent and re-read by a second.

## 1. Keys generated in the computer's TPM or Secure Enclave (L, user request)

Origin: a user, Oct 2026: generate hardware-backed keys on the device itself (no separate hardware key), to use
in workflows that link his devices together.

Today: hardware-backed keys exist only through an OpenPGP card over PC/SC (YubiKey, Token2, Nitrokey):
on-card generation (DesktopCardKeygen, RSA; vendored EdDSA path), keytocard, and card sign / decrypt / ssh-agent.
There is nothing for the computer's own TPM 2.0 (Linux, Windows) or the Mac's Secure Enclave. Outside the app,
GnuPG 2.3+ has `keytotpm` (Linux, tpm2d), which moves an existing software key into the TPM; it does not
generate one there, and the key existed in software first.

Limits that shape the feature:

- TPM 2.0 and the Secure Enclave do P-256 (TPMs also RSA 2048, some 3072). No Ed25519 / X25519 on most TPMs and
  none on the Enclave, and no ML-DSA / ML-KEM anywhere. So these keys are OpenPGP v4 ECDSA P-256 (algo 19)
  primary + ECDH P-256 (algo 18) subkey, which gpg, Sequoia, OpenKeychain and PGPony mobile all read.
- The private key never leaves the chip: no backup, no export, no move to another computer. Clearing the TPM
  (fTPM reset on a firmware update, "clear TPM" in the BIOS, a new motherboard) or replacing the Mac loses it.
  For several devices the model is one key per device, shared as public keys (pairing already moves those).

Work:

1. Platform key seam. Mirror the card path, which already splits the private operation from the OpenPGP
   packets: a PlatformPGPContentSigner next to CardPGPContentSigner, a PlatformPublicKeyDataDecryptorFactory
   next to CardPublicKeyDataDecryptorFactory (reusing Rfc6637 / EcdhCipherData for the KDF and key unwrap),
   and P-256 ECDSA / ECDH public-key packet building next to CardKeyPacketBuilder (today hardcoded to EdDSA /
   Cv25519; the RSA twin is desktop-only). The P-256 packet code is portable, so it lands upstream in
   PGPonyAndroid first and is vendored (it would also serve Android Keystore / StrongBox later); only the OS
   bindings are desktop twins.
2. OS bindings:
   - Windows: CNG Platform Crypto Provider through JNA (`NCryptOpenStorageProvider` with
     `MS_PLATFORM_CRYPTO_PROVIDER`, ECDSA_P256 for signing, ECDH_P256 with `NCryptSecretAgreement` for decrypt).
     Nothing to install.
   - Linux: TPM 2.0. Either `tpm2-pkcs11` through the JDK's SunPKCS11 provider (least new code, but needs the
     user to install and init a token) or `libtss2-esys` through JNA (more code, needs `/dev/tpmrm0` access via
     the `tss` group). Decided Nov 2 (3.1.0 Q6): libtss2 through JNA.
   - macOS: Secure Enclave P-256 through Security.framework (`kSecAttrTokenIDSecureEnclave`, sign and
     `SecKeyCopyKeyExchangeResult`). Needs the signed and notarized build with a keychain-access-groups
     entitlement, so it only works from the release dmg. A small Swift helper or JNA on Security.framework.
3. UI: "Generate on this computer" beside "Generate on card" in key creation, with an optional PIN (TPM
   authValue / Enclave user presence or Touch ID). The certificate list gets the same kind of badge planned for
   card-linked keys. Setup says plainly that the key cannot be backed up and suggests also encrypting to a second
   key (another device or a card).
4. Everywhere a card key works, a platform key works: sign, decrypt, git signing shim, ssh-agent (ecdsa-sha2-nistp256),
   SOP CLI. Backup and Clear All Data handle a key whose secret is a handle, not key material; Clear All Data and
   the duress wipe (3.1.0 section 2.2) also delete the TPM / Enclave key.

Test: per OS, generate, sign, decrypt, and a message encrypted by gpg and by PGPony Android to the new public key
opens; the key ring file copied to another computer decrypts nothing; deleting the platform key makes decrypt
fail with a plain message; an offline test with a software P-256 key in place of the chip checks the packets and
fingerprint against real gpg, the same way the RSA card keygen test does.

## 2. Key files wrapped with an OS-held key (M to L, from 3.1.0 Q2)

Origin: 3.1.0 Q2, answered Nov 2: wrap the key files with an OS-held key so a duress wipe can destroy that one key
and make the files unreadable at once, whatever the disk does. Installed copies only.

Why: on an SSD or a copy-on-write file system (APFS, btrfs), overwriting a key file does not guarantee the old
blocks are gone. 3.1.0 says so in the duress setup text. Destroying one small OS-held key closes that gap for every
key file at once.

Work:

- A random 256-bit wrapping key, held by the OS: macOS Keychain (a generic password item, this app only), Windows
  DPAPI (CurrentUser scope, the wrapped key in the data folder), Linux libsecret (Secret Service), with a plain
  message and the current behavior when no Secret Service is running.
- `KeyMaterialStore` encrypts every key file with it (AES-256-GCM, the file name as associated data). Existing files
  are wrapped on the first start after the update; a crash midway leaves each file readable either way.
- Clear All Data and the duress wipe delete the OS-held key first, then the files as today.
- Backups are unchanged: they carry the keys under the backup passphrase, not under the OS key.
- Portable copies never use it (3.1.0 section 3e.5 keeps the passphrase-only rule there), and `--data-dir`
  pointing at a drive is treated the same way.

Test: unit tests with a fake OS key store (wrap, unwrap, migration, a crash mid-migration, wipe order); per OS,
the key files copied to another account or computer decrypt nothing; after a duress wipe the old key files,
restored from a disk image, decrypt nothing.

## 3. apt repository on pgpony.app (M, from 3.1.0 Q4)

Origin: #12 follow-up and 3.1.0 Q4, answered Nov 2: an apt repository signed with the release key, so
`apt upgrade` picks up new .deb releases (today the in-app update notice sends Linux users to download the .deb by
hand).

Work:

- A repository under `pgpony.app/apt/` (`dists/stable/main/binary-amd64` and `binary-arm64`), `Release` and
  `InRelease` signed with the release key, built in the release job from the two .deb files and uploaded with
  the mirror copy.
- The release key published as a keyring file for `signed-by` (`/usr/share/keyrings/pgpony.gpg`), with the
  install lines on `/desktop` and in the README.
- The .deb installs the source list and keyring itself on first install (asked through debconf, default yes), so a
  .deb downloaded by hand also gets updates.
- The in-app update notice on a .deb install says `sudo apt update && sudo apt upgrade` instead of the download
  link.
- RELEASING.md: the repository step, and how to roll back a bad release (republish the previous `Release`).

Test: a fresh Debian and Ubuntu VM (amd64) and a Raspberry Pi OS (arm64): add the repository, install, publish a
test version to a staging path, `apt upgrade` picks it up, and `apt` refuses a `Release` file signed with any other
key.

## 4. Desktop screens for the Android 4.7.0 engine (M to L)

3.1.0 synced the engine to Android v4.7.3, so these work in the vendored code but have no desktop UI yet:

- Own-key re-import (item 24, #78): importing a key the keyring already holds updates it instead of failing.
- SHA-1 User ID bindings kept and marked weak (item 27): the badge and its explanation in key details.
- Key certification (item 31): certify another key's User IDs, with the certification level, from key details.
- Trust levels and Don't use (item 10): the trust picker in key details and the Don't use warning on encrypt.
- Offline primary keys (item 22): show a key whose primary secret is offline, and the operations it still allows.

Each matches Android's screen and wording (the strings are already in `vendor/app-strings/`).

Test: per item, the Android 4.7.0 test cases replayed on desktop, plus the round trip with PGPony Android
(certify on one, see it on the other).

## 5. Not in 4.0.0: waits for the Android 4.8.0 tag

4.0.0 does not wait for Android 4.8.0, so this lands in the first desktop release after that tag, with the vendor
sync to it.

### SOP: v5 signatures in encrypted messages with several signers (S, from 3.1.0 3d)

`pgpony sop decrypt --verify-with` cannot check a LibrePGP v5 signature on its own when an encrypted message has
several signers: a v5 signature hashes the literal data fields, which sit inside the encryption. PGPonyAndroid
af491ba (4.8.0) returns them as `DecryptResult.literalExtra` (and on the streaming and card results).

Work: after the vendor sync to the 4.8.0 tag, `SopLibrePgpV5` checks every v5 packet in `signaturePackets` with
`literalExtra` instead of taking the engine's graded result, so each v5 signer gets its VERIFICATIONS line.

Test: an encrypted message signed by a GnuPG v5 (Ed448) key and a v4 key gives two VERIFICATIONS lines; a tampered
literal date fails the v5 one only.

## 6. Questions for Kevin

None yet.

## 7. Status of this document

Nov 2: section 5 added: 3.1.0 3d, parked until the Android 4.8.0 tag (neither 3.1.0 nor 4.0.0 waits for it).
Rev 0 (Nov 2): split from 3.1.0. Section 1 is 3.1.0 section 3c with its number, the Q6 answer and one
cross-reference updated; sections 2 and 3
are 3.1.0 Q2 and Q4 written out; section 4 is the UI half of 3.1.0 section 3.

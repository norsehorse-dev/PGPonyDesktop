# PGPony Desktop 4.0.0 Planning

Status: Rev 1, 2026-11-04. Base: 3.1.0, plus the vendor sync to the Android v4.8.0 tag.
Release model: as 3.0.0, no release candidates; each stage is self-tested on the Mac, the Windows VM and Linux.

Size tags: S (an evening), M (a few evenings), L (a week or more of evenings).

## Theme

Split from 3.1.0 on Nov 2, when 3.1.0 grew too large for a minor version. 3.1.0 keeps the vendor sync to
Android v4.7.3, #14 (ML-DSA large files), portable mode, and the app lock with the duress PIN. 4.0.0 takes the
items that change how keys are held and how the app is installed: keys generated in the computer's TPM or Secure
Enclave (section 1), key files wrapped with an OS-held key (section 2), an apt repository (section 3), and the
desktop screens for the Android 4.7.0 engine that 3.1.0 already carries (section 4).

Nov 4: Android 4.8.0 now ships first, so 4.0.0 vendors from the v4.8.0 tag and waits for it (this reverses the
Nov 2 call that 4.0.0 would not wait). The item parked for 4.8.0 comes back in (section 5), and 4.0.0 gains the new
recipient picker and recipient groups (section 6), which Android builds first in 4.8.0.

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

## 5. Vendor sync to Android v4.8.0, and the SOP v5 signers

Back in 4.0.0 on Nov 4 (it was parked on Nov 2 while 4.0.0 was not going to wait for 4.8.0). The vendor sync moves
`vendor/` from v4.7.3 to the v4.8.0 tag. What each 4.8.0 item needs on the desktop side is noted per item in
PGPonyAndroid's docs/planning/PLANNING_4.8.0.md ("Desktop takes it from the sync" or "desktop changes it itself").

### SOP: v5 signatures in encrypted messages with several signers (S, from 3.1.0 3d)

`pgpony sop decrypt --verify-with` cannot check a LibrePGP v5 signature on its own when an encrypted message has
several signers: a v5 signature hashes the literal data fields, which sit inside the encryption. PGPonyAndroid
af491ba (4.8.0) returns them as `DecryptResult.literalExtra` (and on the streaming and card results).

Work: after the vendor sync to the 4.8.0 tag, `SopLibrePgpV5` checks every v5 packet in `signaturePackets` with
`literalExtra` instead of taking the engine's graded result, so each v5 signer gets its VERIFICATIONS line.

Test: an encrypted message signed by a GnuPG v5 (Ed448) key and a v4 key gives two VERIFICATIONS lines; a tampered
literal date fails the v5 one only.

## 6. Recipient picker and recipient groups (M, Nov 4)

Every usable key is a checkbox row, in full, on Encrypt text, Encrypt files and the watch folder rule editor, which
gets cluttered past 8 to 10 keys. Decided Nov 4:

- Picker: Android's design. Chips for the selected recipients (click one to remove it) and a Choose recipients
  button that opens a dialog with a search field (focused on open; matches name, email and fingerprint), Select All
  and Clear over the filtered list. Used in all three places. Its strings are already in `vendor/app-strings/` in
  all eleven languages.
- Order: your own keys first, then everyone else A to Z by name (email when there is no name). Android's picker
  changes to the same order.
- Groups: built in PGPonyAndroid 4.8.0 (item 4n there) and taken from the sync. A group is a named set of keys,
  stored by primary fingerprint. Groups show at the top of the picker dialog and search matches their names.
  Picking a group adds its usable keys as chips and names the ones it left out (revoked, expired, or a card row
  without its public certificate).
- Managing groups: "Save as group" in the picker turns the current selection into one; a Groups section on the Keys
  screen creates, renames, edits members and deletes; key details list the groups the key is in, with add and
  remove.
- Deleted keys: a key in Recently Deleted stays a member but cannot be picked, and restoring it puts it back; a key
  deleted for good leaves every group.
- Moving: the full backup and the full-backup pairing transfer carry groups; public-key-only transfers do not.
- Command line: `pgpony encrypt -r @name` takes a group, adds its usable keys, and names any left out on stderr.
  A missing group is an error. `pgpony sop` is not affected (SOP takes certificates, not names).
- Portable mode: groups live in the data folder with the keyring.

Test: 30 keys, search by part of a name, an email and a fingerprint; a group with one revoked and one Recently
Deleted member; `-r @name` with a missing group; a full backup with groups restored on Android and on desktop;
groups through pairing both ways.

## 7. Questions for Kevin

None yet.

## 8. Status of this document

Rev 1 (Nov 4): Android 4.8.0 ships first, so 4.0.0 vendors from its tag; section 5 (the parked 3.1.0 3d) is back
in, and section 6 (recipient picker and groups) is added.

Nov 2: section 5 added: 3.1.0 3d, parked until the Android 4.8.0 tag (neither 3.1.0 nor 4.0.0 waits for it).
Rev 0 (Nov 2): split from 3.1.0. Section 1 is 3.1.0 section 3c with its number, the Q6 answer and one
cross-reference updated; sections 2 and 3
are 3.1.0 Q2 and Q4 written out; section 4 is the UI half of 3.1.0 section 3.

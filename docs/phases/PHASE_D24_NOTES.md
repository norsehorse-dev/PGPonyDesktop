# PHASE_D24_NOTES.md: 3.0.0 stage 3, key generation, SSH and key servers (plan sections 4 to 6)

## D24 (2026-09-27)

Three checkpoints: key generation (3a), SSH (3b), key servers and import (3c).

### Vendor re-sync

Vendor re-synced from PGPonyAndroid main at b19b82e: v4.6.1 plus the settings seam and 4.7.0
item 18 (the three findings from stage 2). Only `crypto/UserIdService.kt` and its new test differ
from the stage 1 sync. `KeyEditsTest` no longer waits a second before revoking a User ID.

### Checkpoint 3a: key generation (plan 4.1, 4.2)

- **Roster**: the picker is Android's KeygenAlgorithmPicker as radio rows, fed by the vendored
  `KeyAlgorithm.generatable*` lists: Classical, Post-Quantum, then collapsed Interop (ML-KEM-768 +
  X25519 as v6, v4 and v5) and Advanced (RSA, LibrePGP ML-KEM-1024, ML-KEM-768 + brainpoolP256r1).
  New to desktop: the v4 ML-KEM-768 interop key (`generateV4Algo35Key`, raw storage) and the
  brainpool LibrePGP form. "Limited app support" on every post-quantum choice and Android's
  captions replace the old desktop hints (the `d_gen_hint_*` strings are gone).
- **Name-only keys**: the email is optional everywhere (`composeUserID`), CLI included.
- **Expiry**: Android's presets, two years by default. Desktop keys used to never expire.
- **SSH authentication subkey** at generation (`addSshAuthSubkeyAtGeneration`): RSA on an RSA
  key, Ed25519 on any other. It does not stamp the key as edited. A failure keeps the key.
- **Granular keygen** (`generateGranularKey`): a v6 Ed25519 primary, the default X25519 subkey
  kept or dropped, and any subkeys from the Add Subkey list, each with the key's expiry.
- **Revocation certificate**: pre-cached from the binary secret ring (Android 4.1.0 Phase 12a);
  desktop parsed the armor, which is not always BouncyCastle's framing for v5 keys. Granular keys
  now get one too.
- **Publish offer** (plan 4.2, verified: desktop had none): after generation, the publish dialog
  opens for a key with an address when online and "Offer to publish new keys" (Settings, Keys)
  is on.
- **CLI**: `gen-key` takes `--ssh-auth`, `--subkey <kind>` (repeatable) and
  `--no-default-encryption`, the email is optional, and `--algo` knows `mlkem-v4`,
  `mlkem-brainpool`, `mldsa-65`, `mldsa-87`.

Tests: `KeygenTest` (name-only, expiry and revocation certificate, v4 interop, brainpool,
granular, SSH subkey at generation, CLI names).

### Checkpoint 3b: SSH (plan section 5)

- **Agent identities** now come from the vendored `SshAuth.authSubkey`: each key pair's newest
  authentication subkey that is bound, live, and cannot also sign or certify. Before 3.0.0 the
  agent served any Authenticate-capable key, the primary and GnuPG-style [SA] subkeys included.
  That is a behavior change for such keys (a signing-capable key answering ssh's chosen bytes is
  the signing oracle Android 4.6.0 closed); Key Detail says so for a key that has only dual-use
  auth subkeys (`ssh_error_dual_use_auth`), and the fix is Add Subkey, Authenticate. Release
  notes must call this out.
- **Algorithms**: Ed25519, RSA, and now ECDSA on NIST P-256, P-384 and P-521 (`SshAuth.sign`).
- **Composite ML-DSA keys**: a classical auth subkey on one is served
  (`loadSshAuthSecretRing`, CompositeKeyFacade's carrier ring).
- **SHA-1 ssh-rsa** stays for a request with no SHA-2 flag (plan Q10); the Settings section says
  so along with which keys are served.
- **Key Detail**: Copy SSH Public Key (the authorized_keys line, email or name as the comment)
  and the OpenSSH SHA256 fingerprint.
- Card AUT slot behavior unchanged.

Tests: `SshAgentServeTest` (a signing primary is not served, an added auth subkey is and its
Ed25519 signature verifies; a composite key's classical auth subkey; RSA answers ssh-rsa,
rsa-sha2-256 and rsa-sha2-512 by flag; the authorized_keys line).

### Checkpoint 3c: key servers (plan 6.1 to 6.4)

- **Upload status** (Android 4.6.0 item 9): each successful upload is recorded per server
  (`KeyPublicationStore`, `markKeyServerUploaded(fp, serverId)`). The publish dialog becomes
  "Update on key servers" once a key has been published, pre-checks the servers it went to,
  shows when each last got a copy, and under each server lists the key's addresses as confirmed
  or not (`MultiKeyServerService.serverCopy`). Publishing stays available after the first upload.
- **Ambiguous primary** (item 9): a key whose live User IDs carry more than one primary flag, or
  a flag on a different User ID than the one shown, is not published; the dialog points at Make
  Primary (`publishPayload`).
- **Out-of-date marker** (item 11): Key Detail shows "changed since it was last uploaded" with
  an Update action for a published key edited since (`hasUnpublishedChanges`, fed by every
  stage 2 edit's `lastLocalEditAt`).
- **Offline** (item 10): Key Detail's key-server buttons and the out-of-date marker hide, and the
  background refresh does not run.
- **Settings** (4.5.0 items 6 and 21): custom servers were already there (verified); WKD now has
  its own lookup-only row with an on/off switch (`WkdLookup`).
- The publish dialog's secondary button reads "Not now" (Android item 8), so the post-keygen
  offer has an explicit skip.

Tests: `PublishStatusTest` (per-server record, out-of-date after an edit, addresses, ambiguous
primary refused).

### Checkpoint 3d: import (plan 6.5, 6.6)

- **Import preview** (`ImportPreview.kt`, `previewArmoredText`): a paste, a QR code or a link now
  shows every key's User IDs, fingerprint, algorithm, public or key pair, and whether it is
  already in the keyring, before anything is written. A file still imports directly (it may be a
  many-key export), as before.
- **Paste tolerance** (Android 4.5.0 item 19): verified; desktop's block splitter already took only
  the key blocks out of surrounding text and skipped signature blocks. The preview makes it visible.
- **Encrypt to this key** (item 29): for a single public key, the preview imports it and opens
  Crypto with it as the recipient.
- **Import from a link** (Android 4.6.0 item 2): the vendored UrlKeyFetcher on the desktop HTTP
  client, so proxy, Tor isolation and offline mode apply; https only (http for .onion), redirects
  checked hop by hop, public keys only; the preview shows the final link.

Tests: `ImportPreviewTest` (noise ignored and nothing stored, several keys and a signature, link
rules).

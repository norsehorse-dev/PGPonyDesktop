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

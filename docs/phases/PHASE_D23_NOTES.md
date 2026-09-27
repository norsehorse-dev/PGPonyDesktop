# PHASE_D23_NOTES.md: 3.0.0 stage 2, key management (plan 3.0.0 section 3)

## D23 (2026-09-26)

The Key Detail cluster Android grew between 4.2.0 and 4.6.0. Three checkpoints: the edit layer
and the keyring surfaces (2a), the Key Detail screen and Clear All Data (2b), then the consumers
that read the new settings in the encrypt and decrypt paths (2c).

### Checkpoint 2a: edit layer, Recently Deleted, destructive guards

- `DesktopKeyEdits` ports the Android KeyRepository mutations: recycle bin (14 days, launch
  sweep), last backed up, fallbacks and signing defaults storage, passphrase set, change and
  remove, User IDs (add, revoke, remove with a tombstone, make primary), notations, subkey list,
  revoke and remove with the last-encryption-subkey guard. Every mutation stamps lastLocalEditAt;
  every classical edit carries a v4 ML-KEM subkey (V4Algo35Carry).
- `DestructiveGuard`: "Protect destructive actions" (typed DELETE, on by default) and "Hide
  destructive actions" (off by default), the plan Q3 decision in place of device authentication.
- Recently Deleted dialog, the delete confirm with the backup line and revoke instead, same-address
  badges and the note label on keyring rows.

### Checkpoint 2b: Key Detail, add subkey, Clear All Data

- **Add subkey** (`DesktopKeyEdits.addSubkey`, one `AddSubkeyChoice` dispatch): classical on v4
  (RSA, Ed25519, X25519, authentication), Ed25519 and X25519 on v6 (V6SubkeyGen), RSA and the rest
  on a composite ML-DSA primary (raw octets, re-protected), ML-KEM-768 on a v4 key (converts it to
  the RFC 9980 v4 shape, relabels MLKEM768_X25519_V4, carries an earlier ML-KEM subkey), ML-KEM
  768 or 1024 and ML-DSA signing on v6. `addSshAuthSubkeyAtGeneration` is ported for stage 3.
- **Key Detail** (`KeyDetailManage.kt`): passphrase line and dialog (the no-passphrase copy says
  the file permissions are the only protection at rest, plan 3.3); User IDs with make primary,
  revoke and remove; primary and subkey cards with revoke, remove (revoke instead offered) and the
  last-encryption-subkey confirmation; notations editor; decryption fallbacks with order and
  strict mode; the three signing defaults; last backed up; Encrypt to this key and Decrypt with
  this key. Remove actions use the typed confirmation and vanish with the hide switch.
- **Clear All Data** (`ClearAllData.kt`, Settings, Storage): the Android RC5 gauntlet (key list,
  backup offer, two acknowledgements, typed word, five-second countdown). Destroys every key
  including Recently Deleted, the Autocrypt and API client tables, the whole desktop preferences
  node, the watch rules, the agent directory and the cached card PIN, then closes the app. The
  password store folder is the user's and stays.

### Upstream finding (Android)

Android's Add Subkey sheet hands the repository an absolute epoch time as `expirationSeconds`,
while every generator writes it as a key expiration subpacket, which is seconds after creation.
A subkey added on Android with "1 year" expires nearly 58 years out. Desktop converts to a lifetime
(`addClassicalSubkeyUsesALifetimeAndStampsTheEdit` pins it). Fix belongs in Android 4.7.0
(KeyDetailViewModel.addSubkey or the sheet), then a re-sync changes nothing here.

A smaller one: `UserIdService.isRevoked` needs the revocation strictly newer than the newest
certification. Signature times have one-second resolution, so a User ID revoked in the same
second it was last certified (just added, or re-signed by a make-primary) reads as not revoked.
By hand that takes a fast click; the desktop test waits a second. Upstream fix: let a revocation
win a tie, or stamp it one second past the newest certification.

### Strings

23 new desktop keys in all seven languages (machine-translated for de, es, fr, ja, pt-BR, ru; due
the usual review). Everything else reuses the vendored Android keys (key_detail_userids_*,
key_detail_add_subkey_*, key_detail_subkey_*, key_detail_notations_*, key_detail_fallbacks_*,
key_detail_signing_default*, change_passphrase_*, settings_data_clear_*).

### Tests added

`KeyEditsTest` (2a: recycle bin, passphrase, composite passphrase, User IDs, notations, last
encryption subkey, v4 ML-KEM survival; 2b: subkey lifetime and edit stamp, v6 and v4 refusals,
ML-KEM on v4 plus a later classical add, classical subkey on a composite primary, ML-DSA signing
subkey on v6, fallback ordering, Clear All Data reset).

### Checkpoint 2c: fallbacks and signing defaults in use

- **Decrypt order** (`DecryptOrder.kt`, `DesktopKeyRepository.decryptKeys`): the key picked in
  the new "Decrypt with" picker (text and files; Key Detail's Decrypt with this key preselects
  it), then its enabled fallbacks in order, then every other key pair unless the key is strict.
  "Any of my keys" keeps the old keyring order. Text and armored files use Android's cascade
  (each key alone, then the whole list, so the final error is the pre-fallback one); binary
  files and the CLI stream take the order only. `pgpony decrypt --decrypt-with <key>`.
- **Failure wording** (Android #46): with a key picked, a failure says whether that key is not
  a recipient or its passphrase was wrong.
- **Composite classical subkeys decrypt** (Android 4.6.0 item 21): a composite ML-DSA key's
  X25519 or RSA subkey (added in 2b for clients that cannot use ML-KEM) now opens mail. Desktop
  could add such a subkey and not decrypt with it.
- **Signing defaults** (`SigningDefaults.pick`, `signerAfterDefaults`): applied in text and file
  encrypt and sign, MIME bundles, `pgpony encrypt` and `sign` (a stderr note names the key;
  `--no-signing-defaults` opts out) and the gpg shim's sign-only path. Crypto shows a note under
  the signer picker when a default takes over, so the passphrase typed is the right one.

Upstream finding: Android picks the post-quantum default when every recipient
`isComposite`, which leaves out composite ML-DSA keys (they receive on their ML-KEM subkey).
Desktop uses `isPostQuantum`; Android should too.

Watch-folder rules name their own signer and are not routed through signing defaults.

### Tests added in 2c

`DecryptOrderTest`: order and strict mode, the cascade rule, signing-default picks (and the
table read), strict mode on real keys with the not-a-recipient wording, a composite key's
X25519 subkey decrypting.

Still open for stage 4: passphrase change clears the agent's held unlock once SessionPolicy
lands.

# Desktop parity audit against Android 4.4.1

Status: analysis (2026-09-03). A fresh, from-scratch audit of what the desktop app
(2.1.3, plus the committed 4.4.x parity work) is missing relative to PGPony Android
at its current shipped release, 4.4.1.

Method: read every Android release note from 4.2.0 through 4.4.1 and the 4.5.0 and 5.0
planning docs, then probed the desktop source for each feature. The shared crypto and
data trees are vendored verbatim from Android (vendor/app-crypto, vendor/app-data), so
gaps are almost never in the engine. They are in the desktop UI and the desktop twins of
excluded Android files.

Baselines:
- Android: 4.4.1 (versionCode 434) shipped. 4.5.0 in planning, 5.0 a direction doc.
- Desktop: 2.1.3, with the 4.4.x parity commits already on main (vendor sync to 4.4.1,
  composite ML-DSA sign/verify/keygen/recipient, Tor stream isolation, offline switch).

Legend: PORT (desktop UI/logic to write), VERIFY (confirm before deciding), N/A
(structurally Android-only), FUTURE (Android has not shipped it yet either).

## Already at parity (no work)

Confirmed present on desktop through the vendor sync plus the P1 to P4 parity commits:

- Crypto core at 4.4.1: AEAD 64 KiB chunk fix, RSA 3072/4096/8192 labels, ML-KEM-1024
  vs 768 label fix, composite ML-DSA signing stack.
- Composite ML-DSA end to end: keygen (GUI and CLI), sign, verify, decrypt-to, secret
  export, and as an encryption recipient.
- Tor/SOCKS stream isolation with credentials; offline switch with a Settings toggle.
- Signed-only file verify (a signed but not encrypted file verifies in place).
- Full keygen algorithm roster including both post-quantum composites.
- GnuPG-compatible composite secret export (the SECRET_GPG export target).
- Per-key expiry edit, notes, trust levels, make-default-signing, subkey display
  (read only), keyserver publish and refresh, single-symbol QR, revoke, revocation-cert
  export, backup and restore, watch folders, ssh-agent, pass store, hardware cards.
- Symmetric encryption already defaults to interoperable S2K (AES-256 CFB, iterated
  salted, no Argon2), so the 4.3.2 "opens in GnuPG on Linux by default" change is
  already the desktop behavior. See VERIFY V2 for the optional toggle.

## PORT: Android-shipped features missing from the desktop UI

Ordered by a mix of value and cost. The first three already have their database tables
in place from the Room vendor sync, so they are logic and UI only.

### 1. Key recycle bin / Recently Deleted (Android 4.3.0, #36)
Android soft-deletes a key to a recycle bin, restorable, auto-purged after 14 days, and
shows whether the key is in a backup before you confirm. Desktop already has the schema
(deletedAt and lastBackedUpAt columns, DbMigrations 8 to 9) but delete is still a hard,
one-way delete with no bin. High value: this is the safeguard that stops a lost key.
Work: soft-delete on the delete action, a Recently Deleted view reachable from the
Keyring, restore and purge-now, a 14-day sweep, and the backup-state line on the delete
confirm.

### 2. Per-key fallback decryption keys with strict mode (Android 4.2.0, #34)
Older keys enabled, in the user's order, as decryption fallbacks for a newer key, with an
optional strict mode that disables the net. Desktop has the fallback_keys table
(DbMigrations 7 to 8) but nothing reads or writes it. Work: the Key Detail UI to pick and
order fallbacks, the strict-mode toggle, and the decrypt path that consults them.

### 3. Per-key signing defaults (Android 4.2.0, #34/#22)
Choose which key signs on behalf of another for PQC recipients, classical recipients, and
sign-only, so pre-v6 recipients can still verify while the primary stays modern. Desktop
has the signing_defaults table but only a single global make-default-signing action. Work:
the per-key substitution UI and the send-path logic that applies it. Note the provider
half of #51 is N/A on desktop (no mail provider), but the signing-substitution model
itself is portable and useful.

### 4. Change / set / remove a key's passphrase (Android 4.3.0, #26)
From Key Detail: set a passphrase on a key that had none, change it, or remove it, with
the cached entry cleared on change. Desktop has no passphrase-change path at all. Work:
a Key Detail action plus the re-encrypt-secret operation.

### 5. Multiple identities (User IDs) per key, add and revoke (Android 4.2.0, #29)
Desktop shows one userID and cannot add or revoke a second. Work: list identities in Key
Detail, add-identity and revoke-identity actions. The provider address-resolution half
(4.2.1) is N/A on desktop.

### 6. Add a subkey to an existing key (Android 4.2.0, #25)
Desktop displays subkeys read-only. The engine (V6SubkeyGen and the composite subkey gens)
is vendored in. Work: an add-subkey action in Key Detail wired to the vendored generators.

### 7. Editable key notations (Android 4.3.0)
OpenPGP notation packets, editable. Desktop has free-form notes, which are not the same
thing. Work: a notations editor in Key Detail.

### 8. Per-key last-backed-up indicator (Android 4.3.0)
The lastBackedUpAt column exists on desktop but is never shown or written. Work: stamp it
on backup and surface it in Key Detail. Pairs naturally with item 1.

### 9. Zip output for transport (Android 4.3.0, #31)
Wrap file and bundle ciphertext in a .zip for channels that mangle .gpg or .asc, and
accept a zip containing a PGP message on decrypt. Desktop has neither. Work: an output
toggle on the Files tab and zip detection on the decrypt path.

### 10. Animated multi-frame QR for large keys (Android 4.3.0, #37)
A post-quantum key does not fit one QR symbol. Android splits it across auto-rotating
frames with play/pause and manual step. Desktop shows a single symbol and falls back to
"too large", so a PQC key cannot be shown as a QR at all today. Work: multi-frame encode,
playback controls, on Key Detail and any Exchange equivalent.

### 11. Configurable passphrase cache duration / session policy (Android 4.2.0 #15, 4.3.0)
1 minute to 1 hour, or until cleared, or until the device locks, with one policy governing
the passphrase cache and the card PIN cache together. Desktop has a card PIN cache but no
configurable passphrase session policy. Work: a Settings control and a single policy the
caches obey. The "until the phone locks" option maps to session/screen-lock on desktop.

### 12. Deletion friction and Clear All Data (Android 4.2.0, #16/#21/#36)
Android gates a key-pair delete behind a backup offer and an explicit acknowledgement, and
Clear All Data behind two acknowledgements, a typed word, a five-second countdown, and a
reset to first-run. Desktop has none of this. Item 1 (recycle bin) covers most of the
single-key safety; a Clear All Data flow is still net-new.

## VERIFY: confirm before deciding

- V1. Password (symmetric) result clarity (Android 4.4.0, #53). Android stopped showing a
  recipient count and a bogus "origin unverified" banner on a passphrase-encrypted message.
  Check the desktop decrypt result for the same confusion and fix the copy if present.
- V2. Optional Argon2id "Stronger passphrase protection" toggle (Android 4.3.2). Desktop is
  already interop-safe by default (S2K type 3, no Argon2), so this is only the opt-in
  memory-hard toggle. iOS deliberately did not build it, on the same reasoning. Recommend
  leaving desktop as is unless a user asks.

## N/A: structurally Android-only

- OpenPGP provider service, per-address signing memory, provider process plumbing (#51,
  4.2.1): desktop has no mail provider. Desktop already has a signer picker in CryptoScreen.
- Contact identities / a Contacts screen: desktop has no contacts concept.
- Tab-bar icon fills, the doubled inset band, Keyring back-nav, the NFC screen, recipient
  sheet scroll (#45, #53): different UI toolkit, no equivalent surface.
- Sideload update check being off on F-Droid: desktop ships its own UpdateCheck.
- Default sharing method (#31 cluster): an Android share-sheet concept; desktop uses
  save, export, and clipboard instead.

## FUTURE: Android has not shipped these either (track, do not build yet)

From PLANNING_4.5.0 and ROADMAP_5.0, so parity here means waiting for Android to lead:

- PQ-only vs compatibility keygen: omit the standalone classical X25519 subkey so a PQ key
  has no downgrade path; a PQ-only key is a full PQ certificate (composite ML-DSA primary
  plus composite ML-KEM subkey). Origin #36/#56.
- Mixed-recipient post-quantum warning: flag when a message mixes PQ and classical
  recipients. Origin #36.
- Email-less / UID-less key generation: optional email, name-only UID, and a fully UID-less
  v6 key. Origin the 4.4.x cycle.
- Delete-subkey: local remove vs a proper 0x28 subkey revocation.
- Deemphasize the LibrePGP v5 (algo 8) PQC formats in the UX as GnuPG-only.
- 5.0 provider and migration wizard: Android-only by design (on-device IPC provider).

## Suggested order

The three schema-ready items first, since the tables already exist: recycle bin (1),
fallback keys (2), signing defaults (3). Then the Key Detail cluster: change passphrase
(4), identities (5), add subkey (6), notations (7), last-backed-up (8). Then zip output
(9) and animated QR (10), which are self-contained. Then the session-policy setting (11)
and Clear All Data (12). Fold the two VERIFY items in where they touch the same screens.

Russian localization is being added in parallel this cycle (seventh desktop language,
matching Android 4.3.0's Russian add). See the separate localization change.

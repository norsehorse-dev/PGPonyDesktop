# PGPony Desktop 3.0.0 Planning

Status: Rev 3 (2026-09-26). All questions resolved (section 16).
Release model: no release candidates. Each stage is self-tested on the Mac, the Windows VM and
Linux, and 3.0.0 goes straight to production after the last stage.
Base: 2.1.3, plus the 4.4.x parity work already committed on main (vendor at Android 4.4.1,
composite ML-DSA sign/verify/keygen/recipient, Tor stream isolation, offline switch), plus the
Russian localization sitting uncommitted in the working tree.
Upstream target: PGPonyAndroid v4.6.1 (versionCode 461), the tag frozen for external review.
Supersedes: `PLANNING_DESKTOP_PARITY_AUDIT_4_4_1.md`. None of its 12 PORT items has started;
they are folded in below (section 3 and section 7) rather than tracked in two places.

Size tags: S (an evening), M (a few evenings), L (a week or more of evenings).

## Theme

Desktop fell two Android minors behind while 4.5.x and 4.6.x shipped. 3.0.0 is the catch-up
release: every portable feature through Android 4.6.1, on every desktop surface (GUI, CLI,
git shim, ssh-agent, watch folders), and nothing Android-only dressed up as parity.

It is a major version for three reasons: the database goes from schema 9 to 12, the keyring
gains a mutation model it never had (identities, subkeys, passphrases, a recycle bin), and it
resets the "desktop tracks Android" baseline so the next cycle starts from a clean diff.

Desktop is ahead of Android in places, and those stay as they are: keytocard (Android 4.7.0
item 13, #71, asks for it; desktop's D21 code is a usable reference for the 0x4D Extended
Header List builder), per-file encryption of a multi-file selection (4.7.0 item 16, #72),
folder encryption, watch folders, verify-a-download, the ssh-agent and the git signing shim.

## 1. Rules for this cycle

- Vendor from the v4.6.1 tag, not the Android working tree. Android main is now 4.7.0
  development. Today the synced trees match the tag exactly, but they will not for long. Point
  `tools/sync-vendor.sh` and `tools/sync-strings.sh` at a clean checkout of the tag.
- One planned exception to the tag rule: the settings seam (2.2) is an upstream change on Android
  main (4.7.0), and desktop vendors those files ahead of the tag. Record it in `vendor/README.md`.
- If desktop work finds a bug in vendored code, the fix lands upstream on Android main (4.7.0),
  and desktop takes that one file ahead of the tag as a recorded exception in `vendor/README.md`,
  the same shape as the #41 WkdService precedent. Never hand-edit vendored files.
- Every encrypt site loads recipients with `loadEncryptionRecipientRing`, and a selected
  recipient that cannot be loaded stops the operation and names the key. Never a silent drop
  (the 4.6.1 #67 lesson).
- Security-review detail stays outside the repository. This doc and the commits name categories
  only (section 8).
- No personal names or handles in this doc, commits or release notes. Issue numbers only.

## 2. Foundation (stage 1)

### 2.1 Vendor re-sync to v4.6.1 (M)
66 files change in the synced trees between v4.4.1 and v4.6.1 (about 8,600 lines added). New
portable pieces that arrive verbatim: CertificateBindings, CertificateMerge, SignerStatus,
SignaturePolicy, S2kPolicy, SecurityLimits, LiteralFilename, VerifiedReleaseSink,
UserIdService, AddSubkeyChoice, EcCurveOid, the V4Algo35 family (carry, edit, protection,
encryption method), CompositePkeskStripper, `crypto/ssh/SshAuth.kt` and `SshSigningKey.kt`,
and on the network side KeyResponse, ResponseLimits and UrlKeyFetcher. Strings re-sync through
`sync-strings.sh` (Russian is already vendored in the working tree). Acceptance: compile plus a
green vendored test suite before any desktop code changes.

### 2.2 Settings seam moves upstream (M) (decided, Q6)
Three newly vendored files read SharedPreferences through `PGPonyApp.instance`:
`data/KeyPublicationStore.kt`, `data/RemovedUserIdStore.kt`, `network/WkdLookup.kt`. Rather than
write a fourth, fifth and sixth desktop twin, the storage moves behind an interface upstream:

- In PGPonyAndroid (4.7.0 main, not the frozen 4.6.1 tag): a small `KeyValueSettings` interface
  (get/put for string, boolean, long, string set, plus remove) and a single place that installs
  the implementation at startup. Android's implementation wraps SharedPreferences and keeps each
  file's name and mode, including `MODE_MULTI_PROCESS` where the provider reads it (the #15
  lesson), so nothing changes on the phone. Android's unit tests plus an on-device pass confirm
  that.
- Files moved onto it: KeyPublicationStore, RemovedUserIdStore, WkdLookup, FallbackPrefs, and,
  as they are touched, the older twinned ones (ProxyPrefs, OfflineMode, CardPinCache,
  PassStorePrefs). Each one that moves loses its exclude and its desktop twin and vendors verbatim.
- Desktop installs a `java.util.prefs` implementation at startup, using the same node paths the
  existing twins use so current settings carry over.
- What the seam does not fix: KeyRepository, KeyServerDirectory (DataStore), ArmorCommentSettings
  (DataStore) and SecureKeyStore (Android Keystore) stay excluded. Their coupling is Context,
  DataStore and Keystore, not only preferences.

Already-excluded files that grew upstream and need their twins brought forward: KeyRepository
(+1,321 lines), KeyDeduplicationService (+103), KeyServerDirectory (+74), BackupService (+51),
HttpClientFactory (+33), ArmorCommentSettings (+14). SecureKeyStore (+601, the 4.5.3 storage
rewrite) stays excluded and is N/A (section 9). Update the `vendor/README.md` inventory in the
same commit.

### 2.3 Database schema 9 to 12 (S, high risk)
Android added three migrations. Desktop needs KMP-form twins in `DbMigrations.kt`, running the
identical SQL, registered in `Db.kt`:
- 9 to 10: `pgp_keys.autocryptImportedAt`, plus an UPDATE against `autocrypt_peers`. Desktop has
  no Autocrypt, so the UPDATE matches no rows, but it runs as written so the schema stays byte
  for byte the Android one.
- 10 to 11: `pgp_keys.lastLocalEditAt` (drives the out-of-date marker, 6.2).
- 11 to 12: `allowed_api_clients.scopes` and `sshKeyFingerprint` (unused on desktop, present
  because the table is part of the shared schema).

This is the issue #3 failure shape exactly. Acceptance adds a `DbUpgradeTest` that opens a real
2.1.3 database (v9) and a real 2.0.0 database (v7) as fixtures and reaches v12 with every row
intact, plus a manual upgrade of a populated install on all three OSes before stage 2 starts.

### 2.4 DesktopKeyRepository catch-up (L, spread across stages)
The upstream KeyRepository grew by about 1,300 lines against an 833-line desktop twin. Port it
function by function alongside the UI that needs each piece, not all up front. Stage 1 takes only
what the foundation needs: the merge and expiry-reconcile paths (2.5) and the recipient loaders
(2.6). The rest arrives with sections 3 to 6.

### 2.5 Key-server refresh: merge, never replace (M)
Port the 4.6.0 refresh rule (item 12) and the expiry guard: `DesktopKeyRefresh` and
`mergeFetchedPublicMaterial` union-merge through CertificateMerge; the user's own key pairs keep
their local User IDs and primary; a fetch that removes or shortens a primary expiry is refused
(`isExpiryDowngrade`); removed User ID tombstones are honored so a refresh cannot pull a deleted
identity back; revocations are still scanned separately. Lookup answers pass KeyResponse
validation, so an error page reads as "no key found", not an import offer.

### 2.6 Recipient and signer loading sweep (S)
Walk every desktop site that picks recipients or signers: Cli, MimeOps, GpgShim, FileCryptoOps,
CryptoScreen, WatchFolderService, the folder/tar path. Move recipient choice to
`loadEncryptionRecipientRing` (composite ML-DSA and v4 algo-35 keys) and apply the fail-closed
rule. Watch folders matter most: they run unattended, so a rule whose recipient cannot load
marks itself failed and posts a tray notification rather than encrypting to the rest. The
verify paths that build `publicRings` with `loadPublicKeyRing` (FileCryptoOps, CryptoScreen) are
checked for composite signers too. Mirrors Android 4.7.0 item 5.

### 2.7 ML-DSA signing and verification on every desktop surface (M)
Android fixed this in three passes (4.5.2 text, 4.5.3 files and streaming verify, 4.7.0 #72
bundles). Desktop gets it in one pass across: detached file signature, sign-while-encrypting a
file, folder encryption, streaming decrypt that verifies a composite inline signature, MIME,
the CLI, and the git shim (`pgpony-gpg` signing and verifying with an ML-DSA key; git verifies
locally, while hosted badges depend on the host supporting the algorithm). Plus the 4.6.0 item 14
prompt when a composite signature is going to a v4-only recipient: Sign anyway, Send unsigned,
Cancel. The CLI signs and prints a warning on stderr naming the v4-only recipients (decided, Q9);
the git shim and watch folders do the same, since neither can prompt.

### 2.8 Expired keys blocked for signing and encrypting (S)
4.5.3 behavior: refuse to sign with or encrypt to an expired key, show which key expired, and
add a Settings toggle "Allow expired keys" (off by default). On desktop this also covers the CLI
(a flag), the git shim (a clear status error, not a silent unsigned commit) and watch folders (a
rule with an expired recipient fails visibly).

### 2.9 Signer trust in the verification result (S)
SignerStatus: a verified or ultimate signer key keeps the green Verified; an unknown or
unverified signer key shows an amber "Signed, key not verified". Same distinction in CLI output,
and the git shim emits the matching trust status lines so `git log --show-signature` and `%G?`
tell a good signature from a trusted one. Check what the shim emits today before changing it.

### 2.10 File router: images misread as detached signatures (S, bug)
`DesktopFileRouter.isBinaryDetachedSignature` decides from the first byte. A PNG starts with
0x89, which parses as an old-format header with tag 2, so opening a PNG with PGPony routes it to
Verify. Same bug as Android 4.7.0 item 2 (#67). Fix it the same way: accept a detached signature
only when the input parses as signature packets and nothing else (size-capped), with known
image, PDF and archive magic numbers short-circuiting to "not a signature". Unit tests with real
PNG, JPEG, PDF and ZIP headers.

### 2.11 Russian localization lands (S)
The working tree holds the seventh desktop language (values-ru, the i18n audit changes and the
test updates). Commit it as part of the stage 1 base so every later string lands in all seven.

## 3. Key management (stage 2)

### 3.1 Recently Deleted (M) (4.4.1 audit 1, Android 4.3.0/4.6.0, #58)
Soft delete to a recycle bin, restore, purge now, a 14-day sweep, and the backup-state line on
the delete confirm. The schema columns already exist. Public-key deletion says the key moves to
Recently Deleted for 14 days. Each row shows days left (Android 4.7.0 item 4; cheap, taken now).

### 3.2 Destructive-action safety (M) (4.4.1 audit 12, Android 4.5.0/4.5.1)
- Revoke instead: offered on the key-pair delete confirm and on subkey removal, since neither
  can be revoked once gone.
- Hide destructive actions: a Settings switch, off by default, that removes delete key, remove
  subkey, remove User ID and clear all data from the app. Revoke stays.
- Protect destructive actions (decided, Q3): no OS authentication. Each destructive action asks
  the user to type a confirmation word, on by default, plus the hide switch above. Portable, no
  native code.
- Clear All Data: two acknowledgements, a typed word, a five-second countdown, reset to first
  run. On desktop the scope also covers the agent socket, watch rules, pass-store settings and
  the PIN cache; the flow lists what it removes.

### 3.3 Set, change or remove a key's passphrase (M) (4.4.1 audit 4)
From Key Detail, with the cached entry cleared on change. Composite and v4 algo-35 keys
re-protect every component (V4Algo35Protection, CompositeSecretProtection). Desktop-specific
note: KeyMaterialStore keeps secret keys as 0600 armored files, so a passphrase-less key is
protected at rest by file permissions alone. The Key Detail copy says so, the way 4.5.3 tells
Android users a passphrase is what lets a key survive a keystore wipe.

### 3.4 Identities (M) (4.4.1 audit 5, Android 4.2.0/4.5.0/4.5.1)
List User IDs in Key Detail; add, revoke, and delete locally with a tombstone that survives a
key-server refresh (the delete copy points at revoke when the goal is to retire it for others).
Adding a non-primary User ID pins the original as primary explicitly (4.5.0 fix: otherwise the
newer self-signature wins on the server). Composite ML-DSA keys carry several User IDs.

### 3.5 Subkeys (L) (4.4.1 audit 6, Android 4.2.0 to 4.6.0)
- Add: classical (Ed25519, X25519, RSA), post-quantum (ML-KEM encryption, ML-DSA signing), an
  authentication subkey (Ed25519, or RSA to match an RSA key), RSA subkeys on a composite
  ML-DSA key, and a v4 ML-KEM-768+X25519 (algo 35) subkey on a classical key. v6 note on
  composite add-subkey, as Android shows it.
- Remove locally versus revoke properly (0x28 signature), defaulting published keys to revoke.
- v4 ML-KEM subkeys on classical keys show in Key Detail, get expiry, revoke and remove, and
  survive every other edit (User ID, expiry, passphrase, revoke). This is V4Algo35Carry; the
  test is "edit the key five ways, the subkey is still there".

### 3.6 Notations editor (S) (4.4.1 audit 7)
Add, edit and remove OpenPGP notation packets, separate from free-form notes.

### 3.7 Fallback decryption keys with strict mode (M) (4.4.1 audit 2)
Pick and order older keys as decryption fallbacks for a newer key, a strict-mode toggle, and a
decrypt path that consults them. The `fallback_keys` table exists and nothing reads it yet.
`crypto/FallbackPrefs.kt` is excluded today as "no desktop consumer"; it gets a twin now.

### 3.8 Per-key signing defaults (M) (4.4.1 audit 3)
Choose which key signs on behalf of another for post-quantum recipients, classical recipients
and sign-only. The `signing_defaults` table exists. This is how a v6 or composite primary still
sends mail a pre-v6 recipient can verify.

### 3.9 Last backed up (S) (4.4.1 audit 8)
Stamp `lastBackedUpAt` on backup, show it in Key Detail and on the delete confirm.

### 3.10 Keyring list polish (S) (Android 4.6.0 items 1 and 20)
A key's note shows as a label on its keyring row and under the Key Detail header. A row whose
address is shared by other keys shows how many and lists them. Key Detail gets "Encrypt to this
key" and "Decrypt with this key" buttons as the desktop form of the Android avatar shortcut.

## 4. Key generation (stage 3)

### 4.1 Granular keygen and the post-quantum roster (M) (Android 4.5.0/4.6.0, #56)
- Choose what goes on the key instead of a fixed template.
- Post-quantum-only: composite ML-DSA primary plus composite ML-KEM subkey, no classical X25519
  subkey, so there is no downgrade path.
- v4 ML-KEM-768+X25519 (algo 35) as the recommended post-quantum encryption shape (#56).
- ML-DSA-87 paired with ML-KEM-1024. Desktop already lists `MLDSA87_ED448_V6`; confirm it
  produces the same key shape as Android's 4.6.0 type, not only the same label.
- ML-KEM-768 with brainpoolP256r1 (the LibrePGP form GnuPG 2.5 uses) in an Advanced group.
- LibrePGP v5 post-quantum formats deemphasized as GnuPG-only, and "Limited app support" on
  every post-quantum option.
- Optional email: a name-only User ID.
- An optional authentication subkey at generation (feeds section 5).
- The CLI `generate` verb takes the same options.

### 4.2 Publish prompt after generation (S, verify first)
Android's prompt suppresses itself offline, has a clearer skip, and a pgpony.app opt-out.
Check whether desktop keygen offers publishing at all before deciding.

## 5. SSH: give the agent keys to serve (stage 3)

Android 4.6.0 made authentication subkeys first class. Desktop has served ssh-agent since 2.0.0
but has no way to create the key it serves; today a user brings an auth subkey made elsewhere.

- Auth subkey at keygen (4.1) and added to an existing key (3.5).
- Key Detail "Copy SSH Public Key": the `authorized_keys` line, User ID as the comment.
- Agent algorithms: add ECDSA P-256/384/521 (the vendored SshAuth and SshSigningKey now cover
  it; the desktop agent does Ed25519 and RSA today), and serve a classical auth subkey sitting on
  a composite ML-DSA key.
- Only a dedicated authentication subkey is served, never one that can also sign or certify.
  Confirm the current agent rule matches.
- SHA-1 `ssh-rsa` signatures stay (decided, Q10): the agent keeps answering them when a client
  sets no SHA-2 flag, for old servers. Android signs rsa-sha2-256/512 only; this is a deliberate
  desktop difference, noted in the agent's Settings copy.
- Card AUT slot behavior unchanged.

## 6. Key servers and import (stage 3)

### 6.1 Upload status (S) (Android 4.6.0 item 9)
Upload stays available after the first upload; Key Detail shows when each server last got the key
and whether each address is confirmed.

### 6.2 Out-of-date marker (S) (Android 4.6.0 item 11)
A key edited since it was published (`lastLocalEditAt`) is marked out of date with an Update
action. Every mutation in section 3 stamps it.

### 6.3 Offline hides key-server actions (S) (Android 4.6.0 item 10)
Desktop has the offline switch; the Key Detail key-server buttons and the refresh action hide
while it is on.

### 6.4 Custom key-server repositories and WKD in Settings (S, verify first)
Desktop already adds servers in Settings; confirm it matches Android 4.5.0 item 6 and surface WKD
there (item 21).

### 6.5 Import from a link (M) (Android 4.6.0 item 2)
Fetch through UrlKeyFetcher on the desktop HTTP twin, so proxy, Tor isolation and offline mode
all apply; show fingerprint, User IDs and the full source link in the import preview before
anything is written.

### 6.6 Paste tolerance and use-once keys (S) (Android 4.5.0 items 19 and 29)
Pasted or dropped key text tolerates surrounding text (ArmorExtractor). A pasted public key can
be encrypted to straight away without importing it.

## 7. Encrypt and decrypt surfaces (stage 4)

- Subkey selector for encrypt and decrypt when a key offers more than one target (S).
- Email under the name in recipient and decrypt-key pickers (S).
- Mixed post-quantum and classical recipients: a warning that the message drops to classical
  security for everyone (S).
- Zip output for transport, and decrypting a zip that contains a PGP message (M) (4.4.1 audit 9).
- Animated multi-frame QR for keys too large for one symbol, with play/pause and step (M) (4.4.1
  audit 10). Use the 4.5.1 density (more frames of roomier codes, natural module size), not the
  4.5.0 one that phones could not scan.
- Session policy (M) (4.4.1 audit 11, Android 4.6.1 #15): 1 minute to 1 hour, until cleared, or
  until the screen locks, and one policy governs the passphrase cache, the card PIN cache, agent
  signing and the git shim. The #15 bug was a second process holding a stale copy of the setting.
  Desktop has the same shape (`pgpony-gpg` is its own process), so confirm the shim never holds a
  passphrase or setting itself and always asks the running app.
- Armor comment: off, default or custom, in Settings and the first-run screen (S). It applies to
  every armored output: GUI, CLI, shim, watch folders. The 4.5.3 lesson was that a second process
  kept the default.
- Password (symmetric) result clarity (S, verify) (#53): no recipient count and no "origin
  unverified" banner on a passphrase-encrypted message.
- Argon2id opt-in toggle: not built. Desktop already writes interoperable S2K by default, and iOS
  made the same call.

## 8. Security hardening (stage 4)

The vendored engine brings the internal review's fixes on its side: tighter checks on keys and
key-server answers and tighter bounds on untrusted input. Desktop has surfaces that Android does
not, so the review could not have covered them: tar extraction, watch folders, the file router,
the ssh-agent socket parser, the git shim's argv and stdin handling, the update check and the CLI.
Each gets the same categories applied (input bounds, archive and filename handling, trust in
network answers). Findings and their mapping to code live with the pre-audit material outside
this repository. Desktop is not in the external review's scope (decided, Q7); this pass is the
desktop's own.

## 9. Not ported, Android-only

- The OpenPGP provider, Connected apps and per-app OpenPGP/SSH scopes, and the provider half of
  #15.
- The share dialog and Quick Action. Desktop's equivalent is DesktopFileRouter plus paste
  classification, which 2.10 and 6.6 already touch.
- MTE (#70): Android native memory tagging.
- The 4.5.3 key-storage migration: it fixes the Android keystore. Desktop's KeyMaterialStore
  never used it.
- Contacts, the NFC screen, R8 keep rules, Play vitals fixes, the Termux and OkcAgent flow, the
  one-time avatar hints.

## 10. Android 4.7.0 items (after the 4.6.1 target)

Taken now (decided, Q4) because they are desktop bugs or nearly free: the file-router misread
(2.10), days left in Recently Deleted (3.1), the recipient sweep (2.6). Deferred: Simplified Chinese (follows
Android 4.7.0 item 14 and reuses its strings). Already done on desktop: keytocard, per-file
encryption, folder signing.

## 11. Stages

No release candidates (decided, Q5). Stages are internal build order. Each ends with the test suite
green and a self-test pass on macOS, the Windows VM and Linux before the next starts. Nothing is
published between stages; 3.0.0 goes to production once, after stage 6.

| Stage | Scope | Why this order |
|---|---|---|
| 1 | 2.1 to 2.11: sync, settings seam, schema, twins, merge rule, recipient sweep, ML-DSA everywhere, expired keys, signer trust, router fix, Russian | The foundation, and the schema bump gets used day to day on the Mac before anything piles on it |
| 2 | Section 3: recycle bin, destructive safety, passphrase, identities, subkeys, notations, fallback, signing defaults, backup stamp, list polish | The Key Detail cluster; shares one screen and one repository surface |
| 3 | Sections 4, 5, 6: keygen roster, SSH keys for the agent, key servers, import from link | Keygen needs stage 2's subkey code; SSH needs keygen |
| 4 | Sections 7 and 8 | UX and hardening close out parity |
| 5 | F2 (SOP CLI), F3 (GnuPG import), and the Flathub build (section 13a) | Bounded work; SOP interop fixes feed back into the engine before F1 builds on it; Flathub needs the final feature list to settle its sandbox holes |
| 6 | F1 (pairing), then the full translation pass and the section 13 release gate | Largest and newest surface last; strings frozen once, after every feature |

All three features ship inside 3.0.0 (decided, Q1 and Q2). F2 has no UI and can be built in
parallel with stages 2 to 4.

With no release candidates there is no field time before production, so the self-test matrix
(section 14) is the whole safety net. Two things get extra care because a user cannot undo them:
the schema upgrade (2.3) and anything that deletes (3.1, 3.2). Both are tested against a copy of
a real, populated keyring, never only a fresh one.

Progress: stage 1 (2.1 to 2.11) is green on the Mac; see `docs/phases/PHASE_D22_NOTES.md`.
Stage 2: checkpoints 2a (edit layer, Recently Deleted, destructive guards) and 2b (Key Detail,
add subkey, Clear All Data) are green; 2c (Decrypt with picker, fallback order, signing
defaults in the signing paths) awaits its build. See `docs/phases/PHASE_D23_NOTES.md`.

## 12. Features (decided: all three, inside 3.0.0)

### F1. Pair with your phone (L)
The LAN bridge the 2.0.0 plan deferred to "its own design doc". The pieces now exist: PonyDirect
Kotlin is a pure-JVM, dependency-free, Apache-2.0 transport for already-paired peers, built to be
audited on its own, and it already runs in CarrierPony.

- Pairing: desktop shows a QR with a one-time pairing secret and its LAN address and port; the
  phone scans it. The address in the QR means no mDNS is needed (PonyDirect keeps discovery behind
  an app-supplied interface, and the flat-dependency rule argues against adding one). The shared
  32-byte key comes from the pairing secret plus a key exchange, and both screens show a short
  confirmation code.
- What moves: public keys either way; a key pair from phone to desktop or back, re-encrypted
  under its passphrase or a transfer passphrase, never plaintext; a full backup. Later, not in
  F1: the phone as a confirmation device for desktop signing.
- Why: moving keys between PGPony installs today is export, a file carried somehow, import. It is
  the most-repeated support path (the backup and restore threads show it), and nothing else in
  the Pony family would benefit as much from one shared transport.
- Staging: desktop 3.0.0 ships pairing desktop to desktop (two computers, same code on both
  ends), which is useful alone and is a complete test bed for the protocol. Phone pairing turns
  on when the Android counterpart ships (4.7.0 or later), then iOS on the Swift twin. The wire
  format is written up as a short protocol doc before code, so Android builds against a spec.
- Cost: cross-repo in the end, and new attack surface arriving right after an external review; it
  goes into the next review's scope.
- Flatpak: listening on the LAN works with `--share=network`, which the manifest already has.

### F2. A Stateless OpenPGP (SOP) CLI and the public interop suite (M)
Android 4.7.0 item 11 (#64) plans a SOP wrapper so PGPony can join the sequoia-pgp OpenPGP
interoperability test suite. Desktop is the natural home: it is already a JVM CLI on Linux,
vendors the same engine byte for byte, and has the verb dispatch in Cli.kt and the argv0 pattern
from `pgpony-gpg`.

- A `pgpony-sop` binary implementing the core roundtrip subset: generate-key, extract-cert,
  sign, verify, encrypt, decrypt, armor, dearmor, inline-sign, inline-verify.
- Get it running in the suite; results appear on its public results page next to the other
  implementations.
- Why: a public, third-party interop grade for the post-quantum and v6 claims, earned by the
  shared engine, so Android and iOS benefit too. It backs the security-audit application with
  something outsiders can check, and it finds interop bugs nobody has reported yet. No new UI,
  no new network surface.
- Cost: the SOP spec's exit codes and edge cases are strict; expect a round of fixes in vendored
  code, which lands upstream first (rule 2 in section 1).

### F3. Import from GnuPG (M)
One action that reads an existing GnuPG home (Gpg4win, GPG Suite, `~/.gnupg`), imports public
keys, maps ownertrust to trust levels, and imports secret keys through `gpg --export-secret-keys`
when gpg is installed (so gpg's own pinentry handles the passphrase). Most desktop users arrive
from GnuPG; this makes switching one step. Reads GnuPG's data and never writes to it. When gpg
is not installed, public keys still import from `pubring.kbx` / `pubring.gpg`, and the screen
says secret keys need gpg or a manual export. Under Flatpak there is no host gpg in the
sandbox and `~/.gnupg` is not visible without a grant, so the Flatpak build reads a GnuPG home
the user picks through the file portal, public keys only, and says so.

## 13. Release mechanics deltas

- `AppVersion.VERSION` and `packageVersion` move to 3.0.0 together (VersionDriftTest).
- Upgrade gate: a populated 2.1.3 install upgrades to 3.0.0 on macOS, Windows and Linux with every
  key, note, trust level, watch rule and pass-store setting intact.
- Release notes drafted per the writing-style rules and pasted inline for review before anything
  is published. The CHANGELOG-style summary covers 2.1.3 to 3.0.0.
- desktop.json, winget, AUR as in RELEASING.md, plus Flathub (13a, decided Q8).
- RELEASING.md and CLAUDE_RELEASE.md gain a Flathub step (metainfo release entry, manifest bump).

### 13a. Flathub (L)
The groundwork exists: `FLATHUB_PLAN.md`, and an unbuilt manifest, metainfo, desktop entry and
launcher in `packaging/flathub/` (uncommitted). 3.0.0 finishes it:

- Offline Gradle build: generate `gradle-sources.json` and build with `--offline` inside
  flatpak-builder. This is the path Flathub reviewers expect; the prebuilt-jlink fallback is not
  used.
- Build and test on a Linux machine: UI opens, a card is seen through `--socket=pcsc`, encrypt and
  decrypt round-trip, the file portal works, the offline switch and proxy hold.
- Sandbox answers per feature: the ssh-agent socket on a host-visible path (`xdg-run/pgpony`)
  with a real host `ssh` connecting, or shipped disabled on Flatpak with the reason stated; the git
  shim through a documented `flatpak run --command=pgpony-gpg` wrapper, with stdin and the status
  fd confirmed to survive; context menus out of scope on Flatpak; clipboard sentinel verified on
  Wayland before it is claimed; F1 and F3 as noted in section 12.
- App ID `org.pgpony.PGPony`, backed in review by ownership of pgpony.app.
- Submit to flathub/flathub, answer review, add the badge to the README and the download page.

Flathub review runs on Flathub's schedule, not ours. 3.0.0 does not wait for it (decided, Q11):
the release goes out on GitHub, winget, AUR and the site, and Flathub follows when review passes.
The section 13 release gate covers the Flatpak build itself, not Flathub acceptance.

## 14. Test matrix delta

| Area | Case | Expected |
|---|---|---|
| Schema | Open 2.0.0 (v7) and 2.1.3 (v9) fixture databases | Both reach v12, rows intact |
| Recipients | Encrypt to classical plus composite ML-DSA plus v4 algo-35 recipients, GUI, CLI, watch rule | All included; an unloadable one stops the run and names the key |
| ML-DSA | Detached sig, sign+encrypt file, folder, CLI, `git commit -S` with ML-DSA-65 and -87 | Each verifies in PGPony, with the signer shown |
| Expired | Sign with or encrypt to an expired key, toggle off then on | Refused with the key named, then allowed with the expiry shown |
| Trust | Verify a signature from an unverified key, then from a verified one | Amber, then green; shim trust status differs accordingly |
| Router | Open a PNG, JPEG, PDF, ZIP, binary .sig and binary message | Only the .sig goes to Verify |
| Refresh | Refresh a key pair whose server copy has fewer UIDs and no expiry | Local UIDs, primary and expiry kept; new server material merged |
| Subkeys | Add ML-KEM, ML-DSA, auth and RSA-on-composite subkeys, then edit the key five ways | Every subkey survives every edit |
| Identities | Add a non-primary UID, upload, re-fetch | Original stays primary |
| Recycle bin | Delete, restore, let 14 days lapse (clock injected) | Restored intact, then purged |
| SSH | `ssh-add -L` and login with Ed25519, RSA, ECDSA P-256 auth subkeys and a card AUT slot | Listed and authenticates |
| Session | Policy 1 minute: decrypt in GUI, sign via shim after 2 minutes | Prompted again |
| QR | Animated QR of an ML-DSA-87 key scanned by PGPony Android | Imports, same fingerprint |
| Zip | Zip-wrapped output decrypted by gpg after unzip, and by PGPony directly | Both work |

## 15. Risks

- The KeyRepository twin roughly doubles. The settings seam (2.2) takes the small files off the
  twin list, but KeyRepository itself stays a twin; moving it into PGPonyCore-Kotlin is the real
  fix and is out of scope here.
- The seam is a change to Android main while 4.6.1 is under review. It lands on 4.7.0 only and
  must not change Android behavior; its test is Android's own suite plus an on-device settings pass.
- No release candidates means no field testers see the schema upgrade or the delete flows before
  production. Mitigated by testing against copies of real keyrings (section 11), but a bad
  migration reaches every user at once.
- Schema migration is the one change that can brick an install; it gets its own stage and fixtures.
- Android is frozen at 4.6.1 for the review. Upstream fixes found here land on 4.7.0 and cross
  over as recorded exceptions, which must stay rare.
- This is the largest desktop release so far: full parity, three features and a new store. If it
  slips, the cut lines are: stages 1 and 2 as a coherent 2.2.0 (foundation plus key management),
  or parity (stages 1 to 4) as 3.0.0 with the features moving to 3.1.0. F1 is the first thing to
  move if anything does; F2 and F3 are bounded.
- ECDSA in the agent and the new keygen shapes widen what the external review would need to see.

## 16. Open questions

Resolved (2026-09-26):
- Q1. All three features go forward: F1 pairing, F2 SOP CLI, F3 GnuPG import.
- Q2. Inside 3.0.0, as stages 5 and 6 after parity.
- Q3. Typed confirmation plus the hide switch; no OS authentication.
- Q4. 4.6.1 plus the 4.7.0 fixes that apply to desktop code (2.6, 2.10, 3.1).

- Q5. No release candidates. Self-tested per stage, then straight to production.
- Q6. Move the settings seam upstream (2.2), on Android 4.7.0 main.
- Q7. Desktop stays out of the external review's scope.
- Q8. Flathub is part of 3.0.0 (13a).
- Q9. CLI signs and warns on stderr when a composite signature goes to a v4-only recipient.
- Q10. Keep SHA-1 `ssh-rsa` agent signatures for old servers.
- Q11. 3.0.0 does not wait for Flathub review; Flathub follows when accepted.

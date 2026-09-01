# Desktop parity with Android 4.4.x

Status: COMPLETE (2026-09-01). All items below are implemented and the desktop
test suite is green. Changes are staged in the working tree, not yet committed.
Base: Desktop 2.1.3. Upstream: PGPonyAndroid 4.4.0 (committed) plus 4.4.1 (#36, commit 837337f).

## What shipped

- Vendor re-sync to 4.4.1: AEAD 64 KiB chunk fix, RSA 3072/8192 labels, ML-KEM-1024
  label fix, and the composite ML-DSA signing stack, all compiled in verbatim.
- P1: composite ML-DSA key as an encryption recipient (loadEncryptionRecipientRing
  across every desktop encrypt-to site).
- P3: Tor/SOCKS stream isolation in the desktop proxy twins (SOCKS5 user/pass, own
  Tor circuit, Settings fields), plus the vendored strings refresh.
- P4: offline switch (DesktopOfflineMode twin, per-request guard, Settings toggle,
  keyserver-search gated while offline, seeded at GUI startup).
- P2: composite ML-DSA signing end to end on desktop, keygen (GUI + CLI), sign
  (GUI + CLI, detached and clear-signed), verify (text, detached, file, CLI),
  decrypt-to (message path), and secret export (raw). OfflineMode.kt excluded from
  the vendor build; its desktop twin is DesktopOfflineMode.

Sections below are kept as the record of what was decided and why.

The vendored crypto and data trees were re-synced from PGPonyAndroid at 4.4.1,
so every portable class now matches upstream byte for byte. What remains is the
desktop-side work: the twins and shims that are excluded from the vendor build,
and the UI that has no Android counterpart to copy.

Legend: DONE by sync (compiles in verbatim), PORT (desktop code to write),
VERIFY (needs a look before deciding), N/A (structurally Android-only).

## Lands automatically through the vendor sync

These live in vendored files that are NOT excluded, so they are already in the
desktop build once it compiles:

- v6 AEAD chunk size fix, 64 byte to 64 KiB (4.4.1, #36). Removes the ~25%
  size bloat on post-quantum encryption. In PGPCryptoService.
- RSA 3072 / 4096 / 8192 labeling and the algorithmForKey rewrite that reads
  real key material (4.4.1, #36). In KeyAlgorithm and PGPCryptoService.
- ML-KEM-1024 vs 768 label fix by reading the curve (4.4.1, #36).
- Composite ML-DSA signing crypto stack (4.4.0): CompositeDocumentSigner,
  CompositeDocumentVerifier, CompositeSigner, CompositeSigVerifier,
  CompositeSigPacket, CompositeSigHash, CompositeSignSuite,
  CompositeSignSubkeyGen, CompositePrimaryKeyGen, CompositeSecretProtection.
  The engine is present; the desktop entry points are not (see PORT below).
- V6SubkeyGen (4.4.0 v6 add-subkey).

Acceptance for this section is a green test suite and a compile, not new code.

## PORT, desktop code to write

### P1. Composite ML-DSA key as an encryption recipient (4.4.1, #36)
Small and self contained. The vendored CompositeKeyFacade.encryptionSubkeyRing
already compiles in. The vendored KeyRepository.loadEncryptionRecipientRing is
excluded (**/data/repository/**), so add the twin method to DesktopKeyRepository
and swap the recipient loads:
- DesktopKeyRepository: add loadEncryptionRecipientRing(fingerprint) that falls
  back to CompositeKeyFacade.encryptionSubkeyRing when loadPublicKeyRing returns
  null.
- Call sites to swap from loadPublicKeyRing: Cli.kt (lines around 96, 123, 163),
  MimeOps.kt (43, 73), GpgShim.kt (139, recipient path only), and the file
  encrypt path reached from CryptoScreen.
- Acceptance: encrypt to a composite ML-DSA key as the only recipient succeeds,
  and the empty-encryption-subkey case gives the clearer error text.

### P2. Composite ML-DSA signing, desktop entry points (4.4.0)
The largest item. The crypto is vendored; the surfaces are not:
- Key generation: offer composite ML-DSA-65+Ed25519 as a signing key option in
  the desktop keygen screen, routing to CompositePrimaryKeyGen /
  CompositeSignSubkeyGen.
- Signing: route the sign path (text and file) through CompositeDocumentSigner
  when the chosen signing key is composite.
- Verification: show the composite verification result on decrypt/verify via
  CompositeDocumentVerifier / CompositeSigVerifier.
- Passphrase: composite secret protection through decrypt and export
  (CompositeSecretProtection). See VERIFY V1.
- Acceptance: generate a composite signing key on desktop, sign a message,
  verify it, and round-trip against GnuPG 2.5.x both directions.

### P3. Tor stream isolation in the desktop proxy twins (4.4.0)
DesktopHttpClientFactory has basic SOCKS but no auth, and DesktopProxyPrefs has
no credential fields. Port from the vendored HttpClientFactory / ProxyPrefs:
- SOCKS5 username and password fields in DesktopProxyPrefs and the Settings UI.
- Fail closed when the proxy is unreachable, no direct fallback.
- Resolve the target hostname at the proxy, not locally.
- Acceptance: two credential pairs land on two Tor circuits; proxy down means
  the request fails rather than leaking direct.

### P4. Offline switch (4.4.0)
OfflineMode is vendored but SharedPreferences/Context coupled, so it is excluded
from the desktop build (build.gradle.kts, beside ProxyPrefs). P4 adds a
DesktopOfflineMode twin backed by java.util.prefs.Preferences (as DesktopProxyPrefs
is), wires a Settings toggle that gates every online key lookup, and drops the
online affordance on the decrypted-message signer lookup while it is on.

## VERIFY, look before deciding

- V1. Composite-key passphrase through decrypt and export. Desktop already ships
  composite ML-KEM decrypt (2.0.0); confirm the passphrase-protected composite
  path is reached on desktop or fold it into P2.
- V2. Contact identities. Two desktop files match; confirm whether the 4.4.0
  behavior is already present or partial.
- V3. Decrypted-message view naming the key that actually decrypted. No desktop
  match found; decide whether the desktop decrypt result should name the key.
- V4. Password (symmetric) result clarity (#53). Android-specific banners, but
  check the desktop decrypt result for the same recipient-count-on-password
  confusion.

## N/A, structurally Android-only

- Per-address signing-key memory and the mail-provider process plumbing (#51):
  desktop has no OpenPGP provider or per-account mail integration. Desktop
  already has a signer picker in CryptoScreen.
- Tab-bar icon fills, inset band, Keyring-tab back navigation, NFC and Recently
  Deleted screens (#45): different UI toolkit, no equivalent.
- Recipient picker sheet scroll (#53): Android sheet behavior.
- Keygen duplicate/freeze fix (#48): Android coroutine/UI bug.

## Order of work

P1 first (small, high value, closes the 4.4.1 recipient gap). Then P3 and P4
(bounded). P2 last and largest, with V1 folded in. Run the vendored test suite
before any of it to confirm the sync compiles clean.

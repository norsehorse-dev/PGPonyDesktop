# PHASE_D21_NOTES.md — 2.0.0: move a software key onto the card (keytocard)

## D21 (2026-08-06)

The counterpart to on-card generation, and the answer to "can we make backup possible?". On-card
keys can never be backed up — the secret is born inside the chip and is non-extractable, on every
platform (this is not a mobile limitation; it is the hardware guarantee). The path to a
backup-able card key is the opposite workflow: generate the key in SOFTWARE, back up the secret,
then move it onto the card. The secret then exists in the backup and on the card — a deliberate,
user-made trade (a key that lived off-card is only as safe as its backup). gpg calls this
keytocard; this adds it to the desktop.

### Desktop-only, via the raw transport

Key import uses the ODD PUT DATA instruction (INS 0xDB, P1P2 0x3FFF) with an Extended Header List;
the vendored session's `putData` is even-instruction only (0xDA) and its `transmit` is private, so
the import can't go through the session. Since keytocard is desktop-only, it doesn't belong in the
vendored crypto anyway: `DesktopCardReader.withCardTransport` (new) hands the raw `CardTransport`,
the import APDU goes straight through `transceive` (extended-length, since RSA-4096 CRT data is
~2.5 KB), and the session's PUBLIC methods (verify, setAlgorithmAttributes, writeFingerprint,
writeGenerationTime) handle everything else on the same connection.

- **`CardKeyImport.kt`** — pure and offline-verified: pull the RSA CRT components from a keyring
  secret key (BC `RSAPrivateCrtKeyParameters`; `getDP()`/`getDQ()` called explicitly because BC
  keeps same-named private fields), and build the Extended Header List (DO 4D → empty Control
  Reference Template B6/B8/A4 → private-key template 7F48 → private-key data 5F48). Components are
  left-padded to fixed lengths and canonical BER-TLV lengths, matching gpg.
- **`DesktopCardKeyImport.kt`** — the orchestration: verify PW3, set attributes, send the import,
  then write the key's OWN fingerprint and creation time to the slot (existing, not fresh — it is
  the same key, so the slot must match the keyring entry and gpg's fingerprint for pairing to
  link). Primary → Signature, RSA encryption subkey → Decryption, RSA auth subkey →
  Authentication. A non-9000 status word names the SW, with a hint for the common refusals.

### The import-format knob

Cards differ on which RSA import format they accept: `STANDARD` (e, p, q — the card derives the
CRT params) or `CRT` (e, p, q, qInv, dP, dQ). The algorithm-attributes import-format byte must
match the Extended Header List, and both are driven by one `RsaImportFormat` enum, surfaced as a
radio in the dialog (default CRT). This is the knob to turn first if a card refuses the import.

### UI

A "Move key to card…" button next to Generate/Pair opens a dialog: pick an RSA keypair from the
keyring, its passphrase, the admin PIN, the import format, and a confirm checkbox. The warning
states the trade plainly (this key existed off-card; keep your backup). On success the card is
re-read and paired, so the keyring entry becomes card-backed. RSA only in this first cut;
Ed25519/Cv25519 import (with the Cv25519 scalar-endianness care it needs) can follow once the RSA
path is confirmed on hardware.

### Verification — and its hard limit

This is the one feature that CANNOT be proven offline. For keygen, gpg could import and validate
the result; for key import, what matters is whether the CARD accepts the APDU, and there is no
offline equivalent. So the bar is met as far as it can be: `CardKeyImport` compiled clean and was
offline-verified (the EHL is spec-shaped — correct DO nesting, CRT tag order 91-96, fixed
lengths; and the components reconstruct the modulus: p·q = n, qInv·q ≡ 1 mod p; plus BER-length
and padding edges). `DesktopCardKeyImport` compiled clean against the vendored card stack + BC +
`java.smartcardio`. The card acceptance itself is the hardware bar, and the import format may need
a round or two to tune on a given card.

### Hardware test steps (Kevin)

1. Generate a SOFTWARE RSA key (Keyring → new key, RSA 2048 or 4096), and back up its secret.
2. Cards tab → Move key to card… → pick that key, enter its passphrase + the admin PIN, leave
   format on CRT, confirm.
3. Expect the slots to fill with that key's fingerprints (matching the keyring entry), and the
   entry to show as card-backed. `gpg --card-status` should agree.
4. If the card refuses at the import (SW named in the error, e.g. 6A80), switch the import format
   to STANDARD and retry. If STANDARD works and CRT doesn't (or vice-versa), tell me which — that
   tells us the card's supported import format and I can default to it.
5. Encrypt to the key and decrypt on the card; sign and verify. Then confirm the key still works
   from your backup too (that is the whole point — a backup-able card key).

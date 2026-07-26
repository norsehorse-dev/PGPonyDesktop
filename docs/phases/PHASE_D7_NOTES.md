# PHASE_D7_NOTES.md — Hardware keys over USB (PC/SC) (plan D7)

## D7 (2026-07-25)

### What shipped

- **`PcscCardTransport`** — the desktop `CardTransport` over `javax.smartcardio`, the exact
  seam Android's `IsoDepCardTransport` fills over NFC. Because the transport is the only
  Android-coupled piece of the card layer, the ENTIRE vendored card stack
  (`OpenPgpCardSession` incl. KDF handling, `CardDecryptService`, `CardSigningService`,
  `CardKeygenService`, the BC signer/decryptor bridges, PW1/PW3 lifecycle) runs **unchanged**
  against a USB reader. `CardException` for a pulled card maps to
  `OpenPgpCardException.TagLost`, everything else to `Communication` — the same vocabulary
  every screen's error copy already speaks.
- **`DesktopCardReader`** — reader discovery + the one-operation-per-connection runner (the
  `OpenPgpCardReader` analog). `listReaders()` degrades to empty when PC/SC is absent (Linux
  without pcscd; never throws). `withCard(reader, op)` connects with protocol `"*"` (USB CCID
  tokens negotiate T=1), hands the op a session, and ALWAYS disconnects — the conservative
  session discipline the NFC path enforces, kept rather than inventing a longer-lived model
  now that USB removes the one-tap constraint.
- **Repository** (`DesktopKeyRepository` card section): `importCardKey` (link-or-insert incl.
  the 3.1.0 A1 offline-primary subkey scan via `findEntityBySubkeyFingerprint`),
  `importGeneratedCardKey`, and the card-signer text-encrypt wrapper. Card rows are
  public-only, `isCardBacked = true`, no secret material written.
- **`DesktopCardOps`** — the routing brain: `matchCardDecryptKey` scans a message's PKESK key
  IDs against each paired card row's full public ring (primary AND subkeys), and `signsOnCard`
  identifies a card signer. `CardOpDialog` is the single PIN-and-run surface: reader picker
  (when >1), PW1 entry with the **cache honored** (a live cached PIN skips the prompt), the
  touch-confirm hint, and wrong-PIN retry showing the card's tries-remaining (the cache is
  cleared by the session's `verify()` chokepoint, exactly as on Android).
- **Crypto surfaces wired for the card** (both text tabs and Files):
  - Decrypt routes to the hardware automatically when the message is addressed to a paired
    card key; the on-card result reuses the same MIME structuring as software decrypt
    (`MimeOps.structuredFromBytes`), so bundles and signature banners look identical.
  - Sign (clear + detached) and sign-and-encrypt route to the card when the chosen signer is
    a card key; the signature leg taps the card via the vendored `CardPGPContentSigner`.
  - Files: whole-batch card ops through one session/one PIN — decrypt (card-addressed files
    on the hardware, the rest in software), detached-sign, and sign-and-encrypt.
- **`CardsScreen`** (rail item enabled): reader pick + read, pair-with-keyring, on-card keygen
  (Ed25519 + Cv25519, destructive, with the "can't be backed up" confirmation), PW1/PW3
  change + unblock + factory reset, and the PW1 cache controls (TTL picker + live countdown +
  clear — the 3.1.0 B1/B2 semantics through the vendored session).
- **`DesktopCardPinCache`** gains a `prefsOverride` test hook (the DesktopProxyPrefs pattern).

### Bug fixed in passing

- **`modules("jdk.smartcardio")` → `modules("java.smartcardio")`** in build.gradle.kts. The
  JDK module that exports `javax.smartcardio` is **`java.smartcardio`**; `jdk.smartcardio`
  does not exist. The D1 placeholder was wrong — `./gradlew run` works either way on the full
  dev JDK, but the jlink runtime image (D12 installers) would have silently shipped **without
  card support**. Caught now because D7 is the first phase that actually opens the module.

### Validation (closes D7 when green)

1. `./gradlew test` — the offline suite (`DesktopCardTest`: pairing/linking incl. the A1
   subkey scan, decrypt routing, the PIN-cache twin, reader-discovery no-throw).
2. `./gradlew run` with a **YubiKey 5** over USB:
   - Hardware Keys → Read card → slots + serial shown → Pair with keyring.
   - Encrypt a message to that card's key, Decrypt it → PIN prompt (or silent if cached) →
     plaintext. Sign a message → tap → clear-signed output.
   - Files: encrypt a file to the card, decrypt it back (one PIN for the batch).
   - PIN cache: enable, 5-minute TTL, run one op, watch the countdown; wrong PIN clears it.
   - Management: change PIN, then change it back. (Factory reset only on a scratch card.)
3. Repeat the matrix on a **Token2** (the 3.1.0 tag-20 AEAD path lives here — decrypt a
   gpg-2.5-produced message to confirm the integrity gate still passes).
4. Cross-OS: the same YubiKey on macOS, Linux (with pcscd running), Windows.
5. Offline-primary layout: pair a card whose slots are subkeys of a key already in the
   keyring → links onto the existing row, no duplicate.

### Fix log

- **Fix1 (first build): `Unresolved reference 'smartcardio'` across PcscCardTransport.** The
  JDK module `java.smartcardio` is **not** part of the `java.se` aggregator, so it's absent
  from the compiler's (and a plain `java`/`test` launch's) default root-module set — the
  `modules("java.smartcardio")` in nativeDistributions only feeds the jlink image, which
  covers neither compilation nor `./gradlew run` on the full dev JDK. Fix, three places in
  build.gradle.kts: `kotlin { compilerOptions { freeCompilerArgs.add("-Xadd-modules=java.smartcardio") } }`
  (compile), `application { jvmArgs += "--add-modules=java.smartcardio" }` (run + packaged
  launcher), and `tasks.withType<Test> { jvmArgs("--add-modules=java.smartcardio") }` (tests).
- **Fix2 (Kevin, on-card key): "A recipient's public ring failed to load".** A key generated
  ON the card produced a card-backed row with `armoredPublicKey = null` — the generated public
  certificate was never stored. Root cause in `mergeIfNewMaterial`: it bailed to
  `ALREADY_IN_KEYRING` whenever there was no *pre-existing* stored ring to merge against, but a
  freshly-created card row (from pairing OR the moment after on-card keygen) has none — so the
  incoming certificate (from `importGeneratedCardKey` → `importArmoredKeyDetailed`, and equally
  from importing a cert onto a paired card row) was silently dropped. Fix: when the row holds
  no public material yet, treat the incoming ring as new material and store it (MERGED). Two
  regression tests added. Also hardened the recipient list to Android's exact rule
  (`!card || armor != null`) so a card row still missing its cert can't be selected, and the
  encrypt error now names the offending key. **Existing broken rows don't self-heal** — see the
  recovery note.

### Recovering a card key generated before Fix2

The row is card-backed but has no stored public certificate, and a card *read/pair* doesn't
reconstruct a full certificate (it only reads fingerprints). Two ways forward:
- If the public key was exported/backed up anywhere, import it (paste or file) — it links onto
  the card row by fingerprint and, with Fix2, now stores the armor. The row becomes usable.
- Otherwise, delete the row in the Keyring and **regenerate on the card** (the keys are test
  keys; regeneration overwrites the card slots and, with Fix2, stores the certificate this
  time). Reconstructing a transferable public key from an already-provisioned card is a
  possible later feature (assemble from the card's public-key material + a card self-sig).

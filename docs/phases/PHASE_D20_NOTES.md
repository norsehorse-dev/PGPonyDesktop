# PHASE_D20_NOTES.md — 2.0.0: RSA on-card key generation

## D20 (2026-08-02)

On-card keygen shipped Ed25519 + Cv25519 only. This adds RSA-2048 and RSA-4096 on-card
generation. Requested for desktop; deliberately NOT for mobile (a phone can't reasonably drive
RSA card generation), so this does not go into the shared portable crypto at all.

### Desktop-owned, not vendored

The vendored `CardKeygenService` (from PGPonyAndroid) is hardcoded to Ed25519, and the house rule
is never to hand-edit `vendor/app-crypto/`. Since RSA card keygen is desktop-only, the right home
is a desktop twin, not an upstream change: `DesktopCardKeygen.kt` (the card orchestration) and
`RsaCardPackets.kt` (the pure packet building). They REUSE the vendored card primitives —
`OpenPgpCardSession`'s APDU methods, `CardKeyPacketBuilder`'s generic packet/subpacket helpers,
`CardSigningFormat`'s DigestInfo — and add only what is RSA-specific: the vendored public-key
bodies and signature packets embed the EdDSA algorithm id (22), so RSA needs its own body
(`4 || creation || algo 1 || MPI(n) || MPI(e)`), its own signature-packet assembly (a single
PKCS#1 MPI), and a signature trailer carrying algo 1. The card path returns the same
`CardKeyGenResult`, so the caller (`importGeneratedCardKey`) is unchanged.

The primary is an RSA sign+certify key, the subkey an RSA encryption key; both self-signatures
(certification and subkey-binding) are made by the primary via the card's PSO:CDS over a SHA-256
DigestInfo. The private keys never leave the card and cannot be backed up.

### The byte-exactness proof, without hardware

The vendored EdDSA path was ported from a reference and "verified against gpg byte-for-byte."
There is no reference port for RSA, so correctness is proven a different way. `RsaCardPackets` is
pure with signing INJECTED, which lets a software RSA key stand in for the card. While this
landed, an offline harness generated two software RSA keys, assembled the full transferable
public key, and had **real gpg import it**: gpg accepted the key, computed **the same fingerprint
byte-for-byte**, validated both self-signatures (`sig!3` certification, `sig!` binding), and read
it as `pub rsa2048 [SC]` + `sub rsa2048 [E]`. That proves the packet building (the public-key
body must be byte-exact because it feeds the v4 fingerprint; MPIs are canonical-minimal to match
gpg). `RsaCardPacketsTest` pins the same proof hermetically for the suite: Bouncy Castle parses
the assembled key and verifies the structure, the fingerprint, and both self-signatures — 5 cases,
run green, no external tool.

What offline verification CANNOT cover, and so is the hardware matrix (§8): the card's RSA
algorithm-attribute bytes (`01 || modulus-bits || 0x0020 || 0x00`) and the generate step. The
import-format byte (`0x00`, standard) is the one most likely to need adjusting for a specific
card, and RSA-4096 generation is card-dependent — a card may simply refuse it.

### UI

`CardKeygenDialog` gains a key-type picker (Ed25519 / RSA 2048 / RSA 4096, technical labels, not
translated); the generate handler dispatches Ed25519 to the vendored `CardKeygenService` and the
two RSA sizes to `DesktopCardKeygen.generateRsaOnCard`. One new string, `d_cards_keygen_algo_label`
("Key type"), in all six locales; strict i18n audit green.

### Verification

`DesktopCardKeygen` and `RsaCardPackets` compile clean against the full tree (all vendored card
APIs resolve). `RsaCardPacketsTest` compiled and RAN green (5/5) under JUnit4 with Bouncy Castle.
The offline gpg import + fingerprint-match + signature-validation ran green in the container. The
CardsScreen UI wiring introduces no new real errors (the standing Compose-absence cascade only).
The gradle suite on the Mac is the gate; the on-card generate + `gpg --card-status` + sign/verify
round-trip on a real RSA-capable key is the hardware acceptance bar.

### Hardware test steps (for Kevin, on an RSA-capable card)

1. Cards tab → generate on card → pick RSA 2048 → generate. Expect a new `rsa2048 [SC]` primary
   + `rsa2048 [E]` subkey linked to the card, no error.
2. If the card supports it, repeat with RSA 4096. A refusal here is the card, not the code —
   note which card and whether it advertises rsa4096 in its algorithm attributes.
3. `gpg --card-status` should show the same fingerprints; encrypt to the new key and decrypt on
   the card; sign with the card and verify. If generation fails at `setAlgorithmAttributes`, the
   import-format byte (`RsaCardPackets.rsaAttributes`, currently `0x00`) is the first thing to try.

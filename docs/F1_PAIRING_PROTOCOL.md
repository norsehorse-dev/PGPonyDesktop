# PGPony pairing protocol v1

Status: draft for desktop 3.0.0 (F1), 2026-09-30. Byte-exact: Android and iOS build against
this document, and a change to any byte below bumps the version.

Two PGPony installs on the same network pair for one session and move public keys, key pairs
or a full backup between them. Desktop 3.0.0 pairs two computers. Phones join later with the
same protocol and a QR code (section 8).

Decided (2026-09-30):
- Authentication is numeric comparison: both screens show the same six-digit code and each
  user confirms it matches. No PAKE, so every platform needs only X25519, SHA-256, HMAC and
  AES-GCM (CryptoKit has all four).
- A pairing lasts one session. Its keys are wiped when either side closes; nothing is stored,
  and no listener runs outside an open pairing window.

## 1. Roles and transport

- The **host** opens a pairing window and listens. The **joiner** connects to it.
- Transport is one TCP connection on the local network. The host listens on an ephemeral port
  on every interface for the length of the window (10 minutes at most), accepts one
  connection, and closes the listener as soon as that connection arrives, so there is never a
  second one to turn away. (ABORT reason 1, busy, is reserved for a host that keeps listening.)
- The host screen shows each non-loopback address with the port, for example
  `192.168.1.20:49152`, which the joiner types. No mDNS: nothing is advertised.
- A window ends after one pairing attempt, whatever its outcome. A failed or refused pairing
  needs the user to open a new window, so an attacker gets one guess at the code per window.
  The cost is that anything else that connects first, even by accident, uses up the window.

The connection has three phases:

1. Pairing handshake, framed as below with the magic `PGPP`.
2. Key confirmation, which is the PonyDirect LAN identify handshake keyed with the pairing key.
3. The session: PonyDirect `ENVELOPE` frames, each carrying one encrypted message.

## 2. Framing

Every frame in every phase has the PonyDirect shape:

    type(1) | length(4, big-endian) | payload(length)

A frame longer than 1,114,112 bytes (1 MiB plus 64 KiB) is a protocol error. All integers are
big-endian. Labels are ASCII with no terminator. `||` is concatenation.

## 3. Phase 1: pairing handshake

The joiner writes the 4 ASCII bytes `PGPP` on connect; the host checks them and replies with
`PGPP`. Then:

| Type | Name | Direction | Payload |
|---|---|---|---|
| `0x41` | JOIN | joiner to host | `version(1) = 0x01` \|\| `pk_J(32)` |
| `0x42` | ACCEPT | host to joiner | `pk_H(32)` \|\| `commit(32)` |
| `0x43` | NONCE_J | joiner to host | `n_J(32)` |
| `0x44` | NONCE_H | host to joiner | `n_H(32)` |
| `0x4F` | ABORT | either | `reason(1)` |

- `pk_J`, `pk_H`: X25519 public keys, fresh for each attempt (RFC 7748).
- `n_J`, `n_H`: 32 random bytes each, fresh for each attempt.
- `commit = HMAC-SHA256(key = n_H, "pgpony/pair/commit/v1" || pk_H || pk_J)`

The order matters. The host commits to `n_H` before it sees `n_J`, and the joiner sends `n_J`
before it sees `n_H`, so neither side, and no one in the middle, can pick a nonce that steers
the code. On NONCE_H the joiner recomputes `commit` and aborts with reason 3 if it differs.

Both sides then compute:

    Z   = X25519(own secret, peer public key); all-zero Z aborts (reason 3)
    T   = SHA-256("pgpony/pair/transcript/v1" || pk_J || pk_H || n_J || n_H)
    PRK = HKDF-Extract(salt = T, ikm = Z)                       (HKDF-SHA256, RFC 5869)
    K    = HKDF-Expand(PRK, "pgpony/pair/key/v1", 32)           PonyDirect pair key
    k_HJ = HKDF-Expand(PRK, "pgpony/pair/host-to-joiner/v1", 32)
    k_JH = HKDF-Expand(PRK, "pgpony/pair/joiner-to-host/v1", 32)
    code = uint32(first 4 bytes of SHA-256("pgpony/pair/code/v1" || T)) mod 1,000,000

The code is shown as six digits in two groups of three, zero-padded (`042 917`).

ABORT reasons: 1 busy, 2 unsupported version, 3 handshake failed, 4 refused by the user,
5 timed out. The sender closes the connection after an ABORT. Any other frame type in
phase 1 is a protocol error: close without a reply.

Timeouts: 30 seconds for each phase 1 frame; 5 minutes for the users to compare the code.

## 4. Phase 2: key confirmation

Each screen shows the code and asks "Does the other computer show the same code?".

- When the joiner's user confirms, the joiner writes `PDR1` and a PonyDirect HELLO keyed with
  `K` (WIRE-PROTOCOL.md, LAN identify handshake). If its user says no, it sends ABORT 4.
- The host reads the HELLO but does not answer it until its own user confirms. Then it checks
  the HELLO tag with `K`: if it verifies, the host writes `PDR1` and HELLO_ACK; if not, it
  writes `PDR1` and NO_MATCH and closes. If the host's user says no, it sends ABORT 4 instead
  (a phase 1 frame; the host has not written `PDR1` yet).
- The joiner checks HELLO_ACK with `K`. NO_MATCH or a bad tag ends the attempt.

HELLO and HELLO_ACK prove that each side shares `K` with the connection it is talking to, which
ties the users' decision to this exchange: once the codes matched and both users confirmed, no
one else holds the session keys. Someone in the middle has to run a separate exchange with each
side and ends up with two unrelated codes on the two screens. The chance that they match is one
in a million, and the window closes after that one try. A user who confirms without comparing is
the only way through, which is why both users confirm and the screen says what a mismatch means.

## 5. Phase 3: the session

Every message is one PonyDirect `ENVELOPE` (`0x04`) frame whose payload is:

    seq(8) || AES-256-GCM(key, nonce = 0x00000000 || seq(8), aad = "pgpony/pair/msg/v1" || seq,
                          plaintext = type(1) || body)

`key` is `k_HJ` for messages the host sends and `k_JH` for the joiner's. `seq` starts at 0 in
each direction and goes up by one per message; a receiver requires exactly the next value, so a
replayed, dropped or reordered message ends the session. The ciphertext includes the 16-byte
tag. The plaintext is at most 1,048,576 bytes.

| Type | Name | Body |
|---|---|---|
| `0x01` | INFO | JSON `{"name": "...", "app": "PGPony Desktop 3.0.0"}` |
| `0x10` | OFFER | JSON `{"items": [ITEM, ...]}` |
| `0x11` | ANSWER | JSON `{"accept": [id, ...]}`, empty to decline all |
| `0x20` | ITEM_BEGIN | `id(4)` \|\| `size(8)` |
| `0x21` | ITEM_DATA | `id(4)` \|\| bytes |
| `0x22` | ITEM_END | `id(4)` \|\| `SHA-256 of the item(32)` |
| `0x30` | RESULT | JSON `{"id": n, "ok": true, "error": null}` |
| `0x3F` | BYE | empty |

`ITEM` is `{"id": n, "kind": "public-key" | "key-pair" | "backup", "name": "...",
"fingerprint": "hex or null", "size": n}`. JSON is UTF-8. Unknown JSON members are ignored;
an unknown message type ends the session.

Flow: each side sends INFO first (device names travel only inside the session, never in the
clear). Either side may then send an OFFER. The receiver shows it, the user picks, and the
receiver answers with the ids it accepts. The sender sends each accepted item as ITEM_BEGIN,
ITEM_DATA messages that each stay within the plaintext limit (at most 1,048,571 item bytes
apiece), and ITEM_END; the receiver checks the size
and hash, imports it, and reports a RESULT for that id. A side may send another OFFER after the
RESULTs for the previous one. BYE, or closing the connection, ends the session; both sides then
wipe `K`, `k_HJ` and `k_JH`.

Limits: one item is at most 64 MiB, one OFFER lists at most 1,000 items, and a side has at most
one OFFER outstanding.

## 6. What moves

- **public-key**: one certificate, armored, as PGPony exports it.
- **key-pair**: one secret key, armored, as PGPony exports it, and never unprotected. A key with
  a passphrase goes as stored, and the receiver needs that passphrase to use it. A key without
  one is exported under a transfer passphrase the sending user types (the stored key is not
  changed). It arrives protected by that passphrase; the receiving user needs it to use the key
  and can change or remove it in Key Detail.
- **backup**: a PGPony backup file, encrypted under a recovery code generated for this
  transfer. The sending screen shows the code and the receiving user types it, as in a restore
  from a file.

The receiver imports through the same code as a file import or a restore, with every check
those run. Pairing adds a way to carry the bytes and nothing else: no item skips validation,
and nothing is imported that the receiving user did not accept.

## 7. What an observer learns

Someone watching the network sees two addresses, the port, the `PGPP` and `PDR1` magics, two
X25519 public keys, the nonces, and the sizes and timing of the encrypted messages. Device
names, key names, fingerprints and all key material are inside the session. The session key
never leaves memory and is not reused across windows.

## 8. Phones (reserved for Android 4.7.0 or later and iOS)

The host also shows a QR code:

    pgpony-pair:1?a=<ip:port>[,<ip:port>...]&h=<base64url(SHA-256(pk_H)[0..16])>

Its host key is generated when the window opens, so the QR fixes it. A phone joiner scans it,
connects to an address from `a`, and checks that the `pk_H` in ACCEPT matches `h` before it
continues; a mismatch aborts with reason 3. The code comparison in phase 2 stays in place for
phones too, since the QR authenticates the host to the phone but not the phone to the host.

## 9. Test vectors

`src/test/resources/pairing/v1-vectors.json` fixes the X25519 keys and nonces of one attempt
and lists `commit`, `T`, `K`, `k_HJ`, `k_JH`, `code`, and the first sealed message in each
direction. An implementation that does not reproduce them does not speak this protocol.

# PHASE_D15_NOTES.md — 2.0.0 the agent: ssh-agent + git signing shim (plan 2.0.0 §1)

## D15 (2026-08-02)

The anchor pillar of 2.0.0: making other software depend on PGPony. Two faces of the same
idea — serve the keyring's authentication keys to `ssh`, and serve its signing keys to `git` —
built on infrastructure D1–D14 already put in place (the keyring, subkey capabilities, the
single-instance socket precedent, the CLI's key resolver). No new crypto; two well-specified
wire protocols and the plumbing to host them.

### Four decisions taken up front (the plan's open questions)

1. **Windows agent transport (Q1): a helper exe, later.** The JDK cannot serve the named pipe
   OpenSSH-for-Windows expects, and the decision is a tiny native pipe↔socket bridge in a
   later phase rather than a JNA dependency now (the flat-dependency posture). 2.0.0 ships the
   agent on macOS/Linux; `SshAgentService.isSupported()` gates every entry point and the
   Settings section says so plainly. This did not stall the macOS/Linux work, as intended.
2. **Card AUT advertising (Q5): hide until the cert is imported.** The recipients-rule
   precedent — a pairing-only row (a card whose AUT public certificate was never imported)
   does not appear as an identity. `ssh-add -L` needs the full public key anyway, so an
   advertised row without its cert would be broken. The seam is `SshAgentKeys.identities`.
3. **Shim shape (Q2): a dispatch face, not a third binary.** `pgpony-gpg` is the one artifact
   under another name — reached by argv[0] basename (how git invokes `gpg.program`, seen via
   `jpackage.app-path`) or the explicit `gpg-shim` verb. No new binary to sign/notarize/declare;
   Windows still gets its own `pgpony-gpg.exe` from packaging, the `pgpony-cli.exe` precedent.
4. **Scope: agent core + the shim's sign/verify slice.** Both landed this phase.

### 1a. The SSH agent

`SshWire.kt` is the protocol, pure: bytes in, bytes out, no I/O, no keyring, no threads — the
ExpirationNotifier split, so the wire is unit-tested without a socket (`SshWireTest`, 13
cases, run green). Only the committed slice is served: `REQUEST_IDENTITIES`, `SIGN_REQUEST`,
and the failure code; every other request — add/remove, lock, extensions — answers
`SSH_AGENT_FAILURE`, which is the spec's own instruction for the unrecognized. mpint encoding
delegates to `BigInteger.toByteArray()` (its two's-complement minimal form is exactly RFC
4251's), and the 0x80-padding edge is the test that proves the delegation.

`SshAgent.kt` is the impure half:

- **Identities** are the authentication-capable subkeys with LOCAL secret material
  (`SubkeyCapability.Authenticate`), re-enumerated per `REQUEST_IDENTITIES` so imports and
  deletions show up without a toggle. PGP→SSH conversion runs through BC's lightweight
  `BcPGPKeyConverter` (no JCA provider needed) — Ed25519 (v4 algo 22 and v6 algo 27) and RSA;
  anything else (Ed448, PQC, ECDH) has no SSH name and is skipped. The card AUT leg is stubbed
  at the identities seam: `OpenPgpCard.INS_INTERNAL_AUTHENTICATE` is unimplemented in the
  vendored session ("deferred (auth slot)"), and vendored files are fixed upstream in
  PGPonyAndroid then re-synced, never edited here — so card AUT waits on that upstream sync.
- **Signing** produces the RAW algorithm signature (bare Ed25519 / PKCS#1 via `Ed25519Signer` /
  `RSADigestSigner`), deliberately NOT a PGP signature — mixing the two containers is how a
  signing oracle grows. The RSA flag chooses `rsa-sha2-256/512`; flagless `ssh-rsa` (SHA-1)
  survives only as the spec default modern OpenSSH never sends.
- **Unlock** tries the empty passphrase first (PGPony's generated keys are passphrase-less by
  default), then prompts through `AgentPrompt` — the TrayNav idiom: a `@Volatile` request the
  window polls, rendered as `AgentUnlockDialog`, completed back through a latch the agent
  thread waits on, one prompt at a time, 60s timeout. The `s2KUsage == 0` test distinguishes
  "unprotected but still failed" (structural, give up) from "protected" (prompt).
- **The listener** is a `UnixDomainSocketAddress` `ServerSocketChannel` (JDK 16+, no
  dependency) on a daemon `pgpony-ssh-agent` thread, socket 0600 in a 0700 dir under the
  config dir (`Config.agentDir`), deleted on stop and via a shutdown hook. Serial accept like
  SingleInstance — ssh clients hold a connection for milliseconds, and a queue of one keeps
  every signature behind the single prompt path. Off by default; the toggle
  (`DesktopState.enableSshAgent`) starts/stops it and an enabled agent restarts at launch.
  Settings shows the `SSH_AUTH_SOCK` export line with a copy button.

### 1b. The git signing shim

`GpgShim.kt`, pure over its streams (`run(argv, stdin, stdout, stderr): Int`) so a test drives
it without a process (`GpgShimTest`). It speaks exactly git's slice:

- **Sign** (`-bsau <key>`): read stdin, resolve the key against the app keyring (`Cli.matchKeys`),
  write the armored detached signature to stdout, emit `[GNUPG:] SIG_CREATED` on the status fd.
  A passphrase-protected key can't be served non-interactively (git has no way to prompt through
  the shim) and says so — the GUI agent is the interactive path.
- **Verify** (`--verify <sig> <data>`): `VerifyService.verifyDetached` mapped to
  `GOODSIG`+`VALIDSIG` / `BADSIG` / `NO_PUBKEY` on the status fd, human text on stderr, exit 0
  only on a good signature.
- `--version` answers plausibly (git probes `gpg.program` with it) without touching the keyring;
  anything else exits non-zero. The bounded contract — no Assuan, no agent emulation (§1c).

Status-fd handling honors the plan's pinned `--status-fd=1|2` by routing to stdout/stderr; any
other fd falls back to stderr rather than dup'ing an arbitrary inherited descriptor the JVM
can't portably reach.

### Files

New: `SshWire.kt`, `SshAgent.kt`, `GpgShim.kt`; tests `SshWireTest.kt`, `SshAgentKeysTest.kt`,
`GpgShimTest.kt`. Edited: `Main.kt` (shim dispatch + `gpg-shim` verb + `invokedAsGpgShim`),
`Config.kt` (`agentDir`), `Gui.kt` (toggle state, launch restart, prompt drain loop),
`SettingsScreen.kt` (the section). Strings: 12 new `d_` keys in all six locales (strict i18n
audit green, 505/505 per locale).

### Verification

`SshWire` compiles standalone against the JDK alone; the BC conversion/signing calls were
type-checked against real Bouncy Castle jars in isolation; the full main tree was compiled with
BC + coroutines on the classpath and diffed against a pristine-tree compile — the one real
finding (a suspend `loadPublicKeyRing` called outside its coroutine in the shim's verify) was
fixed. `SshWireTest` was compiled and RUN green (13/13) under JUnit4 in the container. The
gradle suite on the Mac is the gate as always; the end-to-end rows — `ssh-add -L`, `ssh` to a
host, `git commit -S` + `git verify-commit`, the GitHub verified badge — are the manual matrix
(§8), since the container has no ssh/git-signing harness to drive them.

### Deferred / follow-ups

- Card AUT signing, gated on the upstream `INTERNAL AUTHENTICATE` sync into PGPonyAndroid.
- The Windows agent helper exe (tracked from Q1).
- `RELEASING.md` §7 grows the `pgpony-gpg` launcher declaration per platform when packaging
  work reaches it; `Config.VERSION` / `packageVersion` move to 2.0.0 at release, not here.

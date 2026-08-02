# PGPony Desktop 2.0.0 Planning

Status: draft
Base: 1.1.0 (the field-report fixes plus the Message/Files restructure — see `PLANNING_DESKTOP_1_1_0.md`)
Origin: feature brainstorm, Aug 2 2026, starting from the question "what could only work on desktop?"
Plan of record for the 1.x line remains `PLANNING_DESKTOP_1_0_0.md` in the PGPonyAndroid repo root. This doc is the next major, not an increment.

## Theme

1.0 built a window you open. 2.0 makes PGPony part of the machine.

Everything in this plan is structurally desktop-only — not "the phone hasn't done it yet" but "a phone cannot do it": other programs asking the app to do crypto, the OS file manager offering the app's verbs, folders that encrypt themselves, clipboards watched from a tray. Three pillars, one carried item:

1. **The agent** — SSH authentication and git commit signing served from the PGPony keyring, hardware keys included.
2. **OS integration** — file-manager context menus on all three platforms, and an opt-in clipboard sentinel.
3. **Files at desktop scale** — folder encryption, multi-gigabyte streaming with progress, watch-folder rules, and a verify-a-download flow.
4. **Russian localization + the plural engine** (carried from the 1.0.4/1.1.0 planning, still gated on its external dependencies).

The scope decision made up front: SSH + git signing, **not** full gpg-agent emulation. The Assuan protocol surface is enormous, versioned against GnuPG's own behavior, and owning it means owning every tool that speaks it. git's `gpg.program` contract and the ssh-agent protocol are small, documented, and stable. That is the bounded version of "replace GnuPG" and it is the one this release commits to.

## 1. Pillar: the agent

### Why this is the anchor

A PGP app earns daily use when other software depends on it. Developers keep GnuPG installed for exactly two reasons that recur in the field: `ssh` via gpg-agent and `git commit -S`. Both run through infrastructure this repo already has — the vendored card stack over PC/SC, the PIN cache with TTL, subkey capabilities (`SubkeyCapability.kt` already models AUTHENTICATION), and a keyring that knows which keys can do what. The missing piece is not crypto; it is two well-specified wire protocols.

### 1a. SSH agent

Serve the ssh-agent protocol (draft-miller-ssh-agent: `REQUEST_IDENTITIES`, `SIGN_REQUEST`, and the failure codes — the rest can return `AGENT_FAILURE`) from a background listener owned by the running app:

- **Identities** are the authentication-capable keys in the keyring: software auth subkeys, and the AUT slot of a paired card. Conversion is PGP key material → SSH wire format (Ed25519 and RSA first; they cover the fleet. ECDSA if the keyring ever holds one).
- **Signing** routes through the existing services: software keys via the vendored signing path, card keys via `OpenPgpCardSession` with the PIN cache. A sign request for a card key that needs a PIN raises the window / posts a tray notification rather than failing — the same interaction shape as `CardOpDialog`.
- **Sockets.** macOS/Linux: `UnixDomainSocketAddress` — in the JDK since 16, we build on 17+, no dependency. Socket file mode 0600 in a 0700 directory under the config dir; print the `SSH_AUTH_SOCK` line in Settings for copy-paste. Windows: OpenSSH-for-Windows expects a named pipe (`\\.\pipe\openssh-ssh-agent`), and the JDK cannot *serve* named pipes. Options: a small JNA dependency, or a tiny native helper exe that bridges pipe↔localhost like the WiX story, or Windows ships without the agent in 2.0.0. Decision needed before the pillar is scheduled (open question 1) — the repo's flat-dependency preference (see the ICU4J discussion in the 1.1.0 doc) argues against JNA, but there is no twenty-line hand-written table for this one.
- **Lifecycle.** The agent runs while the app runs, matching the tray posture; a headless `pgpony agent` CLI verb can come later if demand shows up. Off by default, one toggle in Settings.

### 1b. Git signing shim

git shells out to whatever binary `gpg.program` names. Ship `pgpony-gpg` (and `pgpony-gpg.exe` — the Windows console-subsystem precedent is already established by `pgpony-cli.exe`) speaking exactly the slice git uses:

- **Sign:** `gpg --status-fd=2 -bsau <keyid>` — read the payload from stdin, write the armored detached signature to stdout, emit `[GNUPG:] SIG_CREATED` on the status fd.
- **Verify:** `gpg --keyid-format=long --status-fd=1 --verify <sig> <data>` — emit `GOODSIG` / `BADSIG` / `VALIDSIG` / `NO_PUBKEY` against the keyring, human-readable text on stderr.

That is the whole contract for commits and tags. The shim resolves keys against the app's keyring, uses the same never-downgrade signing rule as the Encrypt surface (Phase A3), and for card-backed signers either uses the PIN cache or forwards to the running app for the PIN prompt. One `git config --global gpg.program pgpony-gpg` and commits are signed by the keyring or the hardware key — verified badges with no GnuPG installed.

### 1c. Explicitly out of scope for 2.0.0

- Full gpg-agent / Assuan emulation. Revisit only if 2.0 telemetry-free feedback demands it.
- A browser-extension native-messaging host. It is the natural 2.1 candidate — the agent gives it the process model for free — but it needs its own security design and does not gate anything here.

## 2. Pillar: OS integration

### 2a. File-manager context menus

D9/D13 built the plumbing: single-instance forwarding, `AppOpen`, `DesktopFileRouter.classify`, file associations. A context-menu entry is just a new way to invoke it. Add explicit CLI routing (`pgpony open --op encrypt <file>…`) so a menu verb can force an operation instead of relying on classification, then per platform:

- **Windows:** static registry verbs (`HKCR\*\shell\PGPony.Encrypt\command` and friends), authored in WiX alongside the existing association work. Encrypt on `*`; Decrypt/Verify on `.gpg`/`.pgp`/`.asc`/`.sig`. Known caveat: on Windows 11 static verbs live under "Show more options" — the first-class menu needs an `IExplorerCommand` DLL in a sparse package, which is native code and a 2.x follow-up, not a 2.0.0 gate.
- **macOS:** file associations already give "Open With → PGPony". For real verbs, ship Finder Quick Actions (bundled `.workflow` bundles installed to `~/Library/Services` on first run, with a Settings toggle) that invoke the CLI. Notarization treats them as data, not code, but verify this on a clean machine before committing (test matrix).
- **Linux:** `.desktop` `Actions=` entries (GNOME shows them on right-click of an associated file), plus a Nautilus scripts installer and a KDE ServiceMenus `.desktop` — all text files, all cheap, all installable from Settings without root.

### 2b. Clipboard sentinel

A tray-resident watcher, **off by default** (the update-check opt-in posture): when enabled, poll the AWT clipboard on a couple-second tick and recognize three shapes — `BEGIN PGP MESSAGE`, `BEGIN PGP PUBLIC KEY BLOCK`, `BEGIN PGP SIGNED MESSAGE`. On sight, post one tray notification ("Encrypted message on clipboard — decrypt?"); clicking routes through the existing `OpenAction` path (`DecryptText`, `ImportKey`, verify). Dedupe by content hash so the same clipboard never notifies twice.

Rules that make it shippable: it never auto-decrypts, never touches key material without a click, never logs or persists clipboard contents, and the poll reads only text flavors. The setting copy should say all four things.

## 3. Pillar: files at desktop scale

### 3a. Folder encryption

Encrypting a dropped *folder* today is an error. Make it a tarball leg on the existing streaming encrypt: walk, tar, encrypt — one `.tar.gpg` out. On decrypt, when the plaintext is a tarball, offer extract-to-folder.

The tar decision mirrors the plural-selector one: `java.util.zip` is in the stdlib but produces something gpg users don't expect, Commons Compress is a new dependency on a module that has none to spare, and a hand-written ustar reader/writer is ~200 lines each way, covers regular files + directories + the long-name extension, and buys `gpgtar` interop. The hand-written table won last time for smaller stakes; propose the same here, with the interop tests (`gpgtar -d` on our output, our extract on `gpgtar` output) as the acceptance bar.

Extraction is a security surface: path traversal (the zip-slip shape) must be rejected, symlinks skipped or contained, and the test matrix carries hostile-archive cases.

### 3b. Multi-gigabyte honesty

The engine already streams; the UI doesn't say so. Audit `FileCryptoOps` for any full-file buffering, then add per-file progress (bytes through the stream), cancel, and a Files-tab row state that shows it. Acceptance: a 10 GB encrypt on a spinning disk shows moving progress, cancels cleanly, and leaves no partial output behind (the never-overwrite rule extends to never-leave-partials).

### 3c. Watch folders

Rules of the form: folder + glob + recipients → encrypt arrivals, via `java.nio.file.WatchService` (stdlib). **Encrypt-only by design** — encryption needs only public keys, so an unattended rule never holds a passphrase, never touches a PIN, and a compromised rules file can at worst encrypt things. Sign and decrypt stay interactive, permanently. Per-rule options: output directory, delete-original-after (default off), armor. Quiesce heuristic before touching a file (size stable across two ticks) so half-copied files don't get eaten; outcomes surface as tray notifications and a results pane. Rules persist in the config dir; the surface lives in Settings.

This turns PGPony into backup infrastructure: "anything landing in ~/Backups is encrypted to the offsite key" is a sentence a user can now say.

### 3d. Verify a download

Drop a file, its detached `.sig`/`.asc`, and optionally a `SHA256SUMS(.asc)` onto Files-tab Verify: pair (the `pairDetached` logic exists), hash, check the sums line, verify the signature, one verdict banner naming what was checked. This is our own release page's workflow — `RELEASING.md` produces exactly these artifacts — so the feature dogfoods the release process and the test fixtures are the previous release's files.

## 4. Russian + the plural engine (carried)

Scope and analysis live in the 1.1.0 planning doc §4 and are not repeated here; the substance: `values-ru` must land in PGPonyAndroid first (vendored strings), the desktop layer follows, and `trQuantity`'s two-way branch must become a CLDR plural-category selector (hand-written rule table, ~20 lines, over an ICU4J dependency) because Russian needs `one`/`few`/`many`/`other`. The selector rework is not Russian-specific and should land early in 2.0.0 with its own test pass at counts 1, 2, 3, 5, 11, 21, 101. Shipping gate unchanged: a confirmed native reviewer, or Russian holds regardless of code readiness.

## 5. What 2.0.0 deliberately does not do

- **No accounts, no servers, no telemetry.** Unchanged and load-bearing; every feature above works with the network cable pulled (keyserver features aside).
- **No phone↔desktop LAN bridge yet.** QR-authenticated local pairing for key/backup transfer is attractive and fits the no-server posture, but it is a protocol design with real attack surface and deserves its own doc. 2.1 candidate.
- **No browser extension, no Assuan** (§1c).
- **No IA changes.** The Message/Files restructure ships in 1.1.0; 2.0.0 inherits it frozen. New surfaces (watch rules, agent) are Settings sections, not tabs.

## 6. Sequencing

The pillars are independent; inside them, order matters:

1. `trQuantity` selector rework (small, self-contained, everything else sits on top of strings).
2. CLI `open --op` routing (context menus and sentinel both land on it).
3. SSH agent core + socket on macOS/Linux → shim (`pgpony-gpg`) → Windows pipe decision.
4. Folder/tar + progress (3a/3b), then watch folders (3c) on top of the same ops, verify-a-download (3d) any time.
5. Context menus per platform as installer work completes; clipboard sentinel late (it is small and rides on routing).

## 7. Release mechanics

- Two new binaries per platform (`pgpony-gpg`, and the Windows agent helper if that path is chosen) — signing and notarization cover them; `RELEASING.md` grows a section.
- Installer deltas: WiX registry verbs, macOS bundled Quick Actions, deb/AUR `.desktop` actions. The winget and AUR packagings need the new binaries declared.
- `Config.VERSION` / `packageVersion` move together to 2.0.0; the drift test added in 1.1.0 enforces agreement.
- Release notes should name the agent + shim as the headline and be explicit about what is opt-in (sentinel, watch folders, agent — all off by default).

## 8. Test matrix (delta over the standing suites)

| Area | Case | Expected |
|---|---|---|
| SSH agent | `ssh-add -L` against the socket | Auth-capable keys listed, correct comments |
| SSH agent | `ssh` to a host with a software Ed25519 auth subkey | Auth succeeds |
| SSH agent | Same with the card's AUT slot, PIN not cached | Prompt raised, auth succeeds after PIN |
| Git shim | `git commit -S` + `git verify-commit`, software key | Signed, verifies; `gpg --verify` agrees on another machine |
| Git shim | Tag signing + GitHub verified badge | Badge shows |
| Context menu | Right-click Encrypt on Windows/GNOME/KDE; Quick Action on macOS | App front, file queued, op forced |
| Sentinel | Copy armored message with sentinel on / off | Notification once / nothing |
| Folder | Encrypt folder → `gpgtar -d`; `gpgtar` output → our extract | Both round-trip |
| Folder | Hostile archive: `../` member, symlink out | Rejected, named error |
| Big file | 10 GB encrypt: progress, cancel mid-way | Moves, cancels, no partial output |
| Watch | Rule on folder, copy 3 files in slowly | 3 outputs after quiesce, 3 notifications |
| Watch | App restart with rules present | Rules resume, nothing double-encrypted |
| Verify DL | Previous release's `.dmg` + `.sig` + `SHA256SUMS` | One good verdict naming both checks |
| Plurals | Every plural key at 1, 2, 3, 5, 11, 21, 101 per locale | Correct category per CLDR |

## 9. Risks

- **The Windows agent transport** is the one place a dependency or native code may be unavoidable. Decide early; do not let it stall the macOS/Linux agent, which has no such problem.
- **Windows 11 context-menu demotion** makes the cheap path look half-done. Ship it anyway, say so in release notes, keep the sparse-package work visible on the roadmap.
- **The sentinel reads clipboards**, which is what malware does; being opt-in, click-to-act, and loudly documented is the defense. Copy review before ship.
- **Watch folders act unattended.** Encrypt-only bounds the damage, but a bad rule can still churn a folder; delete-original defaults off and outcomes are always surfaced.
- **Tar extraction** is a new parser facing hostile input. The traversal/symlink cases are in the matrix; keep the parser dumb.
- **Scope.** Three pillars is a real release. The sequencing puts the agent first for a reason: if 2.0.0 slips, a 1.2.0 of "agent only" is a coherent fallback; context menus alone are not.

## 10. Open questions

1. Windows agent transport: JNA, helper exe, or no Windows agent in 2.0.0?
2. `pgpony-gpg` as a third binary, or `pgpony-cli` growing an argv[0] / verb dispatch? (Windows needs distinct exes either way.)
3. Do watch-folder outcomes need a persistent log surface, or are tray notifications + the results pane enough?
4. Finder Quick Actions: bundle-install from Settings, or document-and-link only?
5. Does the agent advertise card keys whose public certificate is absent (pairing-only rows), or hide them until the cert is imported (the recipients-rule precedent)?
6. Russian reviewer status — same gate as before; any movement from the reporter?

## 11. Follow-ups outside the code

- Confirm with PGPonyAndroid whether `values-ru` is in scope on their side before §4 schedules anything.
- The LAN phone↔desktop bridge wants its own design doc before 2.1 planning starts.
- The iOS/Android IA question (whether the phones follow the 1.1.0 Message/Files shape) belongs to the phone repos once 1.1.0 has field feedback.
- File the sparse-package `IExplorerCommand` work as a tracked 2.x item so the Windows 11 demotion isn't forgotten.

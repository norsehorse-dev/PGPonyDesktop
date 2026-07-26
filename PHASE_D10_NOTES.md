# PHASE_D10_NOTES.md — the `pgpony` CLI (plan D10)

## D10 (2026-07-25)

### What shipped

- **`Cli`** — the command-line face, dispatched from `Main` for the eight verbs (bare launch
  still opens the GUI; a file argument still opens-and-routes). Shares the SAME keyring +
  config as the app (`Config.dbFile` / `Config.keysDir` / the same `DesktopKeyRepository`), so
  a key made in the GUI is usable from the shell and vice-versa. Not a gpg shim — its own small
  surface.
- **Verbs**:
  - `encrypt -r <key> [-r …] [-u <key>] [-c] [-a] [-o out] [file|-]` — public-key (multi-
    recipient, optional `-u` sign-as) or `-c` symmetric (AES-256/CFB, iterated-salted S2K, no
    AEAD/Argon2 — the gpg-decryptable posture). Streams via `encryptStream`.
  - `decrypt [-o out] [file|-]` — tries every held secret key; reports the signature state to
    stderr (Good / unheld-signer / none).
  - `sign [-u <key>] [-b] [-a] [-o out] [file|-]` — clear-sign by default, `-b` detached; falls
    back to the default signing key when `-u` is omitted.
  - `verify [-s <sigfile>] [file|-]` — clear-signed inline, or detached with `-s`; exit 4 on
    invalid/unknown/unsigned.
  - `import [file|-]`, `export [--secret] [-a] [-o out] <key>`, `list-keys [--secret]`,
    `gen-key --name <n> --email <e> [--algo ed25519] [--expires <days>]`.
- **Options** — a minimal parser: `--long`/`-short` flags + values, `--opt=value` form,
  repeatable `-r`, `--` to end options, `-`/absent = stdin/stdout. `--armor/-a`, `--output/-o`.
- **Key selectors** — a fingerprint (prefix or suffix), long key id, email (exact), or a unique
  name/email substring; ambiguous selectors error with the candidates (exit 2).
- **Passphrases** — never a plain flag (would leak into `ps`/history): `--passphrase-env VAR`,
  `--passphrase-fd N` (`/dev/fd/N`), or an interactive prompt with confirmation for fresh
  secrets (`gen-key`, `-c`). No console + no `--passphrase-*` → a clear usage error.
- **Exit codes** — stable: `0` ok · `1` usage · `2` not-found/ambiguous · `3` failed ·
  `4` unverified.
- **Tests** (`CliTest`) — the option parser (flags/values/repeats/`=`/`--`) and the key resolver
  (email, fingerprint suffix, name substring, no-match) and algorithm aliases. The verbs
  themselves are thin over the already-tested engine + repository.

### Notes / limits

- The CLI opens the same SQLite DB the GUI uses. Read verbs are always safe; a WRITE verb
  (`import`, `gen-key`) run WHILE the GUI is open can briefly hit SQLite's busy lock — rare, and
  a retry succeeds. Typical CLI use is with the app closed.
- `gen-key` needs a real terminal for the passphrase prompt (or `--passphrase-env`). Under
  `./gradlew run` there is no console, so use `--passphrase-env` there; the installed binary
  prompts normally.
- macOS: the app already ships `--add-modules=java.smartcardio` (D7) on every launch, CLI
  included, though the CLI verbs don't touch cards in 1.0.

### Validation

1. `./gradlew test` — incl. `CliTest`.
2. Build a runnable image or use `./gradlew run --args="…"`:
   - `list-keys` → the same keys the GUI shows.
   - `export -a <your-email> -o /tmp/pub.asc` then `import /tmp/pub.asc` on a scratch profile.
   - `echo "hi" | pgpony encrypt -r <you> -a | pgpony decrypt` (installed binary) → round-trips.
   - `pgpony sign -u <you> -a message.txt -o message.asc` then `pgpony verify message.asc`.
   - Cross-tool: `pgpony encrypt -r <you> -a msg.txt -o m.asc`, then `gpg -d m.asc` (if the
     recipient key is also in gpg) — and the reverse, `gpg -e -a -r you msg | pgpony decrypt`.
3. Exit codes: `pgpony verify` a tampered message → `echo $?` is 4; an unknown selector → 2.

### Fix log

- **Fix1 — repeated options were reordered by alias spelling** (`CliTest >
  parsesFlagsValuesRepeatsAndPositional`, 381 tests / 1 failed). `Options` stored values in a
  `Map<String, MutableList<String>>` keyed by the option name as typed, and
  `all(vararg names)` did `names.flatMap { values[it].orEmpty() }` — so the result was grouped by
  the order of the ALIAS NAMES passed in, not the command line. `-r alice@x --recipient bob@y`
  came back as `[bob@y, alice@x]`.

  Not just a test wart: recipient order is what the user sees in the PKESK sequence and in every
  "encrypted to" listing, and `-r`/`--recipient` are freely mixable (and `--recipient=x` is a
  third spelling). Fixed by storing an ordered `List<Pair<String, String>>` of
  (name, value) and filtering in `all()`, which makes command-line order the single source of
  truth; `value()` is now simply `all(*names).firstOrNull()` — the first occurrence among any
  spelling, where before it preferred whichever alias was listed first in the call. Regressions
  added: `repeatedOptionsKeepCommandLineOrderAcrossAliases` (both alias orders + the `=` form)
  and `shortFormValueIsFoundWhenLongFormAbsent`.

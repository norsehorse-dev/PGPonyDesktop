# PHASE_D14_NOTES.md — 2.0.0 foundations: the plural selector, `open --op` (plan 2.0.0 §4, §2a)

## D14 (2026-08-02)

The first code of the 2.0.0 line: the two items the sequencing (§6) puts before everything
else. Both are foundations other pillars sit on — strings under every surface, routing under
the context menus and the clipboard sentinel — and neither touches the frozen 1.1.0 IA.

### 1. `trQuantity` → CLDR plural categories

The two-way `count == 1` branch in `Strings.kt` is gone, replaced by
`I18n.pluralCategory(tag, count)`: a hand-written rule table over the CLDR cardinal data —
integer rules only, since every count the app pluralizes is a whole number of keys, files, or
bytes. The same trade the plan called for: a ~20-line `when` instead of an ICU4J dependency.

Two rows matter beyond Russian-readiness:

- **French and Brazilian Portuguese put 0 with the singular** («0 fichier»). The old branch
  rendered the plural there. This is a deliberate, visible behavior change in two shipped
  locales, and it is CLDR-correct.
- **Russian is in the table now** (`one`/`few`/`many` over the final digit, teens special),
  ahead of `values-ru` existing. The selector is not Russian-specific; Russian was just the
  language that made the old branch untenable. The shipping gate for Russian itself
  (native reviewer, upstream `values-ru`) is unchanged.

The resolution chain in `plural()` is untouched and is what makes the table safe: a category a
translation file doesn't carry degrades sideways to that language's `other` before it degrades
to English — Japanese proved that path in D11, and Russian's `few`/`many` will ride it until
its file lands.

Tests: the plan's matrix counts (1, 2, 3, 5, 11, 21, 101) asserted per locale against values
transcribed from CLDR, plus the edges the matrix can't reach (0 in fr/pt-BR, the Russian
teens and hundreds, negatives, `Long.MIN_VALUE`, a 64-bit count) and a wiring test proving
`trQuantity` actually routes through the selector (French, count 0, renders the `one` item).

### 2. `pgpony open --op` — forced operations

`DesktopFileRouter.classify` stays the default; what's new is the caller's ability to
overrule it. `pgpony open [--op encrypt|decrypt|verify|import|restore] <file>…` — the spelling
the 2a context menus and the sentinel will invoke — forces the ACTION KIND, with file content
only ever choosing between text and file variants of that same action (a small armored message
under a forced decrypt still prefills the text surface). A user who right-clicked "Encrypt" on
a key file means it; rerouting to Import is the bug this exists to prevent.

The op travels the whole existing D9 path, so every entry point behaves identically:

- **`ForcedOp`** (DesktopFileRouter.kt) — the enum, whose `cliName`s are a public contract the
  installers will write into registry verbs / `.desktop` Actions / Quick Actions. Add names,
  never rename. `sign` is deliberately absent: signing stays interactive (the §3c rule).
- **`OpenRequest`** (paths + optional op) replaces bare path lists on the `AppOpen` bus, and
  pending deliveries queue as requests, not pooled paths — two forwarded opens with different
  ops must not merge.
- **The single-instance wire** gains one optional header line, `--op <name>`, before the
  path-per-line body. No collision with paths (forward writes absolute paths, which never
  start with `--`); an unknown op name degrades to classification rather than dropping files.
- **`open` in Main.kt** is not one of PGPONY_VERBS on purpose — it launches or forwards to
  the GUI, so it must not pin English, and it routes through the single-instance guard.
  Grammar errors (unknown op, missing/non-file argument) fail loudly on stderr with
  `ExitCode.USAGE` — a misconfigured menu verb must not open an empty window. The grammar
  reuses the D10 `Options` parser (`--op` added to its valued set; `allPositionals()` new),
  so `--op=verify` and `--` behave like every other verb.

Scoped out, on purpose: a forced op on a MULTI-file open delivers to the Files batch surface
unchanged (the batch surface is the existing bulk-op chooser; pre-selecting its operation is
2a installer-facing UI, not routing). And nothing yet emits `open --op` — the context menus
arrive with the installer work per platform.

Tests: forced-op routing rows in `DesktopFileRouterTest` (forced encrypt beating key
classification is the headline); `OpenRoutingTest` (new) pins the CLI grammar and the wire
format, including the unknown-op degrade. The end-to-end two-process forward stays a manual
matrix row — a unit test binding the real lock file would fight any PGPony the developer has
open.

### Behavior changes to name in 2.0.0 release notes

- French/pt-BR labels for a count of 0 now use the singular form (CLDR-correct).
- New CLI surface: `pgpony open [--op …]`, exit code 1 on grammar errors.

### Verification

Logic of the rule table cross-checked against CLDR expectations in a standalone harness
before the suite; the full Gradle suite is the gate as always. GpgInteropTest and the
card/network suites are untouched by both changes.

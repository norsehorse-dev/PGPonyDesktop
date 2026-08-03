# PHASE_D17_NOTES.md — 2.0.0 files at desktop scale: multi-gigabyte honesty (plan 2.0.0 §3b)

## D17 (2026-08-02)

The engine already streamed; the UI never said so, and a large pass couldn't be stopped. §3b
closes that: per-file byte progress, a cancel that lands promptly, and the never-overwrite rule
extended to never-leave-partials — all done from OUTSIDE the vendored crypto, which we never
edit.

### The audit (§3b's first clause)

`FileCryptoOps` was walked for full-file buffering. The genuine buffering that remains is
inherent, not fixable here: the armored-text decrypt path (`Files.readString`) is
base64-bounded by nature, the card sign/decrypt paths (`Files.readAllBytes`) are a card-protocol
constraint (the APDU pass wants the whole payload), and the 512 B / 16 KB head peeks are exactly
that — heads. The two paths that carry gigabytes — software `encryptStream` and `decryptStream`
— already stream chunk-by-chunk and were left streaming; §3b instruments them rather than
rewriting them.

### Progress + cancel, without touching vendored code: `ProgressStream.kt`

Bytes read = work done, and the engine's read loop is its one regular check-in point, so a
single decorator on the `InputStream` we pass gives both signals:

- **`ProgressInputStream`** counts bytes through `read()`, reports at most once per 1 MiB (a
  final report on `finish()`), and polls a cancel flag on every read — the engine reads in
  8–64 KiB chunks, so a cancel lands within one chunk, not one file. `total` is the source
  size (plaintext length for encrypt; ciphertext length for decrypt, a fine proxy; the walked
  folder size for §3a); `-1` means unknown → the UI shows an indeterminate bar.
- **Cancel** throws `CancelledException`, which propagates out of the engine call. Each file op
  now writes to a temp sibling and `move`s to the unique final name only on success; the inner
  catch deletes the temp on any failure. So a cancel or crash leaves neither a half-written
  `.gpg` nor an overwrite — §3b's third clause. (Decrypt already used temp+move; encrypt and
  folder-encrypt now do too.)

The file ops (`encryptFile`, `decryptFile`, `encryptFolder`) gained optional `onProgress` /
`isCancelled` params with no-op defaults, so the card paths and tests call them unchanged.

### The Files tab

- A snapshot `mutableStateMapOf` keyed by source path holds `(done, total)`; each `FileRow`
  renders a determinate `LinearProgressIndicator` with a human byte line, or an indeterminate
  bar when the size is unknown. A tick from the worker thread moves the bar next frame.
- A **Cancel** button appears while an encrypt/decrypt batch runs (the two streaming ops worth
  interrupting; sign/verify are quick and bounded) and trips an `AtomicBoolean` the ops poll.
  On cancel the banner reads neutral "Cancelled", not a red error.
- **The batch now runs on `Dispatchers.IO`, not the composition dispatcher.** This is the fix
  that makes the whole feature real: a 10 GB pass on the UI thread can neither paint a bar nor
  register a click. Progress ticks are snapshot-state writes (thread-safe); the result
  assignment resumes on the caller's context. This also un-freezes the pre-existing software
  file batch, which had been blocking the UI thread since D3b.

Four new strings (`d_crypto_cancelling`, `d_crypto_progress_bytes`,
`d_crypto_progress_bytes_indeterminate`, `d_file_cancelled`) in all six locales, reusing the
existing `common_button_cancel` / `common_processing` / `d_crypto_cancelled`; strict i18n audit
green at 513/513 per locale.

### Verification

`ProgressStream` compiles standalone against the JDK; `ProgressStreamTest` (4 cases: transparent
byte-count + final report, once-per-tick throttling, prompt cancel mid-stream, unknown-total
passthrough) was compiled and RUN green under JUnit4 in the container. The full main tree
compiled with BC + coroutines and diffed against the D16 baseline — `FileCryptoOps` and
`ProgressStream` are internally clean, the new `withContext(Dispatchers.IO)` resolves, and the
CryptoScreen deltas are the standing Compose/Room-absence cascade with none referencing the new
symbols as real errors. The §3b acceptance bar itself — a 10 GB encrypt on a spinning disk shows
moving progress, cancels cleanly, and leaves no partial output — is a manual matrix row (§8), as
is the responsiveness check; the gradle suite on the Mac is the gate.

### Deferred / next in the pillar

- **§3c watch folders** — encrypt-only rules over `WatchService`, riding these same ops.
- **§3d verify-a-download** — pair + hash + verify, one verdict banner.
- Pillar 2 (context menus, clipboard sentinel) is now mostly installer work atop `open --op`.

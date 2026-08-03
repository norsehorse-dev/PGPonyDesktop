# PHASE_D16_NOTES.md — 2.0.0 files at desktop scale: folder encryption (plan 2.0.0 §3a)

## D16 (2026-08-02)

Encrypting a dropped *folder* used to be an error. Now it's a tarball leg on the existing
streaming encrypt — walk → tar → encrypt, one `<folder>.tar.gpg` out — and on decrypt a
plaintext that turns out to be a tarball extracts to a sibling folder. First step of pillar 3.

### The tar codec: `TarStreamer.kt`

A second, desktop-owned ustar reader/writer — NOT the vendored `UstarArchive` (that one is
byte-in/byte-out, regular-files-only, names ≤100; right for a keyring backup, and vendored, so
never edited here). The folder case needs three things the backup codec doesn't have:
directories, names past 100 bytes, and STREAMING so a multi-gigabyte tree never lands in the
heap (the §3b honesty rule starts here). Same trade the plural table made: a hand-written
~300-line ustar over Commons Compress, with `gpgtar` interop as the acceptance bar.

- **Format:** POSIX ustar (magic `ustar\0`, version `00`), regular files (typeflag `0`) and
  directories (`5`). Names over 100 bytes use the GNU long-name extension — a `././@LongLink`
  `L` entry carrying the full path, then the real header. GNU tar and gpgtar both read it, and
  deep folder paths blow past 100 bytes constantly, so it's the one extension worth carrying.
- **Write** streams file bodies in 64 KiB chunks; paths are relative to the folder's *parent*,
  so the top folder name is the archive's single root (untar reconstructs the folder, not its
  loose contents). mtime is fixed to 0 for deterministic output; the reader ignores it.
- **Extract** streams straight to disk under the target root and is paranoid, because it's a
  parser facing hostile input: every member is rejected if absolute-with-escape, if any
  component is `..`, or if its normalized destination leaves the root (the zip-slip guard); a
  destination that is already a symlink is refused rather than written through; symlink/hardlink
  members and every other exotic typeflag are skipped, never materialized. A member that fails
  a check fails the *whole* extract with a named error — a folder that half-extracts around a
  hostile entry is worse than a refusal the user sees.

### Integration: `FileCryptoOps`

- **`encryptFolder`** pipes `TarStreamer.archive` into `crypto.encryptStream` through a
  `PipedInputStream`/`PipedOutputStream` on a `pgpony-tar-encrypt` daemon thread. Two wins over
  a temp file: bounded memory for any tree size, and the plaintext tar never touches disk (no
  temp to leak or clean up). The producer thread carries any walk/IO failure across the pipe so
  the outcome reflects it. Output is `<folder>.tar.gpg` (or `.tar.asc` when armored).
- **Decrypt** now peeks the plaintext head (`TarStreamer.looksLikeTar`, the magic at offset
  257) on BOTH paths — the armored/byte path and the streaming temp-file path — and, when it's
  a tarball, extracts to a uniquely-named sibling folder (`docs.tar.gpg` → `docs/`) instead of
  dropping a raw `.tar`. This mirrors the existing MIME-bundle precedent and reuses the
  never-overwrite `uniquePath`. The tar check runs *before* the MIME parse: a tar is
  unambiguous by its magic, whereas `MimeParser` would happily mis-read tar bytes. The
  streaming path extracts straight off the temp file, so a huge archive never re-enters the
  heap.

### GUI

`onFilesDropped` (Gui.kt) now admits directories as well as files, and the Files-tab encrypt
loop routes a directory to `encryptFolder`, a file to `encryptFile`. The card-signer batch
handles files only, so a folder always lands on the software path — a folder + card-signer
combo degrades to a per-file error in the results rather than mis-encrypting. Drag-drop is the
folder entry point; the AWT add-files picker stays file-only (cross-platform directory
selection in `FileDialog` is a macOS-specific hack not worth taking here). Two new plural
strings (`d_file_folder_encrypted`, `d_file_folder_extracted`) in all six locales; strict i18n
audit green at 509/509 per locale.

### Verification

`TarStreamer` compiles standalone against the JDK alone. The full main tree compiled with
BC + coroutines and diffed against the D15 baseline — `FileCryptoOps` and `TarStreamer` are
internally clean; the CryptoScreen/Gui errors are the standing Compose/Room-absence cascade,
and none reference the new folder symbols. `TarStreamerTest` (7 cases: round-trip, long name,
nested dirs, top-folder-as-root, and the three hostile archives) was compiled and RUN green
under JUnit4 in the container. Separately, the plan's interop bar was run green in the
container against the real tools: **GNU `tar` extracts our archive** (including the long name)
and **our extract reads GNU `tar`'s output**, both directions. The `gpgtar -d` check on a full
`.tar.gpg` needs the app's BC encrypt pipeline and stays a manual matrix row (§8), alongside
`git commit -S` and `ssh-add -L`; the gradle suite on the Mac is the gate as always.

### Deferred / next in the pillar

- **§3b multi-gigabyte honesty** — per-file byte progress, cancel, and no-partial-output on the
  Files tab. `encryptFolder` already streams without buffering, so the plumbing is ready for a
  progress tap; the UI is the work.
- **§3c watch folders** and **§3d verify-a-download** sit on top of these same ops.

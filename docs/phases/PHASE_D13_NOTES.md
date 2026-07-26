# PHASE_D13_NOTES.md — packaging, signing, release (plan D12)

## D13 (2026-07-26)

Packaging, signing and release, plus the OS-level file-association registration deferred from
D9. Delivered in batches, each green on the Mac before the next started. This record covers
batches 1 through 4 and the site work; the release run itself is appended at the bottom once
`v1.0.0` is tagged.

Two decisions were taken before any code. **arm64-only** for the dmg, reversing an initial
"universal", once the cost was measured rather than assumed (below). And **CI, not local**, for
building — RelayPonyDesktop's `release.yml` is a proven three-runner pipeline and D13 lifts it
rather than re-deriving it.

### The spike, and what it corrected

D13 opened by asking the Compose plugin what it exposes instead of asserting it. Two probe
runs, both read-only Gradle init scripts run from `_to_delete/`, writing their findings to a
file under the mount rather than to a terminal someone has to paste.

The headline correction: **Compose 1.11.1 ships `fileAssociation(mimeType, extension,
description)`** on `JvmApplicationDistributions` and on every platform settings class. The
planning assumption — that the DSL had no such thing and D13 would hand-roll registration
through raw jpackage arguments — was wrong, and building on it would have produced a mechanism
the plugin already contains.

The probes also settled:

- `AbstractJPackageTask` exposes `getFreeArgs(): ListProperty`, a raw jpackage-argument escape
  hatch. That is the lever for anything the DSL does not cover.
- `LinuxPlatformSettings` has **no** dependency field — `debMaintainer` and `debPackageVersion`
  are the whole deb surface — so `Depends: pcscd` has to go through `freeArgs`.
- `FileAssociation` is a data class holding exactly ONE `iconFile`. That settles what the
  set-wide overloads taking two and three `File`s must be — per-OS icons — in an order the API
  does not document. Declared per-platform instead, which is unambiguous.
- `JvmMacOSPlatformSettings` has `entitlementsFile` and `runtimeEntitlementsFile`, answering a
  Batch 2 question before Batch 2 started.

### What shipped

- **File associations for `.pgpony`, `.asc`, `.gpg` and `.pgp`**, declared per-platform. This
  is what finally arms the `java.awt.Desktop.setOpenFileHandler` shipped in D9 batch 1 — until
  the OS knows the app owns the extension, that handler can never fire.
- **`gradle.properties`**, which the project had never had.
- **`LICENSE` and `NOTICE`**, which it had also never had, before the repo went public.
- **Two CI workflows.** `release.yml` ported from RelayPony with a signing job added;
  `build.yml` is new — a push/PR lane running the full suite and the strict i18n audit, which
  RelayPony has no equivalent of, so a broken main there is invisible until release day.
- **The repo itself.** `PGPonyDesktop` was not a git repository at all. Now private on GitHub
  with twenty topics, flipping public at the `v1.0.0` tag — which is what
  `d_settings_about_repo_note` has promised in all six locales since D11.
- **An opt-in update check** (`UpdateCheck.kt`) and its comparator tests.
- **`/desktop` on pgpony.app**, its release manifest, homepage buttons, and desktop click
  tracking through to the daily report.
- **`RELEASING.md`** and staged winget manifests.

### `.sig` is deliberately not registered

Every other extension here is unambiguously OpenPGP. `.sig` is also claimed by plenty of
unrelated signing tools, and taking it system-wide is a product decision rather than a
technical one. `DesktopFileRouter` still routes a `.sig` passed as a CLI argument to Verify, so
nothing regressed; it is one line to add if that changes.

### Things only a built artifact could tell us

Static review found none of these. Each came from reading a real `Info.plist`, a real jlink
image, or a real failure.

- **Passing an icon to `fileAssociation` is a build failure.** Compose copies an association's
  icon into `Contents/Resources/` under the SOURCE file's name, and Resources already holds the
  app icon renamed to `PGPony.icns` — so `packaging/pgpony.icns` collides with it on a
  case-insensitive volume and `createDistributable` dies with `FileAlreadyExistsException`. The
  first diagnosis (four associations racing each other) was plausible and wrong; the real cause
  is case-insensitivity against the app icon. Passing no icon costs nothing: jpackage gives
  every association `CFBundleTypeIconFile = PGPony.icns` on its own.
- **jpackage writes `CFBundleDocumentTypes` itself**, from the `fileAssociation` calls, merging
  `.gpg` and `.pgp` into one dict because they share a mimeType and description. An
  `infoPlist { extraKeysRawXml }` block for document types would have duplicated it.
- **`LSApplicationCategoryType` was the literal string `Unknown`** and `LSMinimumSystemVersion`
  was jpackage's `10.13` default — dishonest for an arm64-only dmg, since no Apple-silicon Mac
  has ever run anything older than macOS 11. Both are DSL properties; both were simply never set.
- **`AppVersion.VERSION` and `packageVersion` had drifted.** The bundle said `1.0.0` while the
  app reported `1.0.0-dev.D1`, and that string is also written into every `.pgpony` backup as
  `appVersion` metadata. Nothing warns you; it is visible only in a built `Info.plist`.
- **`java.smartcardio` really is in the packaged jlink image.** D12 corrected the module name
  from the non-existent `jdk.smartcardio`, noting it would otherwise silently drop card support.
  This is the first time that fix has been verified in an artifact rather than reasoned about.

### `gradle.properties` — absent, and CI would have found it the hard way

`./gradlew clean build` died with `OutOfMemoryError: GC overhead limit exceeded` out of
`:compileKotlin`. The project had no `gradle.properties` at all, which worked only because
day-to-day builds are incremental: `clean` pushes all 165 Kotlin files (121 vendored, 44
desktop) through one non-incremental compile.

Copying PGPonyAndroid's file would NOT have fixed it. That one sets only `org.gradle.jvmargs`,
because on the Android side the Gradle daemon is the hungry process. The process that died here
is the **Kotlin compile daemon**, a separate JVM sized by `kotlin.daemon.jvmargs`.

Values are sized for the smallest machine that must run them — GitHub's macOS arm64 runner is
roughly 7 GB, so `2g` Gradle plus `4g` Kotlin peaks near 6 GB and leaves room for jlink and
jpackage. Every CI run is a clean build, so this would have failed on the first run of both new
workflows.

### Signing and notarization

`notarizeDmg` succeeded with no entitlements file. **The prediction that `javax.smartcardio`
would force one was wrong** — and wrong in an instructive direction. The risk was never a
rejected submission; it was a clean notarization that then cannot load PC/SC libraries at
runtime, because the hardened runtime restricts library loading when the app runs, not when it
is built. No static check catches that. **A YubiKey was tested against the notarized build and
works.** RelayPony has no card stack, so its clean precedent could not have answered this.

**The dmg container is not code-signed at all**, and that is Compose's behaviour, not a defect:
it signs the `.app`, notarizes it, and staples the ticket to the disk image without signing the
wrapper. This is why `spctl -a -t open --context context:primary-signature` **rejects** a good
release with `source=no usable signature` — it asks an unsigned container a signature question.
The app inside is `accepted` / `source=Notarized Developer ID`, both in `build/` and on the
mounted volume, and a **quarantined dmg opens with no dialog**. Recorded here so nobody
re-investigates a non-problem in a year.

### The update check went from automatic to opt-in, and the reason matters

The check was specified automatic and built that way. Writing the `privacy.php` disclosure
surfaced that pgpony.app already publishes two claims an on-by-default check would falsify:
"by default, nothing leaves your device", and that the features which do transmit are "off by
default, only triggered by direct user action".

It is now **opt-in**, so the app matches the promise instead of the promise being amended to
match the app — and `privacy.php` needed no edit at all.

What it does when enabled: a plain GET of `downloads/desktop.json` with no query string, no
custom headers and no identifier of any kind, through `HttpClientFactory` so a configured
Tor/SOCKS proxy carries it, throttled to once a day with the timestamp persisted so relaunching
cannot make a heartbeat. A failed attempt still stamps the clock, so a site that is down is not
retried every launch. It never downloads or installs anything.

The comparator is the part worth testing, and `UpdateCheckTest` pins the cases a plausible
implementation gets wrong: `1.0.9` before `1.0.10` (lexicographically the reverse, which would
tell a user to downgrade), `1.1` equal to `1.1.0`, a pre-release below its own release so
someone on the final `1.1.0` is never offered `1.1.0-rc.1`, the historical `1.0.0-dev.D1` below
`1.0.0`, malformed input from the network reading as zero rather than throwing, and the running
version never offering itself as an update.

`autoEnabled` reads `Preferences` in the object initialiser, wrapped in `runCatching`: that
initialiser fires from a unit test touching only the pure comparator, and a sandboxed runner
with no prefs backing store must not take the object down with it.

### The site

- **`downloads/desktop.json` is separate from `downloads/releases.json`** — not a style
  preference. `releases.json` is owned and rewritten by the APK admin dashboard on every Android
  publish, so a desktop block inside it would be two release cadences fighting over one file.
- **`/desktop` picks its download URLs from the `Host` header**, reusing the exact sniff
  `api/track-click.php` already does: GitHub Releases on clearnet, the local `/downloads` mirror
  on `.onion` and `.i2p`. Sending a Tor visitor to a clearnet host defeats the mirror's purpose.
  It also checks the mirror file exists before linking it.
- **A readiness gate on published SHA-256.** The installers live on a GitHub release that does
  not exist until the tag is pushed, so without it the page would ship three buttons that 404.
  No checksum, no download links — it shows a "publishing in progress" panel instead.
- **The page was rewritten once for house structure.** The first version invented class names
  (`hero`, `lede`, `notice`) that exist nowhere in the stylesheet and had no `.wrap` container,
  so it bled to the viewport edge. Rebuilt on `section` / `wrap` / `section-head` with a
  `// NN_label` eyebrow and page-local `dsk-*` CSS, mirroring how `apk-*` is done in `apk.php`.
  Same lesson as D12 Fix2: static review does not catch layout, on a web page either.

### Desktop click tracking

Five new `download_clicks.platform` values — `desktop`, `desktop_macos`, `desktop_linux`,
`desktop_windows`, `desktop_sig` — with a guarded, re-runnable migration.

**The trap:** a bare `/\.asc$/` in the beacon's delegated listener would file every APK
signature click (`PGPony-4.0.4.apk.asc`) as a desktop signature fetch. The rule matches the full
`(\.dmg|\.deb|\.msi)\.asc$` and `SHA256SUMS(\.asc)?$` instead, which was simulated across eleven
real paths including GitHub release URLs; APK sidecars correctly stay untracked as before.

The daily report gets its matrix, sparkline and record flags for free because all three iterate
`$PLATFORMS`. Hand-written: the subject total, a desktop funnel with the per-OS split, and the
signature-fetch rate — the share of people downloading a PGP app who actually fetch its `.asc`,
which is a number nobody else can publish because nobody else publishes the signature.

Migration ordering matters on deploy: the ENUM must be extended **before** `track-click.php`
ships, or the first desktop click fails its INSERT. The reverse order is harmless.

### Not to be hand-edited: the APK publish path

Noted here because it nearly was. pgpony.app has `/admin/apk.php`, a publish dashboard with a
supply-chain interlock: it verifies the uploaded `.asc` against the site's own published key
(fingerprint `A0CB…DE62`) and **rejects** anything that fails, then computes the SHA-256 itself,
writes the three files at mode 0644 and rotates `releases.json`. Hand-editing `releases.json` or
dropping files into `/downloads` bypasses that check and gets clobbered by the next publish.

### Known and deliberately left alone

- The **winget manifests are unvalidated**. Internally consistent and valid YAML, but no winget
  client has seen them, and `InstallerSha256` and `ProductCode` are placeholders. `ProductCode`
  is NOT the `upgradeUuid` in `build.gradle.kts` — that is the UpgradeCode, a different GUID.
- **`upload-artifact` / `download-artifact` are still at v4** while checkout and setup-java moved
  to v5. They did not run in the build that produced the Node 20 warning, so nothing has
  confirmed a v5 exists; guessing a version that does not resolve fails a release job outright.
- **No `UTExportedTypeDeclarations`** is emitted for the custom `application/x-pgpony-backup`
  type. Extension binding works through `CFBundleTypeExtensions`; a proper exported UTI is a 1.x
  improvement and should not be claimed broken without testing.
- Document icons per file type would need a separately-named icon file per type per OS —
  twelve near-identical binaries for prettier Finder icons. Not a 1.0 requirement.

### Still unproven at the time of writing

Everything below needs the tag, and none of it should be assumed from a green build:

- the `.deb`'s `Depends: pcsc` — injected via `freeArgs`, which degrades to a silent no-op, so
  `dpkg-deb -f` is the only real check
- the `.msi`'s registry associations, and the `.deb`'s `MimeType=`
- the `.asc` files and signed `SHA256SUMS`
- whether the heap numbers hold on a 7 GB macOS runner
- the three installer beacon branches and `desktop_sig`, which have only been simulated
- clean-machine installs on Linux and Windows, which have had no exercise at all
